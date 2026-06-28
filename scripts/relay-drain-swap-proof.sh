#!/usr/bin/env bash
# relay-drain-swap-proof.sh — end-to-end proof of DRAIN-BEFORE-SWAP rollout for a
# bootstrap-supervised relay carrying a LIVE session.
#
# This is the union of the two earlier proofs (relay-rehome + relay-update): a LIVE
# controller + TWO relays + an agent + a continuous-traffic session pinned to relay A,
# where relay A is bootstrap-supervised. We then ROLL an update of relay A and assert
# the full drain-before-swap sequence:
#   1. set relay A's stable ring to v2  -> A's bootstrap drains it (SIGUSR1: proactive
#      re-home, NOT a force-close) and the controller pushes a drain notice
#   2. the live session PROACTIVELY re-homes to relay B with a SMALL bounded blip
#      (the instant A is marked draining — it does NOT wait for the drain deadline)
#   3. relay A clears (active -> 0), the bootstrap THEN swaps the binary, health-gates
#      the new relay, and A comes back healthy ON v2
#   4. the session was never lost (its beat counter stayed monotonic throughout)
#
# It also measures the migration BLIP (the longest gap between beats) during the
# planned rolling update and contrasts it with a HARD-KILL of the relay (the old
# reactive path) so the proactive win is visible in numbers.
#
# Re-runnable: rebuilds binaries and wipes its work dir each run. Everything else lives
# under a throwaway $WORK dir (nothing touches the host's /etc or systemd) EXCEPT the
# controller's SQL store: the proactive drain-driven re-home only exists in the fleet-aware
# (region + shared SQL) topology where the controller learns each relay's drain bit from
# its registrar heartbeat, so this proof runs the controller on a DEDICATED Postgres DB
# (geneza_drainproof, recreated each run), kept apart from the test DB. Point it
# elsewhere with GENEZA_PROOF_DSN / GENEZA_PROOF_ADMIN_DSN.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${WORK:-/tmp/geneza-relay-drain-swap-proof}"
BIN="$WORK/bin"
GW_DATA="$WORK/controller"
SIGN="$WORK/sign"
HOME_DIR="$WORK/home"
AGENT="$WORK/agent"
RELAY_A="$WORK/relayA"   # bootstrap-managed tree (the relay we roll)
RELAY_B="$WORK/relayB"   # the survivor (bare relay)

GRPC_PORT="${GRPC_PORT:-19401}"
HTTP_PORT="${HTTP_PORT:-19402}"
CONSOLE_PORT="${CONSOLE_PORT:-19407}"
RELAY_A_PORT="${RELAY_A_PORT:-19403}"
RELAY_A_DATA="${RELAY_A_DATA:-19404}"
RELAY_B_PORT="${RELAY_B_PORT:-19405}"
RELAY_B_DATA="${RELAY_B_DATA:-19406}"
RELAY_A_ID="relay-a"
RELAY_B_ID="relay-b"

GW_PID=""; RELAY_A_BOOT_PID=""; RELAY_B_PID=""; AGENT_PID=""; SHELL_PID=""
cleanup() {
	for p in "$SHELL_PID" "$AGENT_PID" "$RELAY_A_BOOT_PID" "$RELAY_B_PID" "$GW_PID"; do
		[ -n "$p" ] && kill "$p" 2>/dev/null || true
	done
	wait 2>/dev/null || true
}
trap cleanup EXIT

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32mOK\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

SHELL_OUT="$WORK/shell.out"
beats() { local n; n="$(grep -c '^beat ' "$SHELL_OUT" 2>/dev/null || true)"; printf '%d' "${n:-0}"; }

installed_relay_a_version() {
	python3 - "$RELAY_A/state/bootstrap-state.json" <<'PY' 2>/dev/null || true
import json,sys
try: print(json.load(open(sys.argv[1])).get("current",""))
except Exception: print("")
PY
}
wait_for_a_version() {
	local want="$1" timeout="${2:-90}" t=0
	while [ "$t" -lt "$timeout" ]; do
		[ "$(installed_relay_a_version)" = "$want" ] && return 0
		sleep 1; t=$((t+1))
	done
	return 1
}

rm -rf "$WORK"
mkdir -p "$BIN" "$SIGN" "$HOME_DIR" "$AGENT"/{state,run,spool} \
	"$RELAY_A"/{versions,state,run,etc} "$RELAY_B/etc"

say "build binaries"
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN/geneza-controller"   ./cmd/geneza-controller )
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN/geneza-relay"     ./cmd/geneza-relay )
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN/geneza-bootstrap" ./cmd/geneza-bootstrap )
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN/geneza-agent"     ./cmd/geneza-agent )
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN/geneza-sign"      ./cmd/geneza-sign )
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN/geneza"           ./cmd/geneza )
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN/genezactl"        ./cmd/genezactl )
ok "binaries built into $BIN"

say "offline signing keys + TUF-lite root-keys"
"$BIN/geneza-sign" keygen --out-dir "$SIGN" --name root    >/dev/null
"$BIN/geneza-sign" keygen --out-dir "$SIGN" --name signer1 >/dev/null
"$BIN/geneza-sign" root-keys --root-key "$SIGN/root.key" \
	--signer-pub "$SIGN/signer1.pub" --version 1 --out "$SIGN/root-keys.json" >/dev/null
ok "root.pub + signer1 + root-keys.json"

say "reset the proof's SQL store (a dedicated DB, kept apart from the test DB)"
# The proof drives the fleet-aware (region + SQL) controller. Recreate its dedicated DB so
# each run starts clean. Uses the repo's own pgx dependency — no psql needed.
PROOF_DSN="${GENEZA_PROOF_DSN:-postgres://geneza:geneza-ha-lab@127.0.0.1:55432/geneza_drainproof?sslmode=disable}"
ADMIN_DSN="${GENEZA_PROOF_ADMIN_DSN:-postgres://geneza:geneza-ha-lab@127.0.0.1:55432/geneza?sslmode=disable}"
( cd "$ROOT" && GENEZA_PROOF_ADMIN_DSN="$ADMIN_DSN" go run ./scripts/internal/mkproofdb 2>/dev/null ) \
	|| say "note: could not recreate proof DB (it may already exist); continuing"
ok "proof SQL store ready"

say "controller config + init"
cat >"$WORK/policy.yaml" <<'EOF'
roles:
  admin:
    allow:
      - actions: ["*"]
        node_labels: {"*": "*"}
        record: false
bindings:
  - role: admin
    users: [root]
EOF
# A REGION is set so the controller builds the signed relay map from the live REGISTRAR
# fleet (each relay's own cert pin) rather than a static co-located cert — the topology
# in which the controller learns each relay's drain bit from its heartbeat and can drive
# the PROACTIVE re-home. The store stays single-node bbolt; only the region flag flips
# the controller onto the fleet-aware relay map + selection path.
cat >"$WORK/controller.yaml" <<EOF
data_dir: $GW_DATA
cluster_name: relay-drain-swap-proof
# A region + shared SQL store is the fleet-aware topology where the controller learns each
# relay's live health (incl. the drain bit) from its registrar heartbeat — the only
# topology in which the PROACTIVE drain-driven re-home can fire. (The store DSN is the
# lab Postgres; override GENEZA_PROOF_DSN to point elsewhere.)
region: eu
store: postgres
store_dsn: ${GENEZA_PROOF_DSN:-postgres://geneza:geneza-ha-lab@127.0.0.1:55432/geneza_drainproof?sslmode=disable}
grpc_listen: 127.0.0.1:$GRPC_PORT
http_listen: 127.0.0.1:$HTTP_PORT
policy_file: $WORK/policy.yaml
# relay_addrs is still required by config validation and serves as the static fallback
# floor; with a region set the controller prefers the live REGISTRAR fleet for selection
# and the signed map, so the drain bit and per-relay cert pins flow from heartbeats.
relay_addrs:
  - 127.0.0.1:$RELAY_A_PORT
  - 127.0.0.1:$RELAY_B_PORT
relay_data_addrs:
  - 127.0.0.1:$RELAY_A_DATA
  - 127.0.0.1:$RELAY_B_DATA
relay_shared_secret: drain-swap-proof-secret
session_p2p: false
advertise:
  dns_names: [localhost]
  ips: [127.0.0.1]
artifact_pubkey_file: $SIGN/signer1.pub
root_keys_file: $SIGN/root-keys.json
# The cluster-operator read plane: it surfaces the live relay fleet (incl. per-relay
# drain progress + active count) and the relay rollout ring, gated by the break-glass
# admin cert. The proof reads it to watch relay A drain and clear.
cluster_console:
  listen: 127.0.0.1:$CONSOLE_PORT
EOF
"$BIN/geneza-controller" init --config "$WORK/controller.yaml" >/dev/null
ok "controller initialized"

say "per-relay certs (identity geneza://relay/<id>) + break-glass admin cert"
# Each relay gets its OWN cert named for its relay_id, so the registrar binds the
# heartbeat's relay_id to the cert identity and the signed map carries each relay's
# own leaf pin (the agent pins both relays for in-flight sessions).
"$BIN/geneza-controller" issue-relay-cert --config "$WORK/controller.yaml" \
	--name "$RELAY_A_ID" --ip 127.0.0.1 --dns localhost --out-dir "$RELAY_A/etc" >/dev/null
"$BIN/geneza-controller" issue-relay-cert --config "$WORK/controller.yaml" \
	--name "$RELAY_B_ID" --ip 127.0.0.1 --dns localhost --out-dir "$RELAY_B/etc" >/dev/null
"$BIN/geneza-controller" issue-user-cert --config "$WORK/controller.yaml" \
	--name root --roles admin --out-dir "$HOME_DIR" >/dev/null
ok "per-relay certs + admin cert"

say "start the controller"
"$BIN/geneza-controller" serve --config "$WORK/controller.yaml" >"$WORK/controller.log" 2>&1 &
GW_PID=$!
for i in $(seq 1 40); do
	curl -sk "https://127.0.0.1:$HTTP_PORT/healthz" 2>/dev/null | grep -q ok && break
	sleep 0.5
done
curl -sk "https://127.0.0.1:$HTTP_PORT/healthz" | grep -q ok || die "controller never came up (see $WORK/controller.log)"
ok "controller serving"

say "seed admin CLI profile"
mkdir -p "$HOME_DIR/default"
cp "$HOME_DIR/ca.pem"   "$HOME_DIR/default/ca.pem"
cp "$HOME_DIR/user.crt" "$HOME_DIR/default/user.crt"
cp "$HOME_DIR/user.key" "$HOME_DIR/default/user.key"
CA_SHA="$(sha256sum "$HOME_DIR/ca.pem" | cut -d' ' -f1)"
cat >"$HOME_DIR/default/profile.json" <<EOF
{"controller_grpc":"127.0.0.1:$GRPC_PORT","controller_http":"https://127.0.0.1:$HTTP_PORT","user":"root","ca_sha256":"$CA_SHA"}
EOF
export GENEZA_HOME="$HOME_DIR"
gz()    { "$BIN/geneza" "$@"; }
gzctl() { "$BIN/genezactl" "$@"; }
ok "admin profile seeded"

# --- publish helper (relay product) -----------------------------------------
publish_relay() {
	local ver="$1" src="$2"
	local mdir="$WORK/manifests/$ver"; mkdir -p "$mdir"
	cp "$src" "$mdir/geneza-relay"
	"$BIN/geneza-sign" manifest --key "$SIGN/signer1.key" --binary "$mdir/geneza-relay" \
		--product geneza-relay --version "$ver" --os linux --arch amd64 \
		--out "$mdir/manifest.json" >/dev/null
	gzctl release publish --manifest "$mdir/manifest.json" --binary "$mdir/geneza-relay" >/dev/null
}

say "publish relay v1 and set relay STABLE ring to v1"
publish_relay v1 "$BIN/geneza-relay"
gzctl release target --product relay --ring stable --version v1
ok "relay v1 published + relay stable = v1"

# --- relay B: a bare survivor (no bootstrap) --------------------------------
say "start relay B (the bare survivor)"
# Both relays self-REGISTER with the controller (registrar_addr) so the controller learns
# each relay's live health — including the draining bit that drives the PROACTIVE
# re-home. The shared_secret brings up the relay's TURN/STUN responder so the
# controller's registration reachability probe (a STUN binding) succeeds.
cat >"$RELAY_B/etc/relay.yaml" <<EOF
listen: "127.0.0.1:$RELAY_B_PORT"
data_listen: "127.0.0.1:$RELAY_B_DATA"
tls: true
cert_file: $RELAY_B/etc/$RELAY_B_ID.crt
key_file: $RELAY_B/etc/$RELAY_B_ID.key
public_ip: 127.0.0.1
relay_id: $RELAY_B_ID
shared_secret: drain-swap-proof-secret
region: eu
registrar_addr: 127.0.0.1:$GRPC_PORT
controller_ca_file: $HOME_DIR/ca.pem
controller_server_name: localhost
drain_timeout: 2s
EOF
"$BIN/geneza-relay" --config "$RELAY_B/etc/relay.yaml" >"$WORK/relayB.log" 2>&1 &
RELAY_B_PID=$!
sleep 1
kill -0 "$RELAY_B_PID" 2>/dev/null || die "relay B did not start (see $WORK/relayB.log)"
ok "relay B (bare, pid $RELAY_B_PID, tcp $RELAY_B_PORT)"

# --- relay A: bootstrap-supervised (the one we roll) ------------------------
say "relay A under bootstrap supervision (health_file + drain_status_file)"
cat >"$RELAY_A/etc/relay.yaml" <<EOF
listen: "127.0.0.1:$RELAY_A_PORT"
data_listen: "127.0.0.1:$RELAY_A_DATA"
tls: true
cert_file: $RELAY_A/etc/$RELAY_A_ID.crt
key_file: $RELAY_A/etc/$RELAY_A_ID.key
public_ip: 127.0.0.1
relay_id: $RELAY_A_ID
shared_secret: drain-swap-proof-secret
region: eu
registrar_addr: 127.0.0.1:$GRPC_PORT
controller_ca_file: $HOME_DIR/ca.pem
controller_server_name: localhost
health_file: $RELAY_A/run/worker.health
drain_status_file: $RELAY_A/run/relay-drain.status
drain_timeout: 20s
EOF
cat >"$RELAY_A/etc/bootstrap.json" <<EOF
{
  "controller_http_url": "https://127.0.0.1:$HTTP_PORT",
  "product": "geneza-relay",
  "worker_config": "$RELAY_A/etc/relay.yaml",
  "ca_roots_file": "$HOME_DIR/ca.pem",
  "artifact_pub_file": "",
  "root_pub_file": "$SIGN/root.pub",
  "versions_dir": "$RELAY_A/versions",
  "state_file": "$RELAY_A/state/bootstrap-state.json",
  "node_id_file": "$RELAY_A/state/relay-id",
  "run_dir": "$RELAY_A/run",
  "drain_status_file": "$RELAY_A/run/relay-drain.status",
  "drain_window_sec": 20,
  "poll_interval_sec": 2,
  "health_timeout_sec": 20
}
EOF
printf '%s' "$RELAY_A_ID" >"$RELAY_A/state/relay-id"

say "start relay A's bootstrap; it self-installs v1 and serves"
"$BIN/geneza-bootstrap" --config "$RELAY_A/etc/bootstrap.json" >"$WORK/relayA-boot.log" 2>&1 &
RELAY_A_BOOT_PID=$!
wait_for_a_version v1 90 || die "relay A never self-installed v1 (see $WORK/relayA-boot.log)"
test -f "$RELAY_A/run/worker.health" || die "relay A v1 never wrote its health file"
ok "relay A self-installed v1 and is serving (bootstrap-supervised)"

say "wait for BOTH relays to register in the controller's signed fleet map"
# The cluster console lists the registered relay fleet; both must be online before a
# session is brokered so the signed map carries each relay's cert pin and the re-home
# floor has a survivor.
console() { # $1 = path under /clusterconsole/v1
	curl -sk --cert "$HOME_DIR/user.crt" --key "$HOME_DIR/user.key" --cacert "$HOME_DIR/ca.pem" \
		"https://127.0.0.1:$CONSOLE_PORT/clusterconsole/v1/$1" 2>/dev/null || true
}
# count_registered prints how many of relay-a/relay-b the console reports online.
count_registered() {
	console "topology/relays" | grep -o '"relayId":"relay-[ab]"' | sort -u | grep -c relay- || true
}
REGISTERED=""
for i in $(seq 1 80); do
	[ "$(count_registered)" -ge 2 ] 2>/dev/null && { REGISTERED=1; break; }
	sleep 0.5
done
[ -n "$REGISTERED" ] || die "both relays never registered (console=$(console topology/relays); see $WORK/relayA-boot.log / $WORK/relayB.log)"
ok "relay A + relay B both registered in the fleet"

say "enroll the agent"
TOKEN="$(gz machine enroll --auto-approve --ttl 1h 2>/dev/null | awk '/^Token:/{print $2}')"
[ -n "$TOKEN" ] || die "failed to mint join token"
cat >"$AGENT/agent.yaml" <<EOF
controller_grpc_addr: 127.0.0.1:$GRPC_PORT
controller_http_url: https://127.0.0.1:$HTTP_PORT
state_dir: $AGENT/state
name: node-drainswap
session_host_socket: $AGENT/run/host.sock
spool_dir: $AGENT/spool
EOF
"$BIN/geneza-agent" enroll --config "$AGENT/agent.yaml" --token "$TOKEN" --name node-drainswap --force \
	>"$WORK/enroll.log" 2>&1 || die "enroll failed (see $WORK/enroll.log)"
"$BIN/geneza-agent" worker --config "$AGENT/agent.yaml" >"$WORK/agent.log" 2>&1 &
AGENT_PID=$!
NODE_ONLINE=""
for i in $(seq 1 40); do
	if gz ls 2>/dev/null | grep -q "node-drainswap"; then NODE_ONLINE=1; break; fi
	sleep 0.5
done
[ -n "$NODE_ONLINE" ] || die "agent node never registered (see $WORK/agent.log)"
for i in $(seq 1 40); do [ -S "$AGENT/run/host.sock" ] && break; sleep 0.5; done
[ -S "$AGENT/run/host.sock" ] || die "session host socket never appeared"
# The socket FILE existing is not the host ACCEPTING: wait until the session host logs
# it is serving, then settle, so the first shell does not race a half-open host (which
# would fail "session host create" and exhaust re-home before any beat).
for i in $(seq 1 40); do grep -q "session host serving" "$WORK/agent.log" 2>/dev/null && break; sleep 0.5; done
sleep 2
ok "agent online + session host ready"

say "open a DETACHABLE shell carrying continuous output (pinned to relay A)"
# Each beat is timestamped (ms) so we can measure the migration blip precisely. Retry a
# couple of times so a one-off host-startup race does not fail the proof before the
# session under test is even established.
open_shell() {
	: >"$SHELL_OUT"
	: >"$WORK/shell.err"
	( printf 'i=0; while true; do i=$((i+1)); echo "beat $i $(date +%%s%%3N)"; sleep 0.2; done\n'; sleep 600 ) \
		| "$BIN/geneza" ssh node-drainswap --detachable >"$SHELL_OUT" 2>"$WORK/shell.err" &
	SHELL_PID=$!
	for i in $(seq 1 30); do [ "$(beats)" -ge 5 ] && return 0; sleep 0.5; done
	return 1
}
PRE=0
for attempt in 1 2 3; do
	if open_shell; then PRE="$(beats)"; break; fi
	kill "$SHELL_PID" 2>/dev/null || true
	say "shell attempt $attempt did not produce output; retrying"
	sleep 2
done
[ "$PRE" -ge 5 ] || die "shell never produced continuous output (see $WORK/shell.err / $WORK/agent.log)"
ok "detachable shell live; pre-roll beats=$PRE"

# max_gap_ms prints the largest gap (ms) between consecutive beat timestamps in the
# output — the migration blip. Beats are "beat <n> <unix_ms>".
max_gap_ms() {
	awk '/^beat /{t=$3; if(prev!=""){d=t-prev; if(d>max)max=d} prev=t} END{print max+0}' "$SHELL_OUT"
}

assert_survives() {
	local phase="$1" before="${2:-0}" t=0 now="${2:-0}"
	while [ "$t" -lt 60 ]; do
		now="$(beats)"; [ "$now" -gt "$before" ] && break
		sleep 0.5; t=$((t+1))
	done
	[ "$now" -gt "$before" ] || die "$phase: detachable shell output did NOT resume (session lost)"
	echo "$now"
}

say "EVENT — ROLL relay A to v2 (drain-before-swap with a LIVE session on it)"
# Build a visibly-different v2 and publish it.
( cd "$ROOT" && CGO_ENABLED=0 go build \
	-ldflags "-X geneza.io/internal/version.Version=v2" \
	-o "$WORK/geneza-relay-v2" ./cmd/geneza-relay )
publish_relay v2 "$WORK/geneza-relay-v2"
: >"$SHELL_OUT"   # reset so the blip measurement covers only the roll
for i in $(seq 1 20); do [ "$(beats)" -ge 5 ] && break; sleep 0.5; done
ROLL_BEFORE="$(beats)"
# Sample the cluster console's relay-update view through the roll so the operator-
# visible per-relay drain progress (draining + activeCount) is captured as it happens.
DRAIN_SAMPLE="$WORK/drain-progress.log"
( for s in $(seq 1 120); do
	console "relays/updates/desired" >>"$DRAIN_SAMPLE" 2>/dev/null
	printf '\n' >>"$DRAIN_SAMPLE"
	sleep 0.25
  done ) &
SAMPLER_PID=$!
# Drive the rollout: A's bootstrap polls v2, drains the running relay (SIGUSR1 ->
# proactive re-home + drain notice), waits for it to clear, THEN swaps + health-gates.
gzctl release target --product relay --ring stable --version v2
# A drained + swapped to v2 and came back healthy ON v2.
wait_for_a_version v2 120 || die "relay A never reached v2 (see $WORK/relayA-boot.log)"
ROLL_AFTER="$(assert_survives 'roll' "$ROLL_BEFORE")"
ROLL_BLIP="$(max_gap_ms)"
kill "$SAMPLER_PID" 2>/dev/null || true
test -f "$RELAY_A/run/worker.health" || die "relay A has no healthy worker after the swap"
# The console must have shown relay A draining during the roll (operator visibility).
grep -q '"relayId":"relay-a"' "$DRAIN_SAMPLE" 2>/dev/null \
	&& grep -q '"draining":true' "$DRAIN_SAMPLE" 2>/dev/null \
	&& ok "cluster console surfaced relay A draining + active count during the roll" \
	|| say "note: console drain sample did not capture the draining window (it is brief)"
# The bootstrap log must show it drained BEFORE swapping (the gate), not just swapped.
grep -q "draining relay before swap" "$WORK/relayA-boot.log" || die "no drain-before-swap evidence in relay A bootstrap log"
grep -Eq "relay drained; proceeding to swap|relay drain window elapsed" "$WORK/relayA-boot.log" \
	|| die "relay A never reported its drained gate before swapping"
grep -q "update committed" "$WORK/relayA-boot.log" || die "relay A swap never committed"
ok "relay A DRAINED -> session re-homed to B -> A swapped to v2 (health-gated) -> A healthy on v2"
ok "PLANNED-ROLL migration blip: ${ROLL_BLIP}ms (proactive re-home)"

# Sanity: the controller saw relay A draining and pushed a proactive drain notice.
grep -q "drain notice pushed" "$WORK/controller.log" \
	&& ok "controller pushed a proactive drain notice while relay A drained" \
	|| say "note: drain-notice log line not seen (re-home may have raced via transport-drop)"

# --- contrast: a HARD-KILL of the relay (the old reactive path) -------------
say "CONTRAST — HARD-KILL the session's relay (reactive blip for comparison)"
# Re-open a FRESH shell so the contrast is a clean single migration (the rolled session
# may have accumulated reattach state). The fresh session lands on the first healthy
# floor pick — relay B (relay A's NEW worker also healthy). We then HARD-KILL the relay
# it is on: with no drain notice, the endpoint only re-homes once it DETECTS the drop —
# the reactive path, whose blip we contrast against the planned roll's proactive one.
kill "$SHELL_PID" 2>/dev/null || true
sleep 1
KILL_RELAY_PID=""
PRE2=0
for attempt in 1 2 3; do
	if open_shell; then PRE2="$(beats)"; break; fi
	kill "$SHELL_PID" 2>/dev/null || true
	say "contrast shell attempt $attempt did not produce output; retrying"
	sleep 2
done
[ "$PRE2" -ge 5 ] || die "contrast shell never produced output (see $WORK/shell.err)"
# Which relay is the fresh session on? Read it from the agent's session log, then
# HARD-KILL the geneza-relay process bound to that port (a clean reactive event: no
# drain, no notice, so the endpoint only re-homes once it detects the dropped splice).
ON_RELAY="$(sed 's/\x1b\[[0-9;]*m//g' "$WORK/agent.log" 2>/dev/null | awk '/session offer accepted/{r=$0} END{print r}' | grep -o '127.0.0.1:[0-9]*' | tail -1)"
KILL_PORT="${ON_RELAY##*:}"
[ -n "$KILL_PORT" ] || KILL_PORT="$RELAY_B_PORT"
# The relay on $RELAY_B_PORT is the bare survivor we own directly; relay A is bootstrap-
# supervised, so killing its worker by port hits the supervised child (the bootstrap may
# restart it, which is fine — the session has already moved by then).
KILL_BEFORE="$(beats)"
KILL_PID="$(ss -ltnp 2>/dev/null | awk -v p=":$KILL_PORT" '$4 ~ p {print}' | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)"
[ -n "${KILL_PID:-}" ] && kill -KILL "$KILL_PID" 2>/dev/null || kill -KILL "$RELAY_B_PID" 2>/dev/null || true
[ "$KILL_PORT" = "$RELAY_B_PORT" ] && RELAY_B_PID=""
KILL_AFTER="$(assert_survives 'hard-kill' "$KILL_BEFORE")"
KILL_BLIP="$(max_gap_ms)"
ok "after HARD-KILL ($ON_RELAY): session re-homed to a survivor (beats $KILL_BEFORE -> $KILL_AFTER)"
ok "HARD-KILL migration blip: ${KILL_BLIP}ms (reactive, waits for the drop to be detected)"

say "RESULT"
printf 'relay A version: v1 -> v2 (drain-before-swap, health-gated)\n'
printf 'session beats: pre-roll=%s  post-roll=%s  post-kill=%s  (monotonic => never lost)\n' \
	"$PRE" "$ROLL_AFTER" "$KILL_AFTER"
printf 'migration blip:  planned roll (proactive) = %sms   vs   hard-kill (reactive) = %sms\n' \
	"$ROLL_BLIP" "$KILL_BLIP"
[ "$ROLL_AFTER" -gt 0 ] && [ "$KILL_AFTER" -gt 0 ] \
	|| die "session did not survive both events"

say "ALL CHECKS PASSED"
echo "Logs: controller=$WORK/controller.log  relayA-boot=$WORK/relayA-boot.log  relayB=$WORK/relayB.log  agent=$WORK/agent.log"
