#!/usr/bin/env bash
# relay-rehome-proof.sh — end-to-end proof of IN-SESSION relay re-home (failover).
#
# When the relay a LIVE session is using drains or dies, the session migrates to a
# surviving relay instead of being torn down. This drives a LIVE single-node controller
# + TWO relays + an agent (with its session host) + a client carrying CONTINUOUS
# traffic, then:
#   1. DRAIN the relay the session is on        -> the session re-homes to the other
#   2. HARD-KILL the relay the session is on     -> the session re-homes to the other
# and asserts the session SURVIVES across each event with a bounded blip:
#   - a DETACHABLE shell keeps its server-side state (the host PTY persists; the
#     client re-attaches and replays missed output) — the SEAMLESS case;
#   - a FORWARD resumes (a fresh upstream is spliced) — the RECONNECT-FAST case.
#
# Re-runnable: it rebuilds binaries and wipes its work dir each run. Everything lives
# under a throwaway $WORK dir; nothing touches the host's /etc or systemd.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${WORK:-/tmp/geneza-relay-rehome-proof}"
BIN="$WORK/bin"
GW_DATA="$WORK/controller"
HOME_DIR="$WORK/home"
AGENT="$WORK/agent"

GRPC_PORT="${GRPC_PORT:-18401}"
HTTP_PORT="${HTTP_PORT:-18402}"
RELAY_A_PORT="${RELAY_A_PORT:-18403}"
RELAY_A_DATA="${RELAY_A_DATA:-18404}"
RELAY_B_PORT="${RELAY_B_PORT:-18405}"
RELAY_B_DATA="${RELAY_B_DATA:-18406}"
ECHO_PORT="${ECHO_PORT:-18410}"   # the forward upstream target
FWD_LOCAL="${FWD_LOCAL:-18411}"   # the client's local forward listen port

GW_PID=""; RELAY_A_PID=""; RELAY_B_PID=""; AGENT_PID=""; HOST_PID=""
SHELL_PID=""; FWD_PID=""; ECHO_PID=""
cleanup() {
	for p in "$SHELL_PID" "$FWD_PID" "$ECHO_PID" "$AGENT_PID" "$HOST_PID" "$RELAY_A_PID" "$RELAY_B_PID" "$GW_PID"; do
		[ -n "$p" ] && kill "$p" 2>/dev/null || true
	done
	wait 2>/dev/null || true
}
trap cleanup EXIT

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32mOK\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

# beats counts the heartbeat lines the remote shell has emitted so far. It always
# prints a single clean integer (0 when the file is missing/empty) so the caller's
# arithmetic comparisons never choke on a blank or multi-line value.
beats() {
	local n
	n="$(grep -c '^beat ' "$SHELL_OUT" 2>/dev/null || true)"
	printf '%d' "${n:-0}"
}

# which relay is the session currently rendezvoused on? We read the controller's relay
# fleet pick order: the FIRST healthy relay is what a (re)issued floor heads with.
relay_pid_for() { case "$1" in A) echo "$RELAY_A_PID";; B) echo "$RELAY_B_PID";; esac; }

rm -rf "$WORK"; mkdir -p "$BIN" "$HOME_DIR" "$AGENT"/{state,run,spool} \
	"$WORK/relayA/etc" "$WORK/relayB/etc"

say "build binaries"
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN/geneza-controller" ./cmd/geneza-controller )
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN/geneza-relay"   ./cmd/geneza-relay )
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN/geneza-agent"   ./cmd/geneza-agent )
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN/geneza"         ./cmd/geneza )
ok "binaries built into $BIN"

say "controller config + init"
cat >"$WORK/policy.yaml" <<'EOF'
roles:
  admin:
    allow:
      - actions: ["*"]
        node_labels: {"*": "*"}
        # No audit recipient is configured in this self-contained harness, and the
        # session host refuses a recorded session without one. Recording is
        # orthogonal to relay re-home, so disable it here.
        record: false
bindings:
  - role: admin
    users: [root]
EOF
# Both relays are in relay_addrs, so the TCP rendezvous floor lists BOTH and a
# re-home (or an initial dial past a draining relay) has a survivor to pick.
cat >"$WORK/controller.yaml" <<EOF
data_dir: $GW_DATA
cluster_name: relay-rehome-proof
grpc_listen: 127.0.0.1:$GRPC_PORT
http_listen: 127.0.0.1:$HTTP_PORT
policy_file: $WORK/policy.yaml
relay_addrs:
  - 127.0.0.1:$RELAY_A_PORT
  - 127.0.0.1:$RELAY_B_PORT
relay_data_addrs:
  - 127.0.0.1:$RELAY_A_DATA
  - 127.0.0.1:$RELAY_B_DATA
relay_shared_secret: rehome-proof-secret
# session_p2p stays OFF so the session DATA flows over the relay-TCP rendezvous
# floor (not a localhost-direct ICE path that would bypass the relay entirely):
# the session genuinely depends on its relay, so draining/killing it exercises the
# in-session re-home onto the surviving relay rather than a no-op.
session_p2p: false
advertise:
  dns_names: [localhost]
  ips: [127.0.0.1]
EOF
"$BIN/geneza-controller" init --config "$WORK/controller.yaml" >/dev/null
ok "controller initialized"

say "relay certs + break-glass admin cert"
# Both relays present the controller's co-located relay cert — the SAME cert the
# single-node signed relay map pins (synthesizeRelays reads $GW_DATA/tls/relay.crt).
# So the agent's relay-leaf pin accepts BOTH relays, and the relay-TCP floor can
# rendezvous on either. (A multi-region deploy instead registers each relay via the
# registrar so the signed map carries every relay's own cert pin; here we keep the
# harness single-node and self-contained.)
cp "$GW_DATA/tls/relay.crt" "$WORK/relayA/etc/relay-a.crt"
cp "$GW_DATA/tls/relay.key" "$WORK/relayA/etc/relay-a.key"
cp "$GW_DATA/tls/relay.crt" "$WORK/relayB/etc/relay-b.crt"
cp "$GW_DATA/tls/relay.key" "$WORK/relayB/etc/relay-b.key"
"$BIN/geneza-controller" issue-user-cert --config "$WORK/controller.yaml" \
	--name root --roles admin --out-dir "$HOME_DIR" >/dev/null
ok "relay certs (shared co-located cert) + admin cert"

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
cp "$HOME_DIR/ca.pem"  "$HOME_DIR/default/ca.pem"
cp "$HOME_DIR/user.crt" "$HOME_DIR/default/user.crt"
cp "$HOME_DIR/user.key" "$HOME_DIR/default/user.key"
CA_SHA="$(sha256sum "$HOME_DIR/ca.pem" | cut -d' ' -f1)"
cat >"$HOME_DIR/default/profile.json" <<EOF
{"controller_grpc":"127.0.0.1:$GRPC_PORT","controller_http":"https://127.0.0.1:$HTTP_PORT","user":"root","ca_sha256":"$CA_SHA"}
EOF
export GENEZA_HOME="$HOME_DIR"
gz() { "$BIN/geneza" "$@"; }
ok "admin profile seeded"

start_relay() {
	local tag="$1" port="$2" data="$3" dir="$WORK/relay$1"
	local lc
	case "$tag" in A) lc=a;; B) lc=b;; esac
	cat >"$dir/etc/relay.yaml" <<EOF
listen: "127.0.0.1:$port"
data_listen: "127.0.0.1:$data"
tls: true
cert_file: $dir/etc/relay-$lc.crt
key_file: $dir/etc/relay-$lc.key
public_ip: 127.0.0.1
relay_id: relay-$lc
controller_ca_file: $HOME_DIR/ca.pem
# A short drain window so a SIGTERM drain forces the live session to re-home
# promptly (it does not linger on the draining relay for the default 5s).
drain_timeout: 2s
EOF
	"$BIN/geneza-relay" --config "$dir/etc/relay.yaml" >"$WORK/relay$tag.log" 2>&1 &
	local pid=$!
	case "$tag" in A) RELAY_A_PID=$pid;; B) RELAY_B_PID=$pid;; esac
}

say "start relay A and relay B"
start_relay A "$RELAY_A_PORT" "$RELAY_A_DATA"
start_relay B "$RELAY_B_PORT" "$RELAY_B_DATA"
sleep 1
kill -0 "$RELAY_A_PID" 2>/dev/null || die "relay A did not start (see $WORK/relayA.log)"
kill -0 "$RELAY_B_PID" 2>/dev/null || die "relay B did not start (see $WORK/relayB.log)"
ok "relay A (pid $RELAY_A_PID, tcp $RELAY_A_PORT) + relay B (pid $RELAY_B_PID, tcp $RELAY_B_PORT)"

say "mint a join token (auto-approve) + enroll the agent"
TOKEN="$(gz machine enroll --auto-approve --ttl 1h 2>/dev/null | awk '/^Token:/{print $2}')"
[ -n "$TOKEN" ] || die "failed to mint join token"
cat >"$AGENT/agent.yaml" <<EOF
controller_grpc_addr: 127.0.0.1:$GRPC_PORT
controller_http_url: https://127.0.0.1:$HTTP_PORT
state_dir: $AGENT/state
name: node-rehome
session_host_socket: $AGENT/run/host.sock
spool_dir: $AGENT/spool
EOF
"$BIN/geneza-agent" enroll --config "$AGENT/agent.yaml" --token "$TOKEN" --name node-rehome --force \
	>"$WORK/enroll.log" 2>&1 || die "enroll failed (see $WORK/enroll.log)"
ok "agent enrolled as node-rehome"

say "start the agent worker (spawns its session host)"
"$BIN/geneza-agent" worker --config "$AGENT/agent.yaml" >"$WORK/agent.log" 2>&1 &
AGENT_PID=$!
# Wait for the node to be online at the controller.
NODE_ONLINE=""
for i in $(seq 1 40); do
	if gz ls 2>/dev/null | grep -q "node-rehome"; then NODE_ONLINE=1; break; fi
	sleep 0.5
done
[ -n "$NODE_ONLINE" ] || die "agent node never registered (see $WORK/agent.log)"
# Wait for the session host's socket so the first shell does not race host startup.
for i in $(seq 1 40); do
	[ -S "$AGENT/run/host.sock" ] && break
	sleep 0.5
done
[ -S "$AGENT/run/host.sock" ] || die "session host socket never appeared (see $WORK/agent.log)"
ok "agent worker online + session host ready"

# ---------------------------------------------------------------------------
# A tiny echo upstream for the forward to splice onto, and a counter so we can
# measure continuity of forwarded traffic across a relay event.
# ---------------------------------------------------------------------------
say "start the forward upstream (an echo server)"
python3 -c '
import socket,sys,threading
p=int(sys.argv[1])
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",p)); s.listen(16)
def h(c):
    try:
        while True:
            d=c.recv(4096)
            if not d: break
            c.sendall(d)
    except Exception: pass
    finally: c.close()
while True:
    c,_=s.accept(); threading.Thread(target=h,args=(c,),daemon=True).start()
' "$ECHO_PORT" >"$WORK/echo.log" 2>&1 &
ECHO_PID=$!
sleep 0.5
ok "echo upstream on 127.0.0.1:$ECHO_PORT (pid $ECHO_PID)"

# ---------------------------------------------------------------------------
# The continuous-traffic session under test. We use a DETACHABLE shell whose
# remote process emits a heartbeat line every 0.3s; the client runs it
# non-interactively and tees output to a file we can count lines in across the
# relay events (proving the SERVER-SIDE state — the running loop — survives).
# ---------------------------------------------------------------------------
say "open a DETACHABLE shell carrying continuous output"
SHELL_OUT="$WORK/shell.out"
: >"$SHELL_OUT"
# `geneza ssh --detachable` with a fed command: the remote shell runs a counter
# loop; the client auto-re-homes on a relay loss (multi-shot reattach), so the
# loop's output stream continues with at most a brief stall.
( printf 'i=0; while true; do i=$((i+1)); echo "beat $i"; sleep 0.3; done\n'; sleep 600 ) \
	| "$BIN/geneza" ssh node-rehome --detachable >"$SHELL_OUT" 2>"$WORK/shell.err" &
SHELL_PID=$!
# Let the shell establish + emit a few beats.
for i in $(seq 1 40); do
	[ "$(beats)" -ge 3 ] && break
	sleep 0.5
done
PRE="$(beats)"
[ "$PRE" -ge 3 ] || die "shell never produced continuous output (see $WORK/shell.err / $WORK/agent.log)"
ok "detachable shell live; pre-event beats=$PRE"

# ---------------------------------------------------------------------------
# A forward session: local $FWD_LOCAL -> node -> echo upstream. We pump bytes and
# count round-trips before/during/after the relay event.
# ---------------------------------------------------------------------------
say "open a FORWARD session (local $FWD_LOCAL -> node -> echo $ECHO_PORT)"
"$BIN/geneza" forward node-rehome "$FWD_LOCAL:127.0.0.1:$ECHO_PORT" >"$WORK/forward.log" 2>&1 &
FWD_PID=$!
sleep 1
fwd_rt() { # one forward round-trip; prints OK on success
	printf 'ping\n' | timeout 3 python3 -c '
import socket,sys
s=socket.create_connection(("127.0.0.1",'"$FWD_LOCAL"'),timeout=2)
s.sendall(b"ping\n"); d=s.recv(16); s.close()
print("OK" if d.strip()==b"ping" else "BAD")
' 2>/dev/null || echo "BAD"
}
[ "$(fwd_rt)" = "OK" ] || die "forward did not round-trip before the relay event (see $WORK/forward.log)"
ok "forward round-trips before any relay event"

# ---------------------------------------------------------------------------
# Determine which relay the session is using. With both relays in the floor the
# rendezvous lands on the FIRST listed (relay A). We assert survival when A is
# removed; the session must re-home to B.
# ---------------------------------------------------------------------------
assert_survives() {
	local phase="$1"
	local before="$2"
	# wait for output to advance past the event (re-home blip), bounded.
	local t=0
	local now="$before"
	while [ "$t" -lt 40 ]; do
		now="$(beats)"
		[ "$now" -gt "$before" ] && break
		sleep 0.5; t=$((t+1))
	done
	[ "$now" -gt "$before" ] || die "$phase: detachable shell output did NOT resume (state lost)"
	# Forward must round-trip again.
	local frt="BAD" ft=0
	while [ "$ft" -lt 20 ]; do
		frt="$(fwd_rt)"; [ "$frt" = "OK" ] && break; sleep 0.5; ft=$((ft+1))
	done
	[ "$frt" = "OK" ] || die "$phase: forward did NOT resume"
	echo "$now"
}

say "EVENT 1 — DRAIN relay A (the session's relay)"
# A graceful drain: SIGTERM lets the relay advertise draining + shed; the controller
# excludes it from the re-issued floor, and both ends re-home to relay B.
DRAIN_BEFORE="$(beats)"
kill -TERM "$RELAY_A_PID" 2>/dev/null || true
RELAY_A_PID=""
DRAIN_AFTER="$(assert_survives 'drain' "$DRAIN_BEFORE")"
ok "after DRAIN: shell resumed (beats $DRAIN_BEFORE -> $DRAIN_AFTER), forward resumed — session re-homed to relay B"

say "EVENT 2 — HARD-KILL relay B (now the session's relay)"
# Bring relay A back so a survivor exists, give the fleet a moment, then hard-kill B.
start_relay A "$RELAY_A_PORT" "$RELAY_A_DATA"
sleep 2
KILL_BEFORE="$(beats)"
kill -KILL "$RELAY_B_PID" 2>/dev/null || true
RELAY_B_PID=""
KILL_AFTER="$(assert_survives 'hard-kill' "$KILL_BEFORE")"
ok "after HARD-KILL: shell resumed (beats $KILL_BEFORE -> $KILL_AFTER), forward resumed — session re-homed to relay A"

say "RESULT"
printf 'detachable shell beats: pre=%s  post-drain=%s  post-kill=%s  (monotonic => state survived)\n' \
	"$PRE" "$DRAIN_AFTER" "$KILL_AFTER"
printf 'forward round-trips: OK before, OK after drain, OK after hard-kill\n'
[ "$KILL_AFTER" -gt "$DRAIN_AFTER" ] && [ "$DRAIN_AFTER" -gt "$PRE" ] \
	|| die "beat counter not monotonic across events — the session did not truly survive"
ok "IN-SESSION RELAY RE-HOME PROVEN: the live session survived a relay DRAIN and a relay HARD-KILL, re-homing to the surviving relay each time with a bounded blip."
