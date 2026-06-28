#!/usr/bin/env bash
# relay-update-proof.sh — end-to-end proof of controller-managed signed updates for
# RELAYS: the same signed / health-gated / rollback machinery the agent uses,
# driven for a bootstrap-supervised relay.
#
# It drives a LIVE single-node controller + a bootstrap-supervised relay through:
#   1. publish relay v1, set relay stable v1  -> the relay self-installs v1
#   2. publish relay v2, set relay stable v2  -> the relay self-updates to v2
#   3. publish a DELIBERATELY BROKEN relay v3 -> the bootstrap health-gates it
#      and ROLLS BACK to v2 (no live-relay outage)
#
# Re-runnable: it rebuilds binaries and wipes its work dir each run. Everything
# lives under a throwaway $WORK dir; nothing touches the host's /etc or systemd.
#
# This script also documents the EXACT deploy shape a real relay now needs under
# bootstrap supervision (see the comments around each step), so it doubles as the
# lab deploy runbook.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${WORK:-/tmp/geneza-relay-update-proof}"
BIN="$WORK/bin"
GW_DATA="$WORK/controller"
SIGN="$WORK/sign"
RELAY="$WORK/relay"            # the relay's bootstrap-managed tree
HOME_DIR="$WORK/home"          # $GENEZA_HOME for the admin CLI profile

GRPC_PORT="${GRPC_PORT:-17401}"
HTTP_PORT="${HTTP_PORT:-17402}"
RELAY_PORT="${RELAY_PORT:-17403}"
RELAY_DATA_PORT="${RELAY_DATA_PORT:-17404}"
RELAY_ID="relay-eu-1"

GW_PID=""
RELAY_BOOT_PID=""
cleanup() {
	[ -n "$RELAY_BOOT_PID" ] && kill "$RELAY_BOOT_PID" 2>/dev/null || true
	[ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null || true
	wait 2>/dev/null || true
}
trap cleanup EXIT

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32mOK\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

# A relay reports its build version on /clusterconsole and on its heartbeat; here
# we read the version straight off the installed binary the bootstrap is running.
installed_relay_version() {
	# The bootstrap writes the running version into its state file.
	python3 - "$RELAY/state/bootstrap-state.json" <<'PY' 2>/dev/null || true
import json,sys
try:
    print(json.load(open(sys.argv[1])).get("current",""))
except Exception:
    print("")
PY
}

wait_for_version() {
	local want="$1" timeout="${2:-60}" t=0
	while [ "$t" -lt "$timeout" ]; do
		[ "$(installed_relay_version)" = "$want" ] && return 0
		sleep 1; t=$((t+1))
	done
	return 1
}

rm -rf "$WORK"; mkdir -p "$BIN" "$SIGN" "$RELAY"/{versions,state,run,etc} "$HOME_DIR"

say "build binaries"
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN/geneza-controller"  ./cmd/geneza-controller )
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN/geneza-relay"     ./cmd/geneza-relay )
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN/geneza-bootstrap" ./cmd/geneza-bootstrap )
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN/geneza-sign"      ./cmd/geneza-sign )
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN/geneza"           ./cmd/geneza )
( cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN/genezactl"        ./cmd/genezactl )
ok "binaries built into $BIN"

say "offline signing keys + TUF-lite root-keys (geneza-sign)"
# The relay update rides the SAME trust chain as the agent: an offline ROOT key
# authorizes a rotatable signing key via root-keys.json; the relay pins the ROOT.
"$BIN/geneza-sign" keygen --out-dir "$SIGN" --name root   >/dev/null
"$BIN/geneza-sign" keygen --out-dir "$SIGN" --name signer1 >/dev/null
"$BIN/geneza-sign" root-keys --root-key "$SIGN/root.key" \
	--signer-pub "$SIGN/signer1.pub" --version 1 --out "$SIGN/root-keys.json" >/dev/null
ok "root.pub (pinned on the relay) + signer1 + root-keys.json"

say "controller config + init"
cat >"$WORK/policy.yaml" <<'EOF'
roles:
  admin:
    allow:
      - actions: ["*"]
        node_labels: {"*": "*"}
bindings:
  - role: admin
    users: [root]
EOF
cat >"$WORK/controller.yaml" <<EOF
data_dir: $GW_DATA
cluster_name: relay-update-proof
grpc_listen: 127.0.0.1:$GRPC_PORT
http_listen: 127.0.0.1:$HTTP_PORT
policy_file: $WORK/policy.yaml
relay_addrs:
  - 127.0.0.1:$RELAY_PORT
advertise:
  dns_names: [localhost]
  ips: [127.0.0.1]
# Defense-in-depth publish gate + the TUF-lite root-keys the controller serves to
# the relay bootstrap alongside every manifest (identical to the agent path).
artifact_pubkey_file: $SIGN/signer1.pub
root_keys_file: $SIGN/root-keys.json
EOF
"$BIN/geneza-controller" init --config "$WORK/controller.yaml" >/dev/null
ok "controller initialized at $GW_DATA"

say "issue the relay's mTLS server cert + a break-glass admin cert"
# A bootstrap-supervised relay needs the SAME identity material as a bare relay:
# its per-relay server cert (identity geneza://relay/<id>) and the controller CA.
"$BIN/geneza-controller" issue-relay-cert --config "$WORK/controller.yaml" \
	--name "$RELAY_ID" --ip 127.0.0.1 --dns localhost --out-dir "$RELAY/etc" >/dev/null
# Break-glass admin cert to drive the rollout from the CLI.
"$BIN/geneza-controller" issue-user-cert --config "$WORK/controller.yaml" \
	--name root --roles admin --out-dir "$HOME_DIR" >/dev/null
ok "relay cert ($RELAY/etc/$RELAY_ID.crt) + admin cert"

say "start the controller"
"$BIN/geneza-controller" serve --config "$WORK/controller.yaml" >"$WORK/controller.log" 2>&1 &
GW_PID=$!
for i in $(seq 1 30); do
	curl -sk "https://127.0.0.1:$HTTP_PORT/healthz" 2>/dev/null | grep -q ok && break
	sleep 0.5
done
curl -sk "https://127.0.0.1:$HTTP_PORT/healthz" | grep -q ok || die "controller never came up (see $WORK/controller.log)"
ok "controller serving (grpc 127.0.0.1:$GRPC_PORT, http 127.0.0.1:$HTTP_PORT)"

say "seed the admin CLI profile (break-glass cert) for the relay rollout"
# The CLI reads its profile from \$GENEZA_HOME/<profile>; assemble it from the
# break-glass cert so the proof can drive the relay ring over gRPC.
mkdir -p "$HOME_DIR/default"
cp "$HOME_DIR/ca.pem"  "$HOME_DIR/default/ca.pem"
cp "$HOME_DIR/user.crt" "$HOME_DIR/default/user.crt"
cp "$HOME_DIR/user.key" "$HOME_DIR/default/user.key"
CA_SHA="$(sha256sum "$HOME_DIR/ca.pem" | cut -d' ' -f1)"
cat >"$HOME_DIR/default/profile.json" <<EOF
{"controller_grpc":"127.0.0.1:$GRPC_PORT","controller_http":"https://127.0.0.1:$HTTP_PORT","user":"root","ca_sha256":"$CA_SHA"}
EOF
export GENEZA_HOME="$HOME_DIR"
gzctl() { "$BIN/genezactl" "$@"; }
ok "admin profile seeded (GENEZA_HOME=$HOME_DIR)"

# --- a helper that publishes a relay binary as version $1 -------------------
# Publishing a relay reuses the EXISTING release-publish path unchanged: the
# manifest's product is geneza-relay, so the controller stores it under that product.
publish_relay() {
	local ver="$1" src="$2"
	local mdir="$WORK/manifests/$ver"; mkdir -p "$mdir"
	cp "$src" "$mdir/geneza-relay"
	"$BIN/geneza-sign" manifest --key "$SIGN/signer1.key" --binary "$mdir/geneza-relay" \
		--product geneza-relay --version "$ver" --os linux --arch amd64 \
		--out "$mdir/manifest.json" >/dev/null
	gzctl release publish --manifest "$mdir/manifest.json" --binary "$mdir/geneza-relay" >/dev/null
}

# A deliberately broken relay binary: it exits non-zero immediately, so it NEVER
# writes its health file — exactly what the bootstrap health gate must catch.
make_broken_relay() {
	cat >"$WORK/broken-relay.sh" <<'EOS'
#!/bin/sh
echo "broken relay: refusing to serve" >&2
exit 1
EOS
	chmod +x "$WORK/broken-relay.sh"
	echo "$WORK/broken-relay.sh"
}

say "publish relay v1 and set the relay STABLE ring to v1"
publish_relay v1 "$BIN/geneza-relay"
gzctl release target --product relay --ring stable --version v1
gzctl release target --product relay --show
ok "relay v1 published + relay stable = v1"

say "relay.yaml + bootstrap.json for the bootstrap-supervised relay"
# The relay's worker config. KEY CHANGE vs the bare service: health_file is set,
# so the relay touches it once serving — the signal the bootstrap health-gates on.
cat >"$RELAY/etc/relay.yaml" <<EOF
listen: "127.0.0.1:$RELAY_PORT"
data_listen: "127.0.0.1:$RELAY_DATA_PORT"
tls: true
cert_file: $RELAY/etc/$RELAY_ID.crt
key_file: $RELAY/etc/$RELAY_ID.key
public_ip: 127.0.0.1
relay_id: $RELAY_ID
health_file: $RELAY/run/worker.health
EOF
# The bootstrap config. product=geneza-relay makes the SAME bootstrap binary
# supervise the relay: it polls ?product=geneza-relay, installs with the relay
# manifest, names the on-disk binary geneza-relay, and health-gates/rolls back.
cat >"$RELAY/etc/bootstrap.json" <<EOF
{
  "controller_http_url": "https://127.0.0.1:$HTTP_PORT",
  "product": "geneza-relay",
  "worker_config": "$RELAY/etc/relay.yaml",
  "ca_roots_file": "$HOME_DIR/ca.pem",
  "artifact_pub_file": "",
  "root_pub_file": "$SIGN/root.pub",
  "versions_dir": "$RELAY/versions",
  "state_file": "$RELAY/state/bootstrap-state.json",
  "node_id_file": "$RELAY/state/relay-id",
  "run_dir": "$RELAY/run",
  "poll_interval_sec": 2,
  "health_timeout_sec": 20
}
EOF
# The bootstrap polls ?node=<relayId>; seed the id file so it uses the relay id
# (matching the cert) rather than the hostname.
printf '%s' "$RELAY_ID" >"$RELAY/state/relay-id"
ok "relay.yaml + bootstrap.json written (health_file + product=geneza-relay)"

say "start the bootstrap-supervised relay; it should self-install v1"
"$BIN/geneza-bootstrap" --config "$RELAY/etc/bootstrap.json" >"$WORK/relay-boot.log" 2>&1 &
RELAY_BOOT_PID=$!
wait_for_version v1 60 || die "relay never self-installed v1 (see $WORK/relay-boot.log)"
test -f "$RELAY/run/worker.health" || die "relay v1 never wrote its health file"
ok "relay self-installed v1 and is serving (health file present)"

say "publish relay v2 and promote relay STABLE to v2; relay should self-update"
# Build a v2 that is visibly different (rebuild with a version ldflag bump).
( cd "$ROOT" && CGO_ENABLED=0 go build \
	-ldflags "-X geneza.io/internal/version.Version=v2" \
	-o "$WORK/geneza-relay-v2" ./cmd/geneza-relay )
publish_relay v2 "$WORK/geneza-relay-v2"
gzctl release target --product relay --ring stable --version v2
wait_for_version v2 60 || die "relay never self-updated to v2 (see $WORK/relay-boot.log)"
ok "relay self-updated v1 -> v2 (health-gated commit)"

say "publish a BROKEN relay v3, promote to v3, expect health-gated ROLLBACK to v2"
BROKEN="$(make_broken_relay)"
publish_relay v3 "$BROKEN"
gzctl release target --product relay --ring stable --version v3
# The bootstrap will install v3, swap, fail the health gate (no health file from a
# binary that exits immediately), and roll back. After the dust settles it must be
# running v2 again and the relay must be healthy.
sleep 35
CUR="$(installed_relay_version)"
[ "$CUR" = "v2" ] || die "expected rollback to v2, bootstrap is on '$CUR' (see $WORK/relay-boot.log)"
grep -q "rolled back to previous worker" "$WORK/relay-boot.log" \
	|| grep -q "rolling back" "$WORK/relay-boot.log" \
	|| die "no rollback evidence in the bootstrap log"
test -f "$RELAY/run/worker.health" || die "relay has no healthy worker after rollback"
ok "broken v3 health-gated; rolled back to v2; relay still healthy"

say "ALL CHECKS PASSED"
echo "Logs: controller=$WORK/controller.log  relay-bootstrap=$WORK/relay-boot.log"
echo
echo "Relay deploy shape proven here (vs the bare geneza-relay.service):"
echo "  - run geneza-bootstrap (NOT geneza-relay directly) with product=geneza-relay"
echo "  - bootstrap.json: controller_http_url, ca_roots_file, root_pub_file (pin the ROOT),"
echo "    worker_config=relay.yaml, versions_dir/state_file/run_dir, node_id_file=relay id"
echo "  - relay.yaml: add health_file (= run_dir/worker.health) so the relay signals readiness"
echo "  - seed the first version by publishing it + setting the relay stable ring,"
echo "    OR image-bake one versions_dir/<ver>/geneza-relay for offline adoption"
