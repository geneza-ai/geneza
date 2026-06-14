package gateway

// installScript is served at GET /install.sh. __GATEWAY_HTTP__ is replaced with
// the origin the operator reached the gateway on. POSIX sh (works under dash);
// the security model is in installer.go. It verifies the root key fingerprint
// BEFORE trusting anything else it downloads.
const installScript = `#!/bin/sh
# Geneza agent installer (curl | sudo bash). Verifies the TUF-lite root key
# against --root-fp, enrolls with a one-time join token, and starts the
# supervised bootstrap. The new machine is PENDING until an admin approves it.
set -eu

GATEWAY_HTTP="__GATEWAY_HTTP__"
GATEWAY_HTTP_RUNTIME=""
GATEWAY_GRPC=""
TOKEN=""; ROOT_FP=""; NAME=""; LABELS=""; BOOTSTRAP_SHA=""; AGENT_SHA=""

while [ $# -gt 0 ]; do
  case "$1" in
    --token)               TOKEN="${2:-}"; shift 2 ;;
    --root-fp)             ROOT_FP="${2:-}"; shift 2 ;;
    --name)                NAME="${2:-}"; shift 2 ;;
    --labels)              LABELS="${2:-}"; shift 2 ;;
    --bootstrap-sha256)    BOOTSTRAP_SHA="${2:-}"; shift 2 ;;
    --agent-sha256)        AGENT_SHA="${2:-}"; shift 2 ;;
    --gateway-http)        GATEWAY_HTTP="${2:-}"; shift 2 ;;
    --gateway-http-runtime) GATEWAY_HTTP_RUNTIME="${2:-}"; shift 2 ;;
    --gateway-grpc)        GATEWAY_GRPC="${2:-}"; shift 2 ;;
    -h|--help) echo "usage: install.sh --token T --root-fp sha256:... [--bootstrap-sha256 sha256:...] [--agent-sha256 sha256:...] [--name N] [--labels k=v,...] [--gateway-http URL] [--gateway-http-runtime URL] [--gateway-grpc host:7401]"; exit 0 ;;
    *) echo "geneza-install: unknown argument: $1" >&2; exit 2 ;;
  esac
done

# The installer FETCHES install.sh/binaries/ca-roots over GATEWAY_HTTP (which may
# be a public, publicly-trusted TLS front so this very curl works). The agent +
# bootstrap then talk to the gateway at RUNTIME (gRPC + the update HTTP API)
# using the gateway's OWN cert, pinned via the ca-roots they just fetched. When
# the two differ (public installer front vs direct gateway endpoint) pass
# --gateway-http-runtime; otherwise it defaults to GATEWAY_HTTP.
[ -n "$GATEWAY_HTTP_RUNTIME" ] || GATEWAY_HTTP_RUNTIME="$GATEWAY_HTTP"

die() { echo "geneza-install: $*" >&2; exit 1; }
[ -n "$TOKEN" ]   || die "missing --token"
[ -n "$ROOT_FP" ] || die "missing --root-fp (copy it from 'geneza admin tokens new')"
[ "$(id -u)" = 0 ] || die "must run as root (pipe to 'sudo bash')"
command -v curl >/dev/null 2>&1 || die "curl is required"
[ -n "$NAME" ] || NAME="$(hostname 2>/dev/null || echo geneza-node)"

host_of() { echo "$1" | sed -e 's#^[a-z]*://##' -e 's#/.*$##' -e 's#:.*$##'; }
[ -n "$GATEWAY_GRPC" ] || GATEWAY_GRPC="$(host_of "$GATEWAY_HTTP_RUNTIME"):7401"

OS="$(uname -s | tr 'A-Z' 'a-z')"
case "$OS" in linux|darwin) ;; *) die "unsupported OS: $OS" ;; esac
ARCH="$(uname -m)"
case "$ARCH" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) die "unsupported arch: $ARCH" ;; esac

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else die "need sha256sum or shasum"; fi
}

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
echo "==> geneza: gateway=$GATEWAY_HTTP grpc=$GATEWAY_GRPC os=$OS arch=$ARCH name=$NAME"

echo "==> fetching + verifying trust anchor (TUF-lite root key)"
curl -fsSL "$GATEWAY_HTTP/v1/root-pubkey" -o "$TMP/root.pub" || die "fetch root pubkey failed"
GOT="sha256:$(sha256_of "$TMP/root.pub")"
if [ "$GOT" != "$ROOT_FP" ]; then
  die "ROOT KEY FINGERPRINT MISMATCH
  expected: $ROOT_FP
  served:   $GOT
refusing to install — the gateway may be impersonated."
fi
echo "    root key verified ($GOT)"

curl -fsSL "$GATEWAY_HTTP/v1/ca-roots" -o "$TMP/ca-roots.pem" || die "fetch ca-roots failed"
echo "==> fetching stage-1 binaries ($OS/$ARCH)"
curl -fsSL "$GATEWAY_HTTP/v1/install/bin/geneza-bootstrap-$OS-$ARCH" -o "$TMP/geneza-bootstrap" || die "fetch bootstrap failed"
curl -fsSL "$GATEWAY_HTTP/v1/install/bin/geneza-agent-$OS-$ARCH" -o "$TMP/geneza-agent" || die "fetch agent failed"

# Verify stage-1 binaries against caller-pinned hashes BEFORE making them
# executable (security #2). The hashes arrive over the same trusted channel the
# root-fp anchors / TLS protects; a tampered binary is refused, not run.
verify_sha() { # <file> <expected "sha256:hex">
  [ -n "$2" ] || return 0
  got="sha256:$(sha256_of "$1")"
  [ "$got" = "$2" ] || die "STAGE-1 BINARY HASH MISMATCH for $1
  expected: $2
  got:      $got
refusing to install — the binary may be tampered."
}
verify_sha "$TMP/geneza-bootstrap" "$BOOTSTRAP_SHA"
verify_sha "$TMP/geneza-agent" "$AGENT_SHA"
[ -n "$BOOTSTRAP_SHA" ] && echo "    geneza-bootstrap verified ($BOOTSTRAP_SHA)"
[ -n "$AGENT_SHA" ] && echo "    geneza-agent verified ($AGENT_SHA)"
chmod +x "$TMP/geneza-bootstrap" "$TMP/geneza-agent"

echo "==> installing files"
mkdir -p /opt/geneza/bin /etc/geneza /var/lib/geneza/agent /var/lib/geneza/versions /var/lib/geneza/spool /run/geneza
install -m0755 "$TMP/geneza-bootstrap" /opt/geneza/bin/geneza-bootstrap
install -m0755 "$TMP/geneza-agent"     /opt/geneza/bin/geneza-agent
install -m0644 "$TMP/root.pub"         /etc/geneza/root.pub
install -m0644 "$TMP/ca-roots.pem"     /var/lib/geneza/agent/ca-roots.pem

cat > /etc/geneza/bootstrap.json <<EOF
{
  "gateway_http_url": "$GATEWAY_HTTP_RUNTIME",
  "ca_roots_file": "/var/lib/geneza/agent/ca-roots.pem",
  "artifact_pub_file": "",
  "root_pub_file": "/etc/geneza/root.pub",
  "versions_dir": "/var/lib/geneza/versions",
  "state_file": "/var/lib/geneza/bootstrap-state.json",
  "node_id_file": "/var/lib/geneza/agent/node-id",
  "agent_config": "/etc/geneza/agent.yaml",
  "run_dir": "/run/geneza",
  "spool_dir": "/var/lib/geneza/spool",
  "session_host_socket": "/run/geneza/session-host.sock",
  "poll_interval_sec": 15,
  "health_timeout_sec": 60
}
EOF

LBL="{}"
[ -n "$LABELS" ] && LBL="{$(echo "$LABELS" | sed 's/=/: /g')}"
cat > /etc/geneza/agent.yaml <<EOF
gateway_grpc_addr: $GATEWAY_GRPC
gateway_http_url: $GATEWAY_HTTP_RUNTIME
state_dir: /var/lib/geneza/agent
name: "$NAME"
labels: $LBL
session_host_socket: /run/geneza/session-host.sock
spool_dir: /var/lib/geneza/spool
health_file: /run/geneza/worker.health
spawn_session_host: true
# Userspace data plane (pion ICE/TURN/STUN over wireguard-go): NAT-traverses
# (hole-punch + relay fallback) so a cloud VM behind SNAT can still mesh.
dataplane: userspace
dataplane_relay_only: false
EOF

echo "==> enrolling with the gateway"
/opt/geneza/bin/geneza-agent enroll --config /etc/geneza/agent.yaml --token "$TOKEN" --name "$NAME" --gateway "$GATEWAY_GRPC" --force

if command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/geneza-bootstrap.service <<'EOF'
[Unit]
Description=Geneza bootstrap (agent supervisor + updater)
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/opt/geneza/bin/geneza-bootstrap --config /etc/geneza/bootstrap.json
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now geneza-bootstrap
  echo "==> started geneza-bootstrap.service"
else
  echo "==> no systemd detected; start manually:"
  echo "    /opt/geneza/bin/geneza-bootstrap --config /etc/geneza/bootstrap.json"
fi

echo
echo "Enrolled '$NAME'. It is PENDING admin approval — no session can reach it"
echo "until an admin runs:  geneza admin nodes approve $NAME"
`
