package controller

// installScript is served at GET /install.sh. __CONTROLLER_HTTP__ is replaced with
// the origin the operator reached the controller on. POSIX sh (works under dash);
// the security model is in installer.go. It verifies the root key fingerprint
// BEFORE trusting anything else it downloads.
const installScript = `#!/bin/sh
# Geneza agent installer (curl | sudo bash). Verifies the TUF-lite root key
# against --root-fp, enrolls with a one-time join token, and starts the
# supervised bootstrap. The new node is PENDING until an admin approves it.
set -eu

CONTROLLER_HTTP="__CONTROLLER_HTTP__"
CONTROLLER_HTTP_RUNTIME=""
CONTROLLER_GRPC=""
ENROLL=""
TOKEN=""; ROOT_FP=""; NAME=""; LABELS=""; BOOTSTRAP_SHA=""; AGENT_SHA=""

die() { echo "geneza-install: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --token)                   ENROLL="${2:-}"; shift 2 ;;
    --name)                    NAME="${2:-}"; shift 2 ;;
    --labels)                  LABELS="${2:-}"; shift 2 ;;
    --bootstrap-sha256)        BOOTSTRAP_SHA="${2:-}"; shift 2 ;;
    --agent-sha256)            AGENT_SHA="${2:-}"; shift 2 ;;
    --controller-http)         CONTROLLER_HTTP="${2:-}"; shift 2 ;;
    --controller-http-runtime) CONTROLLER_HTTP_RUNTIME="${2:-}"; shift 2 ;;
    --controller-grpc)         CONTROLLER_GRPC="${2:-}"; shift 2 ;;
    -h|--help) echo "usage: install.sh <gzk_CODE> [--name N] [--labels k=v,...] [--controller-http URL] [--controller-http-runtime URL] [--controller-grpc host:7401] [--bootstrap-sha256 sha256:...] [--agent-sha256 sha256:...]"; exit 0 ;;
    gzk_*)                     ENROLL="$1"; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

# The enrollment code (gzk_..., from 'geneza node enroll' or OpenStack
# vendordata) bundles the one-time join token, the pinned root-key fingerprint,
# and — when they differ from the defaults — the controller endpoints. The
# fingerprint is what makes curl|bash safe: the node refuses to install unless
# the root key it downloads hashes to the pinned value. Decode it in POSIX sh.
b64dec() {
  if printf '' | base64 -d >/dev/null 2>&1; then base64 -d
  elif printf '' | base64 -D >/dev/null 2>&1; then base64 -D
  elif command -v openssl >/dev/null 2>&1; then openssl base64 -d -A
  else die "need base64 or openssl to decode the enrollment code"; fi
}
case "$ENROLL" in
  gzk_*)
    _b="$(printf %s "${ENROLL#gzk_}" | tr '_-' '/+')"
    case $(( ${#_b} % 4 )) in 2) _b="${_b}==" ;; 3) _b="${_b}=" ;; esac
    _p="$(printf %s "$_b" | b64dec 2>/dev/null)" || die "invalid enrollment code"
    set -f; oIFS="$IFS"; IFS=';'; set -- $_p; IFS="$oIFS"; set +f
    TOKEN="${1:-}"; ROOT_FP="${2:-}"
    [ -n "${3:-}" ] && CONTROLLER_HTTP="${3}"
    [ -n "${4:-}" ] && CONTROLLER_HTTP_RUNTIME="${4}"
    [ -n "${5:-}" ] && CONTROLLER_GRPC="${5}"
    ;;
  "") die "missing enrollment code — run 'geneza node enroll' and paste its gzk_... one-liner" ;;
  *)  die "unrecognized enrollment code (expected gzk_...)" ;;
esac

# The installer FETCHES install.sh/binaries/ca-roots over CONTROLLER_HTTP (a
# public, publicly-trusted TLS front so this very curl works). The agent +
# bootstrap then talk to the controller at RUNTIME (gRPC + the update HTTP API)
# using the controller's OWN cert, pinned via the ca-roots they just fetched.
# Endpoints absent from the code default: runtime to the fetch URL, grpc to
# host(runtime):7401.
[ -n "$CONTROLLER_HTTP_RUNTIME" ] || CONTROLLER_HTTP_RUNTIME="$CONTROLLER_HTTP"

[ -n "$TOKEN" ]   || die "enrollment code carries no token"
[ -n "$ROOT_FP" ] || die "enrollment code carries no root fingerprint"
[ "$(id -u)" = 0 ] || die "must run as root (pipe to 'sudo sh')"
command -v curl >/dev/null 2>&1 || die "curl is required"
[ -n "$NAME" ] || NAME="$(hostname 2>/dev/null || echo geneza-node)"

host_of() { echo "$1" | sed -e 's#^[a-z]*://##' -e 's#/.*$##' -e 's#:.*$##'; }
[ -n "$CONTROLLER_GRPC" ] || CONTROLLER_GRPC="$(host_of "$CONTROLLER_HTTP_RUNTIME"):7401"

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
echo "==> geneza: controller=$CONTROLLER_HTTP grpc=$CONTROLLER_GRPC os=$OS arch=$ARCH name=$NAME"

echo "==> fetching + verifying trust anchor (TUF-lite root key)"
curl -fsSL "$CONTROLLER_HTTP/v1/root-pubkey" -o "$TMP/root.pub" || die "fetch root pubkey failed"
GOT="sha256:$(sha256_of "$TMP/root.pub")"
if [ "$GOT" != "$ROOT_FP" ]; then
  die "ROOT KEY FINGERPRINT MISMATCH
  expected: $ROOT_FP
  served:   $GOT
refusing to install — the controller may be impersonated."
fi
echo "    root key verified ($GOT)"

curl -fsSL "$CONTROLLER_HTTP/v1/ca-roots" -o "$TMP/ca-roots.pem" || die "fetch ca-roots failed"
echo "==> fetching stage-1 binaries ($OS/$ARCH)"
curl -fsSL "$CONTROLLER_HTTP/v1/install/bin/geneza-bootstrap-$OS-$ARCH" -o "$TMP/geneza-bootstrap" || die "fetch bootstrap failed"
curl -fsSL "$CONTROLLER_HTTP/v1/install/bin/geneza-agent-$OS-$ARCH" -o "$TMP/geneza-agent" || die "fetch agent failed"

# Verify stage-1 binaries against caller-pinned hashes BEFORE making them
# executable. The hashes arrive over the same trusted channel the
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
  "controller_http_url": "$CONTROLLER_HTTP_RUNTIME",
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
controller_grpc_addr: $CONTROLLER_GRPC
controller_http_url: $CONTROLLER_HTTP_RUNTIME
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

echo "==> enrolling with the controller"
/opt/geneza/bin/geneza-agent enroll --config /etc/geneza/agent.yaml --token "$TOKEN" --name "$NAME" --controller "$CONTROLLER_GRPC" --force

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
echo "until an admin runs:  geneza node approve $NAME"
`
