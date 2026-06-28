#!/usr/bin/env bash
# Geneza agent installer — install the node agent as a daemon with one command:
#
#   curl -fsSL https://raw.githubusercontent.com/geneza-ai/geneza/main/deploy/install/install-agent.sh \
#     | sudo bash -s -- gzk_XXXX
#
# where gzk_XXXX is the one-time enrollment code from `geneza node enroll`.
# If the code does not embed the controller endpoints (the default code is meant
# for the controller-served install.sh, which derives them from its own origin),
# pass them explicitly: --controller gw.example.com:7401 --token gz-XXXX.
#
# It downloads the right geneza-agent for this node, enrolls it with the
# controller using a one-time join token, and installs a systemd service that runs
# the worker (which self-spawns the persistent session host). The node lands
# PENDING until an admin approves it, so the token alone grants no access.
#
# The agent is Linux-only (kernel TUN data plane + embedded node_exporter). For
# the user-facing client (`geneza`) on macOS/Windows, download a release archive.
set -euo pipefail

# --- defaults -----------------------------------------------------------------
REPO="geneza-ai/geneza"
BASE_URL="${GENEZA_BASE_URL:-}"        # full base dir holding the archives (override for mirrors/testing)
VERSION="${GENEZA_VERSION:-}"          # e.g. 1.2.3 — empty means "latest"
CONTROLLER=""                             # gRPC host:port (required)
CONTROLLER_HTTP=""                        # https URL for enroll/updates (derived from --controller if empty)
TOKEN=""                               # one-time join token (required unless --uninstall)
NAME=""                                # node name (default: hostname)
LABELS=""                              # k=v,k2=v2
CA_SRC=""                              # CA roots bundle: local path or URL (else TOFU at enroll)
NO_START=0
DO_UNINSTALL=0
SKIP_CHECKSUM=0

BIN_DIR=/usr/local/bin
ETC_DIR=/etc/geneza
STATE_DIR=/var/lib/geneza/agent
SPOOL_DIR=/var/lib/geneza/spool
RUN_DIR=/run/geneza
UNIT=/etc/systemd/system/geneza-agent.service

die() { echo "geneza-install: $*" >&2; exit 1; }
log() { echo "==> $*"; }

usage() {
  cat <<'EOF'
usage: install-agent.sh gzk_CODE [options]
       install-agent.sh --controller HOST:PORT --token TOKEN [options]

enrollment (either form):
  gzk_CODE                one-time enrollment code from `geneza node enroll`
                          (also accepted as --token gzk_CODE); embeds the join
                          token and, when present, the controller endpoints
  --controller HOST:PORT     controller gRPC address (e.g. gw.example.com:7401)
  --token TOKEN           one-time join token (gz-... or a gzk_ code)

options:
  --controller-http URL      controller HTTPS base (default: https://<controller-host>:7402)
  --name NAME             node name (default: hostname)
  --labels k=v,k2=v2      node labels
  --ca PATH|URL           CA roots bundle to pre-place (else trust-on-first-use at enroll)
  --version VER           release version to install (default: latest)
  --base-url URL          archive base dir (default: GitHub release assets)
  --no-start              install + enroll but do not enable/start the service
  --skip-checksum         do not verify the downloaded archive against SHA256SUMS
  --uninstall             stop the service and remove agent files (keeps node record)
  -h, --help              this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --controller)       CONTROLLER="${2:-}"; shift 2 ;;
    --controller-http)  CONTROLLER_HTTP="${2:-}"; shift 2 ;;
    --token)         TOKEN="${2:-}"; shift 2 ;;
    --name)          NAME="${2:-}"; shift 2 ;;
    --labels)        LABELS="${2:-}"; shift 2 ;;
    --ca)            CA_SRC="${2:-}"; shift 2 ;;
    --version)       VERSION="${2:-}"; shift 2 ;;
    --base-url)      BASE_URL="${2:-}"; shift 2 ;;
    --no-start)      NO_START=1; shift ;;
    --skip-checksum) SKIP_CHECKSUM=1; shift ;;
    --uninstall)     DO_UNINSTALL=1; shift ;;
    -h|--help)       usage; exit 0 ;;
    gzk_*)           TOKEN="$1"; shift ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "must run as root (pipe to 'sudo bash')"

# --- uninstall ----------------------------------------------------------------
if [ "$DO_UNINSTALL" = 1 ]; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now geneza-agent.service 2>/dev/null || true
    rm -f "$UNIT"
    systemctl daemon-reload 2>/dev/null || true
  fi
  rm -f "$BIN_DIR/geneza-agent"
  log "removed the geneza-agent service and binary"
  echo "    kept $ETC_DIR and $STATE_DIR (node identity); 'rm -rf' them to fully reset,"
  echo "    and run 'geneza node retire <name>' on the controller to drop the record."
  exit 0
fi

# An enrollment code (gzk_..., from 'geneza node enroll' or OpenStack
# vendordata) bundles the join token and — when present — the controller
# endpoints, so the same code works with both installers. Decode it in POSIX sh;
# explicit --controller/--controller-http flags still win over what it carries.
# The code also carries the root-key fingerprint; this installer trusts the
# controller via --ca / trust-on-first-use, so it has no use for it.
b64dec() {
  if printf '' | base64 -d >/dev/null 2>&1; then base64 -d
  elif printf '' | base64 -D >/dev/null 2>&1; then base64 -D
  elif command -v openssl >/dev/null 2>&1; then openssl base64 -d -A
  else die "need base64 or openssl to decode the enrollment code"; fi
}
case "$TOKEN" in
  gzk_*)
    _b="$(printf %s "${TOKEN#gzk_}" | tr '_-' '/+')"
    case $(( ${#_b} % 4 )) in 2) _b="${_b}==" ;; 3) _b="${_b}=" ;; esac
    _p="$(printf %s "$_b" | b64dec 2>/dev/null)" || die "invalid enrollment code"
    # word-split the decoded payload on ';' into positional params; set -f keeps
    # globbing off so the split is the only effect (quoting $_p would defeat it).
    set -f; oIFS="$IFS"; IFS=';'
    # shellcheck disable=SC2086
    set -- $_p
    IFS="$oIFS"; set +f
    TOKEN="${1:-}"
    [ -z "$CONTROLLER" ]      && [ -n "${5:-}" ] && CONTROLLER="${5}"
    [ -z "$CONTROLLER_HTTP" ] && [ -n "${4:-}" ] && CONTROLLER_HTTP="${4}"
    [ -z "$CONTROLLER_HTTP" ] && [ -n "${3:-}" ] && CONTROLLER_HTTP="${3}"
    [ -n "$TOKEN" ] || die "enrollment code carries no token"
    ;;
esac

# --- validate -----------------------------------------------------------------
[ -n "$CONTROLLER" ] || { usage; die "no controller address — pass --controller HOST:PORT, or a gzk_ code that embeds it"; }
[ -n "$TOKEN" ]   || die "missing --token (get one from 'geneza node enroll')"
case "$CONTROLLER" in *:*) ;; *) die "--controller must be HOST:PORT (e.g. gw.example.com:7401)" ;; esac

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
[ "$OS" = linux ] || die "the agent is Linux-only (got $OS); install the 'geneza' client from a release archive instead"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $ARCH" ;;
esac

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar  >/dev/null 2>&1 || die "tar is required"
[ -n "$NAME" ] || NAME="$(hostname 2>/dev/null || echo geneza-node)"

host_of() { echo "$1" | sed -e 's#^[a-z][a-z]*://##' -e 's#/.*$##' -e 's#:.*$##'; }
[ -n "$CONTROLLER_HTTP" ] || CONTROLLER_HTTP="https://$(host_of "$CONTROLLER"):7402"

# Resolve the archive base URL. Default to the GitHub release assets: a pinned
# version uses the tagged release, otherwise the 'latest' redirect (no API call,
# so the installer stays dependency-free).
ARCHIVE="geneza_linux_${ARCH}.tar.gz"
if [ -z "$BASE_URL" ]; then
  if [ -n "$VERSION" ]; then
    BASE_URL="https://github.com/${REPO}/releases/download/v${VERSION#v}"
  else
    BASE_URL="https://github.com/${REPO}/releases/latest/download"
  fi
fi

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else die "need sha256sum or shasum to verify the download"; fi
}

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
log "geneza agent: controller=$CONTROLLER http=$CONTROLLER_HTTP os=$OS arch=$ARCH name=$NAME"

log "downloading $ARCHIVE from $BASE_URL"
curl -fSL "$BASE_URL/$ARCHIVE" -o "$TMP/$ARCHIVE" || die "download failed: $BASE_URL/$ARCHIVE"

if [ "$SKIP_CHECKSUM" = 0 ]; then
  if curl -fsSL "$BASE_URL/SHA256SUMS" -o "$TMP/SHA256SUMS" 2>/dev/null; then
    want="$(grep " $ARCHIVE\$" "$TMP/SHA256SUMS" | cut -d' ' -f1 || true)"
    if [ -n "$want" ]; then
      got="$(sha256_of "$TMP/$ARCHIVE")"
      [ "$got" = "$want" ] || die "checksum mismatch for $ARCHIVE
  expected: $want
  got:      $got"
      log "checksum verified ($got)"
    else
      echo "    note: $ARCHIVE not listed in SHA256SUMS; skipping checksum"
    fi
  else
    echo "    note: no SHA256SUMS at $BASE_URL; skipping checksum (pass --skip-checksum to silence)"
  fi
fi

log "extracting geneza-agent"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP"
AGENT_BIN="$(find "$TMP" -type f -name geneza-agent | head -n1)"
[ -n "$AGENT_BIN" ] || die "geneza-agent not found in $ARCHIVE"

log "installing files"
install -d -m0755 "$BIN_DIR" "$ETC_DIR"
install -d -m0700 "$STATE_DIR" "$SPOOL_DIR"
install -d -m0755 "$RUN_DIR"
install -m0755 "$AGENT_BIN" "$BIN_DIR/geneza-agent"

# Pre-place operator-trusted CA roots (the secure path). Without it the agent
# trust-on-first-use fetches the bundle at enroll and logs its fingerprint.
if [ -n "$CA_SRC" ]; then
  case "$CA_SRC" in
    http://*|https://*) curl -fsSL "$CA_SRC" -o "$STATE_DIR/ca-roots.pem" || die "fetch --ca failed: $CA_SRC" ;;
    *) [ -f "$CA_SRC" ] || die "--ca file not found: $CA_SRC"; install -m0600 "$CA_SRC" "$STATE_DIR/ca-roots.pem" ;;
  esac
  log "placed CA roots at $STATE_DIR/ca-roots.pem"
fi

# agent.yaml. The worker self-spawns + supervises the session host.
LBL="{}"
[ -n "$LABELS" ] && LBL="{$(echo "$LABELS" | sed 's/ *, */, /g; s/=/: /g')}"
cat > "$ETC_DIR/agent.yaml" <<EOF
controller_grpc_addr: $CONTROLLER
controller_http_url: $CONTROLLER_HTTP
state_dir: $STATE_DIR
name: "$NAME"
labels: $LBL
session_host_socket: $RUN_DIR/session-host.sock
spool_dir: $SPOOL_DIR
health_file: $RUN_DIR/worker.health
spawn_session_host: true
# Userspace data plane (pion ICE/TURN/STUN over wireguard-go): NAT-traverses so
# a node behind SNAT still meshes; falls back to the blind relay floor.
dataplane: userspace
dataplane_relay_only: false
EOF
chmod 0644 "$ETC_DIR/agent.yaml"

log "enrolling with the controller"
"$BIN_DIR/geneza-agent" enroll --config "$ETC_DIR/agent.yaml" \
  --token "$TOKEN" --name "$NAME" --controller "$CONTROLLER" --force

if ! command -v systemctl >/dev/null 2>&1; then
  log "no systemd detected — start the worker yourself (and keep it running):"
  echo "    $BIN_DIR/geneza-agent worker --config $ETC_DIR/agent.yaml"
  exit 0
fi

# KillMode=process so a service restart leaves the session host (and its live
# PTYs) running; the worker re-adopts the healthy socket on start. That is the
# session-persistence guarantee a single-unit install preserves.
cat > "$UNIT" <<EOF
[Unit]
Description=Geneza node agent (worker + session host)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN_DIR/geneza-agent worker --config $ETC_DIR/agent.yaml
Restart=always
RestartSec=2
KillMode=process
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
if [ "$NO_START" = 1 ]; then
  systemctl enable geneza-agent.service >/dev/null 2>&1 || true
  log "installed geneza-agent.service (not started; --no-start)"
else
  systemctl enable --now geneza-agent.service
  log "started geneza-agent.service"
fi

echo
echo "Enrolled '$NAME'. It is PENDING admin approval — no session can reach it"
echo "until an admin runs:  geneza node approve $NAME"
echo "Logs:  journalctl -u geneza-agent -f"
