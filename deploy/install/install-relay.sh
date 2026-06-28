#!/usr/bin/env bash
# Geneza relay installer — install the rendezvous relay as a daemon with one command:
#
#   curl -fsSL https://raw.githubusercontent.com/geneza-ai/geneza/wip/deploy/install/install-relay.sh \
#     | sudo bash -s -- --controller gw.example.com:7401 \
#         --cert /tmp/relay.crt --key /tmp/relay.key --ca /tmp/ca-roots.pem --funnel
#
# It downloads the right geneza-relay for this machine, installs a systemd
# service, and — for a funnel-serving relay — runs an interactive step so YOU
# confirm the relay's public IP (the address funnel clients resolve to). There is
# no fully reliable automatic source for that ingress IP (the controller link may be
# a private VLAN; an egress probe differs behind an LB; it may live in the cloud's
# NAT table), so the choice is yours.
#
# The relay's mTLS material (--cert/--key/--ca) is provisioned out of band by the
# operator: `geneza-controller issue-relay-cert --name <relay_id>` on the controller.
set -euo pipefail

# --- defaults -----------------------------------------------------------------
REPO="geneza-ai/geneza"
BASE_URL="${GENEZA_BASE_URL:-}"        # full base dir holding the archives (override for mirrors/testing)
VERSION="${GENEZA_VERSION:-}"          # e.g. 1.2.3 — empty means "latest"
CONTROLLER=""                             # registrar host:port (required) — the controller's relay control listener
REGION="default"
RELAY_ID="$(hostname -s 2>/dev/null || hostname)"
CERT_SRC=""; KEY_SRC=""; CA_SRC=""     # relay TLS material (path or URL); required
LISTEN=":7403"                         # rendezvous TCP listener
FUNNEL=0                               # serve funnel? (public TLS terminator)
FUNNEL_LISTEN=":443"
PUBLIC_IP=""                           # skip the interactive detect if set
PUBLIC_SERVICE=""                      # optional public whoami URL for an egress hint
NO_START=0
DO_UNINSTALL=0

BIN_DIR=/usr/local/bin
ETC_DIR=/etc/geneza
TLS_DIR="$ETC_DIR/relay-tls"
UNIT=/etc/systemd/system/geneza-relay.service

die() { echo "install-relay: $*" >&2; exit 1; }

usage() {
  cat >&2 <<'EOF'
usage: install-relay.sh --controller HOST:PORT --cert PATH --key PATH --ca PATH [options]

  --controller HOST:PORT     the controller's relay registrar address (required)
  --cert PATH|URL         relay TLS certificate (issue-relay-cert) (required)
  --key  PATH|URL         relay TLS private key (required)
  --ca   PATH|URL         CA roots bundle to verify the controller (required)
  --relay-id NAME         relay id (must match the cert CN; default: hostname)
  --region NAME           region id (default: default)
  --listen ADDR           rendezvous listener (default: :7403)
  --funnel                enable the public funnel TLS listener
  --funnel-listen ADDR    funnel public listener (default: :443)
  --public-ip IP          set the funnel public IP non-interactively (skip the prompt)
  --public-service URL    optional public whoami for an egress-IP hint
  --no-start              install but do not start the service
  --uninstall             remove the relay service and binary
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --controller)        CONTROLLER="${2:-}"; shift 2 ;;
    --cert)           CERT_SRC="${2:-}"; shift 2 ;;
    --key)            KEY_SRC="${2:-}"; shift 2 ;;
    --ca)             CA_SRC="${2:-}"; shift 2 ;;
    --relay-id)       RELAY_ID="${2:-}"; shift 2 ;;
    --region)         REGION="${2:-}"; shift 2 ;;
    --listen)         LISTEN="${2:-}"; shift 2 ;;
    --funnel)         FUNNEL=1; shift ;;
    --funnel-listen)  FUNNEL_LISTEN="${2:-}"; shift 2 ;;
    --public-ip)      PUBLIC_IP="${2:-}"; shift 2 ;;
    --public-service) PUBLIC_SERVICE="${2:-}"; shift 2 ;;
    --no-start)       NO_START=1; shift ;;
    --uninstall)      DO_UNINSTALL=1; shift ;;
    -h|--help)        usage; exit 0 ;;
    *)                usage; die "unknown option: $1" ;;
  esac
done

# --- uninstall ----------------------------------------------------------------
if [ "$DO_UNINSTALL" = 1 ]; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now geneza-relay.service 2>/dev/null || true
    rm -f "$UNIT"
    systemctl daemon-reload 2>/dev/null || true
  fi
  rm -f "$BIN_DIR/geneza-relay"
  echo "geneza-relay uninstalled (config + TLS left in $ETC_DIR)"
  exit 0
fi

# --- validate -----------------------------------------------------------------
[ -n "$CONTROLLER" ] || { usage; die "missing --controller"; }
case "$CONTROLLER" in *:*) ;; *) die "--controller must be HOST:PORT" ;; esac
if [ -z "$CERT_SRC" ] || [ -z "$KEY_SRC" ] || [ -z "$CA_SRC" ]; then
  die "missing --cert/--key/--ca (run 'geneza-controller issue-relay-cert' first)"
fi
command -v curl >/dev/null 2>&1 || die "curl is required"
[ "$(id -u)" = 0 ] || die "run as root (sudo)"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
[ "$OS" = linux ] || die "the relay is Linux-only"
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported arch $(uname -m)" ;;
esac

fetch() { # fetch SRC DEST — SRC is a local path or a URL
  case "$1" in
    http://*|https://*) curl -fsSL "$1" -o "$2" ;;
    *) cp "$1" "$2" ;;
  esac
}

# --- install binary -----------------------------------------------------------
mkdir -p "$BIN_DIR" "$ETC_DIR" "$TLS_DIR"
chmod 700 "$TLS_DIR"
ARCHIVE="geneza-relay-${OS}-${ARCH}"
if [ -n "$BASE_URL" ]; then
  URL="$BASE_URL/$ARCHIVE"
elif [ -n "$VERSION" ]; then
  URL="https://github.com/$REPO/releases/download/v$VERSION/$ARCHIVE"
else
  URL="https://github.com/$REPO/releases/latest/download/$ARCHIVE"
fi
echo "downloading $ARCHIVE ..."
curl -fsSL "$URL" -o "$BIN_DIR/geneza-relay" \
  || die "download failed from $URL (set GENEZA_BASE_URL to your archive host)"
chmod 755 "$BIN_DIR/geneza-relay"

# --- TLS material -------------------------------------------------------------
fetch "$CERT_SRC" "$TLS_DIR/relay.crt"
fetch "$KEY_SRC"  "$TLS_DIR/relay.key"
fetch "$CA_SRC"   "$TLS_DIR/ca-roots.pem"
chmod 600 "$TLS_DIR/relay.key"

# --- base config --------------------------------------------------------------
CONFIG="$ETC_DIR/relay.yaml"
{
  echo "listen: \"$LISTEN\""
  echo "relay_id: \"$RELAY_ID\""
  echo "region: \"$REGION\""
  echo "registrar_addr: \"$CONTROLLER\""
  echo "cert_file: \"$TLS_DIR/relay.crt\""
  echo "key_file: \"$TLS_DIR/relay.key\""
  echo "controller_ca_file: \"$TLS_DIR/ca-roots.pem\""
  if [ "$FUNNEL" = 1 ]; then
    echo "funnel_listen: \"$FUNNEL_LISTEN\""
  fi
} > "$CONFIG"

# --- funnel public IP: OPERATOR CONFIRMATION ----------------------------------
if [ "$FUNNEL" = 1 ]; then
  if [ -n "$PUBLIC_IP" ]; then
    "$BIN_DIR/geneza-relay" detect-public-ip --config "$CONFIG" --public-ip "$PUBLIC_IP"
  else
    echo
    echo "This relay will serve FUNNEL (public TLS). Confirm its public IP:"
    "$BIN_DIR/geneza-relay" detect-public-ip --config "$CONFIG" ${PUBLIC_SERVICE:+--public-service "$PUBLIC_SERVICE"} </dev/tty
  fi
fi

# --- systemd ------------------------------------------------------------------
cat > "$UNIT" <<EOF
[Unit]
Description=Geneza rendezvous relay
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN_DIR/geneza-relay --config $CONFIG
Restart=always
RestartSec=2
# A public ingress: drop privileges + harden.
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths=$ETC_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
if [ "$NO_START" = 0 ]; then
  systemctl enable --now geneza-relay.service
  echo "geneza-relay installed and started ($CONFIG)"
else
  systemctl enable geneza-relay.service
  echo "geneza-relay installed ($CONFIG); start with: systemctl start geneza-relay"
fi
