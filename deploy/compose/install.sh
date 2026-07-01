#!/usr/bin/env bash
# Geneza compose installer — stand up (or upgrade) a Geneza node with one command.
#
#   curl -fsSL https://raw.githubusercontent.com/geneza-ai/geneza/main/deploy/compose/install.sh \
#     | sudo bash
#
# It asks what to install, renders a docker-compose.yml + configs under
# /opt/geneza, and brings the stack up. Three roles:
#
#   controller         control plane only:  controller + postgres + victoriametrics + caddy
#   controller+relay   the above, plus a colocated rendezvous relay (single-host default)
#   relay           just a relay that auto-registers to a remote controller
#
# Re-running it is an UPGRADE: it pulls newer images, re-renders from your saved
# answers, and `docker compose up -d`. Secrets and the CA are generated once and
# reused, so re-runs never disturb a live fleet. Drive it interactively, or pass
# every answer as a flag for an unattended install (see --help).
set -euo pipefail

# --- defaults -----------------------------------------------------------------
DIR="${GENEZA_DIR:-/opt/geneza}"        # install root (rendered files + data live here)
ROLE=""                                  # controller | controller+relay | relay
SITE=""                                  # public FQDN for the browser TLS front (Caddy)
PUBLIC_IP=""                             # public IP agents/clients reach this host on
ADMIN_PASSWORD=""                        # break-glass admin login (blank => generated)
ACME_EMAIL=""                            # optional Let's Encrypt contact for Caddy
POSTGRES_DSN=""                          # external Postgres DSN (HA): omits the bundled postgres
METRICS_URL=""                           # external VictoriaMetrics (HA): omits the bundled one
CONTROLLER_ID=""                            # stable per-controller id (REQUIRED, unique, in HA)
IMAGE_TAG="${GENEZA_IMAGE_TAG:-latest}"  # image tag for controller/relay
AGENT_TAG="${GENEZA_AGENT_TAG:-}"        # signed geneza-node release the controller serves (empty = latest)
VULN_FEED="${GENEZA_VULN_FEED:-osv_bulk}" # CVE feed: osv_bulk (open OSV.dev) | osv_dir | geneza-paid | "" off
REGISTRY="${GENEZA_REGISTRY:-ghcr.io/geneza-ai}"
# relay-only:
RELAY_ID=""                              # relay identity; MUST match issue-relay-cert --name (default: derived from the cert)
CONTROLLER_ADDR=""                          # the controller's relay registrar (host:7401)
RELAY_CERT=""; RELAY_KEY=""; RELAY_CA="" # relay mTLS bundle (issue-relay-cert on the controller)
RELAY_SECRET_IN=""                       # controller's relay_shared_secret (enables the TURN floor)
ASSUME_YES=0
NO_START=0
RENDER_ONLY="${GENEZA_RENDER_ONLY:-0}"   # render files but never touch docker (for testing)
DO_UNINSTALL=0
GENERATED_PW=0                            # set when we mint a random admin password (must be shown once)

NONROOT_UID=65532 # distroless nonroot — owns the controller/relay data dirs

die() { echo "install: $*" >&2; exit 1; }
log() { echo "==> $*"; }
randhex() { head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
randpw()  { head -c24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c24; }

# detect_public_ip suggests the host's public IP for the prompt default: a public
# echo service first, falling back to the default-route source address. Just a
# prefilled suggestion — the operator presses Enter to accept it or types another.
detect_public_ip() {
  local ip=""
  ip="$(curl -fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)"
  case "$ip" in ""|*[!0-9.]*) ip="" ;; esac
  [ -n "$ip" ] || ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  printf '%s' "$ip"
}

# write_env persists the single source of truth ($DIR/.env): every var docker compose
# interpolates plus every answer an upgrade re-run must reproduce. Mode 600 — it holds
# the postgres password, relay secret, and admin hash.
write_env() {
  ( umask 077
    {
      echo "# Geneza install state: secrets + answers + admin hash (chmod 600)."
      echo "# docker compose reads this for \${...} interpolation; the installer"
      echo "# re-sources it on every upgrade. A flag to install.sh overrides it."
      # Single-quote every value: the bcrypt hash contains '$' (and a DSN might),
      # which both `. .env` (bash) and docker compose's .env interpolation would
      # otherwise expand/mangle. Single quotes are literal to both.
      for _k in ROLE SITE PUBLIC_IP ACME_EMAIL POSTGRES_DSN METRICS_URL CONTROLLER_ID \
                IMAGE_TAG AGENT_TAG VULN_FEED CONTROLLER_ADDR RELAY_SECRET POSTGRES_PASSWORD ADMIN_BCRYPT; do
        printf "%s='%s'\n" "$_k" "${!_k:-}"
      done
    } > "$ENVFILE"
  )
}

usage() {
  cat >&2 <<'EOF'
usage: install.sh [--role controller|controller+relay|relay] [options]

  common:
    --role ROLE           controller | controller+relay | relay
    --dir PATH            install root (default: /opt/geneza)
    --image-tag TAG       controller/relay image tag (default: latest)
    --agent-tag TAG       signed geneza-node release the controller serves (default: latest)
    --yes                 accept defaults, never prompt (unattended)
    --no-start            render + bootstrap but do not 'up -d'
    --uninstall           stop the stack and remove the systemd-managed services
    -h, --help

  controller / controller+relay:
    --site FQDN           public hostname for the browser TLS front (Caddy + ACME)
    --public-ip IP        public IP agents/clients reach this host on
    --admin-password PW   break-glass admin password (default: generated, printed once)
    --acme-email EMAIL    Let's Encrypt contact address (optional)
    --postgres-dsn DSN    use an EXTERNAL Postgres (HA) instead of the bundled one
    --metrics-url URL     use an EXTERNAL VictoriaMetrics (HA) instead of the bundled one
    --controller-id ID       stable, globally-unique controller id (REQUIRED in HA)

  relay:
    --controller HOST:PORT   the controller's relay registrar (required for role=relay)
    --relay-id ID         relay identity (default: derived from the cert; MUST equal
                          the issue-relay-cert --name the controller signed)
    --cert PATH|URL       relay TLS cert   (geneza-controller issue-relay-cert)
    --key  PATH|URL       relay TLS key
    --ca   PATH|URL       CA roots that verify the controller
    --shared-secret SEC   the controller's relay_shared_secret (enables the TURN floor)
    --public-ip IP        this relay's public IP (TURN allocations / funnel)
EOF
}

# --- arg parse ----------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --role)           ROLE="${2:-}"; shift 2 ;;
    --dir)            DIR="${2:-}"; shift 2 ;;
    --site)           SITE="${2:-}"; shift 2 ;;
    --public-ip)      PUBLIC_IP="${2:-}"; shift 2 ;;
    --admin-password) ADMIN_PASSWORD="${2:-}"; shift 2 ;;
    --acme-email)     ACME_EMAIL="${2:-}"; shift 2 ;;
    --postgres-dsn)   POSTGRES_DSN="${2:-}"; shift 2 ;;
    --metrics-url)    METRICS_URL="${2:-}"; shift 2 ;;
    --controller-id)     CONTROLLER_ID="${2:-}"; shift 2 ;;
    --image-tag)      IMAGE_TAG="${2:-}"; shift 2 ;;
    --agent-tag)      AGENT_TAG="${2:-}"; shift 2 ;;
    --controller)        CONTROLLER_ADDR="${2:-}"; shift 2 ;;
    --relay-id)       RELAY_ID="${2:-}"; shift 2 ;;
    --cert)           RELAY_CERT="${2:-}"; shift 2 ;;
    --key)            RELAY_KEY="${2:-}"; shift 2 ;;
    --ca)             RELAY_CA="${2:-}"; shift 2 ;;
    --shared-secret)  RELAY_SECRET_IN="${2:-}"; shift 2 ;;
    --yes|-y)         ASSUME_YES=1; shift ;;
    --no-start)       NO_START=1; shift ;;
    --uninstall)      DO_UNINSTALL=1; shift ;;
    -h|--help)        usage; exit 0 ;;
    *)                usage; die "unknown option: $1" ;;
  esac
done

GW_IMAGE="$REGISTRY/geneza-controller:$IMAGE_TAG"
RELAY_IMAGE="$REGISTRY/geneza-relay:$IMAGE_TAG"

# A prompt that reads from the terminal even when the script is piped from curl.
ask() { # ask VAR "question" "default"
  local __var="$1" __q="$2" __def="${3:-}" __ans=""
  if [ "$ASSUME_YES" = 1 ] || [ ! -r /dev/tty ]; then printf -v "$__var" '%s' "$__def"; return; fi
  if [ -n "$__def" ]; then read -r -p "$__q [$__def]: " __ans </dev/tty || true
  else read -r -p "$__q: " __ans </dev/tty || true; fi
  printf -v "$__var" '%s' "${__ans:-$__def}"
}

# --- preflight ----------------------------------------------------------------
if [ "$RENDER_ONLY" != 1 ]; then
  [ "$(id -u)" = 0 ] || die "run as root (it owns $DIR and chowns the data dirs)"
  command -v docker >/dev/null 2>&1 || die "docker is required"
  if docker compose version >/dev/null 2>&1; then DC=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then DC=(docker-compose)
  else die "docker compose (v2) or docker-compose is required"; fi
else
  DC=(true) # render-only: stub the compose calls
fi

# --- uninstall ----------------------------------------------------------------
if [ "$DO_UNINSTALL" = 1 ]; then
  [ -f "$DIR/docker-compose.yml" ] || die "no install found at $DIR"
  ( cd "$DIR" && "${DC[@]}" down ) || true
  echo "stack stopped. data left under $DIR (delete it by hand to purge)."
  exit 0
fi

# --- load saved state (single source of truth) -------------------------------
# Generated secrets + every saved answer live in ONE file, $DIR/.env. Source it
# FIRST so an upgrade reuses the full topology (role, hostname, public IP, …) and
# the prompts below are driven purely by what is still unknown — never by a separate
# marker that can disagree (e.g. a leftover docker-compose.yml without a .env, which
# used to skip the hostname/IP prompts while still asking the role). A flag passed
# this run wins; docker compose also auto-loads .env for ${...} interpolation.
mkdir -p "$DIR" "$DIR/config" "$DIR/data"
ENVFILE="$DIR/.env"
# Precedence: a flag passed THIS run > saved .env > default. These answers all default
# to empty, so a non-empty value here means a flag explicitly set it. Stash them, source
# .env for everything else, then re-apply — so a re-run can CHANGE role/hostname/IP/…
# (e.g. add a relay), not merely reproduce the saved topology.
_ANSWERS="ROLE SITE PUBLIC_IP ACME_EMAIL POSTGRES_DSN METRICS_URL CONTROLLER_ID CONTROLLER_ADDR RELAY_ID RELAY_SECRET_IN"
for _v in $_ANSWERS; do eval "_flag_$_v=\${$_v}"; done
# shellcheck source=/dev/null
[ -f "$ENVFILE" ] && . "$ENVFILE"
for _v in $_ANSWERS; do eval "if [ -n \"\${_flag_$_v}\" ]; then $_v=\${_flag_$_v}; fi"; done
: "${RELAY_SECRET:=$(randhex)}"
: "${POSTGRES_PASSWORD:=$(randpw)}"
: "${ADMIN_BCRYPT:=}"
UPGRADE=0; [ -f "$ENVFILE" ] && UPGRADE=1

# --- pick a role --------------------------------------------------------------
if [ -z "$ROLE" ] && [ -f "$DIR/role" ]; then ROLE="$(cat "$DIR/role")"; fi  # legacy marker fallback
if [ -z "$ROLE" ]; then
  cat <<'EOF'

What do you want to run on this host?
  1) controller+relay   control plane + a colocated relay   (single-host default)
  2) controller         control plane only (add relays elsewhere)
  3) relay           a relay that joins a remote controller
EOF
  _r=""; ask _r "Choose 1-3" "1"
  case "$_r" in 1) ROLE="controller+relay" ;; 2) ROLE="controller" ;; 3) ROLE="relay" ;; *) die "invalid choice: $_r" ;; esac
fi
case "$ROLE" in controller|controller+relay|relay) ;; *) die "invalid --role: $ROLE" ;; esac
IS_CONTROLLER=0; IS_RELAY=0
case "$ROLE" in controller) IS_CONTROLLER=1 ;; controller+relay) IS_CONTROLLER=1; IS_RELAY=1 ;; relay) IS_RELAY=1 ;; esac
echo "$ROLE" > "$DIR/role"

###############################################################################
# CONTROLLER  (controller / controller+relay)
###############################################################################
if [ "$IS_CONTROLLER" = 1 ]; then
  if [ "$UPGRADE" = 0 ]; then
    [ -n "$SITE" ]      || ask SITE "Public hostname for the console (blank = self-signed TLS)" ""
    # Offer the detected public IP as the default (Enter accepts it); type another to
    # override, or 127.0.0.1 for a localhost lab.
    [ -n "$PUBLIC_IP" ] || ask PUBLIC_IP "Public IP agents/clients reach this host on" "$(detect_public_ip)"
    if [ -z "$ACME_EMAIL" ] && [ -n "$SITE" ]; then ask ACME_EMAIL "Let's Encrypt contact email (optional)" ""; fi
  fi
  [ -n "$PUBLIC_IP" ] || PUBLIC_IP="127.0.0.1"
  # advertise + relay endpoints: localhost always works on-host; add the public face when given.
  ADV_DNS="[localhost]"; [ -n "$SITE" ] && ADV_DNS="[localhost, $SITE]"
  ADV_IPS="[127.0.0.1]"; [ "$PUBLIC_IP" != "127.0.0.1" ] && ADV_IPS="[127.0.0.1, $PUBLIC_IP]"
  # The relay's advertised address MUST be routable, never loopback: the controller's
  # own session-host runs in a container where 127.0.0.1 is ITS loopback, not the relay
  # — so a tunnel to 127.0.0.1:7403 is refused. A container reaches a routable host IP
  # by hairpin, so advertise a real IP (fall back to the detected one if PUBLIC_IP is
  # loopback), and warn hard if a colocated relay has none.
  RELAY_IP="$PUBLIC_IP"
  case "$RELAY_IP" in ""|127.*|localhost) RELAY_IP="$(detect_public_ip)" ;; esac
  case "$RELAY_IP" in ""|127.*) RELAY_IP="" ;; esac
  if [ "$IS_RELAY" = 1 ] && [ -z "$RELAY_IP" ]; then
    log "WARNING: no routable IP for the colocated relay. Shell/forward tunnels will fail"
    log "         (the containerized controller can't reach a 127.0.0.1:7403 relay)."
    log "         Re-run with:  --public-ip <this host's routable IP>"
    RELAY_IP="$PUBLIC_IP"
  fi
  [ -n "$RELAY_IP" ] || RELAY_IP="$PUBLIC_IP"
  # The colocated relay's TLS server cert is issued from the controller's advertise IPs,
  # so it MUST cover the routable address clients dial the relay at — otherwise the tunnel
  # fails cert verification (SAN mismatch) even once relay_addrs is routable.
  if [ -n "$RELAY_IP" ] && [ "$RELAY_IP" != "127.0.0.1" ] && ! printf '%s' "$ADV_IPS" | grep -qF "$RELAY_IP"; then
    ADV_IPS="${ADV_IPS%]}, ${RELAY_IP}]"
  fi
  # Caddy needs a HOST NAME to terminate TLS — a port-only ":443" block with
  # `tls internal` cannot issue a cert and fails every handshake. With an FQDN, use
  # it (ACME or internal); without one (lab), serve internal TLS for localhost (+ the
  # public IP if given) so https://localhost works.
  if [ -n "$SITE" ]; then
    CADDY_SITE="$SITE"
  else
    CADDY_SITE="localhost"
    [ -n "$PUBLIC_IP" ] && [ "$PUBLIC_IP" != "127.0.0.1" ] && CADDY_SITE="localhost ${PUBLIC_IP}"
  fi
  # Public origin the browser console is reached on (cookie + OIDC redirect origin).
  CONSOLE_URL="https://localhost"
  [ "$PUBLIC_IP" != "127.0.0.1" ] && CONSOLE_URL="https://${PUBLIC_IP}"
  [ -n "$SITE" ] && CONSOLE_URL="https://${SITE}"

  # Backends: bundle Postgres + VictoriaMetrics by default; in HA point at shared
  # external ones (--postgres-dsn / --metrics-url) and skip the bundled services.
  BUNDLE_PG=1; STORE_DSN="postgres://geneza:${POSTGRES_PASSWORD}@postgres:5432/geneza?sslmode=disable"
  if [ -n "$POSTGRES_DSN" ]; then BUNDLE_PG=0; STORE_DSN="$POSTGRES_DSN"; fi
  BUNDLE_VM=1; METRICS="http://victoriametrics:8428"
  if [ -n "$METRICS_URL" ]; then BUNDLE_VM=0; METRICS="$METRICS_URL"; fi

  log "rendering controller config"
  cat > "$DIR/config/controller.yaml" <<EOF
# Geneza controller — rendered by deploy/compose/install.sh. Edit and re-run the
# installer (it re-renders from your saved answers) or edit here and 'up -d'.
data_dir: /var/lib/geneza/controller
grpc_listen: ":7401"
http_listen: ":7402"
cluster_name: geneza

# Browser console SPA, served from the build baked into the controller image; Caddy
# terminates TLS and fronts it. external_url is the public origin (cookie + OIDC
# redirect). The cluster-operator console ships in the image too (static_dir
# /var/lib/geneza/cluster-web) — enable it with a cluster_console: block.
console:
  listen: ":7406"
  static_dir: /var/lib/geneza/console-web
  external_url: "${CONSOLE_URL}"

# Persistence: Postgres. The controller stores signed records under SERIALIZABLE
# invariants; it keeps no time-series itself.
store: postgres
store_dsn: "${STORE_DSN}"
$( [ -n "$CONTROLLER_ID" ] && echo "controller_id: ${CONTROLLER_ID}" )

# SANs stamped into the controller + relay server certs. localhost/127.0.0.1 are
# always included; your public face is added so remote agents/clients verify.
advertise:
  dns_names: ${ADV_DNS}
  ips: ${ADV_IPS}

# Where grants tell clients/agents to reach the relay.
relay_addrs: ["${RELAY_IP}:7403"]
relay_data_addrs: ["${RELAY_IP}:7404"]
relay_realm: geneza
relay_shared_secret: ${RELAY_SECRET}

policy_file: /etc/geneza/policy.yaml
metrics_url: "${METRICS}"

# curl|bash agent install: the controller serves the root signing key it already
# carries (compiled into the binary) at /v1/root-pubkey, and install_dir holds the
# stage-1 binaries. agent_release keeps install_dir populated with the SIGNED
# geneza-node release pulled from GitHub (tag empty = latest; needs GitHub egress).
# 'geneza node enroll' then prints a verifiable one-liner. (Air-gapped / no release?
# Remove agent_release; enroll still mints the token to install the agent another way.
# Pin your OWN root instead of the built-in by setting root_pubkey_file.)
install_dir: /var/lib/geneza/install
agent_release:
  pull: true
  tag: "${AGENT_TAG}"

# CVE affectedness: match the fleet's SBOMs against a vulnerability feed. Default is
# the OPEN OSV feed (osv_bulk pulls OSV.dev distro + language advisories — Debian,
# Ubuntu, Alpine, Red Hat, npm, PyPI, … — needs egress), enriched with CISA KEV +
# FIRST EPSS. First sync runs in the background; verdicts appear within minutes.
# Disable with GENEZA_VULN_FEED= ; use source: geneza-paid for the commercial feed.
$( [ -n "$VULN_FEED" ] && printf 'vuln_feed:\n  source: %s\n  kev_url: default\n  epss_url: default' "$VULN_FEED" )

cert_ttl:
  node: 24h
  user: 8h
grant_ttl: 2m
default_max_session_ttl: 12h

# Break-glass local admin lives in its OWN file (written once, never re-rendered),
# so re-running the installer can't clobber a changed password or extra users. Edit
# /opt/geneza/config/local_users.yml to manage them. Federate human login by adding
# an oidc:/clouds: block (see docs).
local_users_file: /etc/geneza/local_users.yml

agent_policy:
  forbid_detach: false
  max_sessions: 64
  max_detached: 16
  ring_buffer_bytes: 262144
  detached_ttl_sec: 86400
  idle_reap_sec: 0
EOF

  cat > "$DIR/config/policy.yaml" <<'EOF'
# Minimal starting policy (policy-as-data): the geneza-admins group + the local
# admin user get ws-admin — every action on this workspace's nodes. `roles` is a
# MAP of role -> allow rules; `bindings` maps users/groups onto a role. The reserved
# cluster role `admin` is break-glass-cert only and cannot be bound here. Grow this
# into per-workspace RBAC/ABAC; see docs/ for the full model.
roles:
  ws-admin:
    allow:
      - actions: ["*"]
        node_labels: {"*": "*"}
        record: true
bindings:
  - role: ws-admin
    users: [admin]
    groups: [geneza-admins]
EOF

  cat > "$DIR/config/Caddyfile" <<EOF
# Public, browser-trusted TLS for the console + the public HTTPS endpoints. Caddy
# terminates the real cert and reverse-proxies to the controller: the browser console
# SPA on the plain-HTTP console listener (:7406), and the enroll/update/vendordata/
# installer endpoints on the controller's own HTTPS API (:7402, an internal hop whose
# cert is not verified here).
${CADDY_SITE} {
$( [ -n "$SITE" ] && [ -n "$ACME_EMAIL" ] && echo "    tls ${ACME_EMAIL}" )
$( [ -z "$SITE" ] && echo "    tls internal" )

    # Agent enrollment + updates, RFC 8628 device login is brokered by the console,
    # the OpenStack vendordata callback, and the one-line agent installer.
    @api path /openstack/* /v1/* /install.sh
    handle @api {
        reverse_proxy https://controller:7402 {
            transport http {
                tls_insecure_skip_verify
            }
        }
    }

    # The browser console SPA and its /api/v1.
    handle {
        reverse_proxy http://controller:7406
    }
}
EOF
fi

###############################################################################
# RELAY  (relay-only)
###############################################################################
if [ "$IS_RELAY" = 1 ] && [ "$IS_CONTROLLER" = 0 ]; then
  if [ "$UPGRADE" = 0 ]; then
    [ -n "$CONTROLLER_ADDR" ] || ask CONTROLLER_ADDR "Controller registrar address (host:7401)" ""
    [ -n "$CONTROLLER_ADDR" ] || die "role=relay needs --controller HOST:PORT"
    [ -n "$RELAY_CERT" ] || ask RELAY_CERT "Relay TLS cert path/URL (issue-relay-cert)" ""
    [ -n "$RELAY_KEY" ]  || ask RELAY_KEY  "Relay TLS key path/URL" ""
    [ -n "$RELAY_CA" ]   || ask RELAY_CA   "CA roots path/URL (verifies the controller)" ""
    [ -n "$PUBLIC_IP" ]  || ask PUBLIC_IP  "This relay's public IP (TURN/funnel)" ""
    [ -n "$RELAY_SECRET_IN" ] || ask RELAY_SECRET_IN "Controller relay_shared_secret (blank = no TURN floor)" ""
  fi
  # Fetch the operator-provided mTLS bundle NOW (before rendering relay.yaml), so
  # relay_id can be derived from the cert.
  if [ "$RENDER_ONLY" != 1 ]; then
    mkdir -p "$DIR/data/relay/tls"
    fetch() { case "$1" in http://*|https://*) curl -fsSL "$1" -o "$2" ;; *) cp "$1" "$2" ;; esac; }
    [ -n "$RELAY_CERT" ] && fetch "$RELAY_CERT" "$DIR/data/relay/tls/relay.crt"
    [ -n "$RELAY_KEY" ]  && fetch "$RELAY_KEY"  "$DIR/data/relay/tls/relay.key"
    [ -n "$RELAY_CA" ]   && fetch "$RELAY_CA"   "$DIR/data/relay/tls/ca-roots.pem"
    [ -f "$DIR/data/relay/tls/relay.crt" ] || die "relay needs a cert (run 'geneza-controller issue-relay-cert' on the controller)"
    chmod 600 "$DIR/data/relay/tls/relay.key" 2>/dev/null || true
  fi
  # The controller binds the registered relay_id to the cert's NAME, so they MUST
  # match. Default relay_id to the cert's own identity (geneza-controller
  # issue-relay-cert --name <X> -> CN "relay:<X>"), so it just works; --relay-id and
  # then the hostname are the fallbacks.
  if [ -z "$RELAY_ID" ] && [ -f "$DIR/data/relay/tls/relay.crt" ] && command -v openssl >/dev/null 2>&1; then
    RELAY_ID="$(openssl x509 -in "$DIR/data/relay/tls/relay.crt" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *relay:\([^,/]*\).*/\1/p')"
  fi
  [ -n "$RELAY_ID" ] || RELAY_ID="$(hostname -s 2>/dev/null || hostname)"
fi

###############################################################################
# RELAY config + cert material (controller+relay OR relay-only)
###############################################################################
if [ "$IS_RELAY" = 1 ]; then
  RELAY_PUBLIC_IP="${PUBLIC_IP:-127.0.0.1}"
  if [ "$IS_CONTROLLER" = 1 ]; then
    # colocated: same secret as the controller; cert is issued locally at bootstrap.
    RELAY_TURN_SECRET="$RELAY_SECRET"
    REGISTRAR_LINES="" # colocated relay needs no registrar; the controller maps it directly
  else
    RELAY_TURN_SECRET="$RELAY_SECRET_IN"
    REGISTRAR_LINES=$(cat <<EOF
# Auto-join: self-register to the controller so it lands in the signed fleet map
# with no manual map edits, and fail over across controllers on its own.
relay_id: "${RELAY_ID}"
registrar_addr: "${CONTROLLER_ADDR}"
controller_ca_file: /var/lib/geneza/relay/tls/ca-roots.pem
EOF
)
  fi

  log "rendering relay config"
  {
    cat <<EOF
# Geneza relay — rendered by deploy/compose/install.sh. Stateless and
# payload-blind: it splices ciphertext and holds no keys or session state.
listen: ":7403"
tls: true
cert_file: /var/lib/geneza/relay/tls/relay.crt
key_file: /var/lib/geneza/relay/tls/relay.key
match_ttl: 60s
idle_timeout: 10m
max_pending: 1024

realm: geneza
region: default
public_ip: ${RELAY_PUBLIC_IP}
EOF
    [ -n "$RELAY_TURN_SECRET" ] && echo "shared_secret: ${RELAY_TURN_SECRET}"
    [ -n "$REGISTRAR_LINES" ] && echo "$REGISTRAR_LINES"
  } > "$DIR/config/relay.yaml"
fi

###############################################################################
# Render docker-compose.yml for the chosen role
###############################################################################
log "rendering docker-compose.yml ($ROLE)"
{
  echo "# Geneza — rendered by deploy/compose/install.sh (role: $ROLE). Re-run the"
  echo "# installer to upgrade; it pulls newer images and re-renders from .env."
  echo "name: geneza"
  echo
  echo "services:"

  if [ "$IS_CONTROLLER" = 1 ]; then
    if [ "$BUNDLE_PG" = 1 ]; then
      cat <<EOF
  postgres:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: geneza
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD}
      POSTGRES_DB: geneza
    volumes:
      - ./data/postgres:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U geneza"]
      interval: 5s
      timeout: 3s
      retries: 10

EOF
    fi
    if [ "$BUNDLE_VM" = 1 ]; then
      cat <<EOF
  victoriametrics:
    image: victoriametrics/victoria-metrics:v1.145.0
    restart: unless-stopped
    command: ["--storageDataPath=/victoria-metrics-data", "--retentionPeriod=3"]
    ports:
      - "127.0.0.1:8428:8428" # loopback only — for a local Grafana, never world-exposed
    volumes:
      - ./data/victoriametrics:/victoria-metrics-data

EOF
    fi
    # depends_on only the backends we actually bundle
    DEPENDS=""
    [ "$BUNDLE_PG" = 1 ] && DEPENDS="${DEPENDS}      postgres: { condition: service_healthy }"$'\n'
    [ "$BUNDLE_VM" = 1 ] && DEPENDS="${DEPENDS}      victoriametrics: { condition: service_started }"$'\n'
    cat <<EOF
  controller:
    image: ${GW_IMAGE}
    restart: unless-stopped
    user: "${NONROOT_UID}:${NONROOT_UID}"
    command: ["serve", "--config", "/etc/geneza/controller.yaml"]
$( [ -n "$DEPENDS" ] && printf '    depends_on:\n%s' "$DEPENDS" )
    ports:
      - "7401:7401" # mTLS gRPC: enroll, node control, user/admin API
      - "7402:7402" # HTTPS: ca-roots, updates, console, device login
    volumes:
      - ./generated/controller.yaml:/etc/geneza/controller.yaml:ro
      - ./generated/local_users.yml:/etc/geneza/local_users.yml:ro
      - ./config/policy.yaml:/etc/geneza/policy.yaml:ro
      - ./data/controller:/var/lib/geneza/controller

  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    depends_on: [controller]
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./config/Caddyfile:/etc/caddy/Caddyfile:ro
      - ./data/caddy:/data
EOF
  fi

  if [ "$IS_RELAY" = 1 ]; then
    if [ "$IS_CONTROLLER" = 1 ]; then DEP="    depends_on: [controller]"; else DEP=""; fi
    cat <<EOF
  relay:
    image: ${RELAY_IMAGE}
    restart: unless-stopped
    user: "${NONROOT_UID}:${NONROOT_UID}"
    command: ["--config", "/etc/geneza/relay.yaml"]
$DEP
    ports:
      - "7403:7403"     # TCP rendezvous floor
      - "7404:7404/udp" # STUN/TURN data
    volumes:
      - ./config/relay.yaml:/etc/geneza/relay.yaml:ro
      - ./data/relay/tls:/var/lib/geneza/relay/tls:ro
EOF
  fi
} > "$DIR/docker-compose.yml"

# Persist the single source of truth now that every answer is resolved, so the
# first `docker compose` call below interpolates ${POSTGRES_PASSWORD} from it.
write_env

# The rendered config files AND the geneza data dirs are read/written INSIDE the
# containers by the distroless nonroot user, so they must be owned by it. Two
# failure modes this prevents: configs unreadable ("open /etc/geneza/*.yaml:
# permission denied"), and — because docker auto-creates a missing bind-mount source
# as ROOT — the data dirs unwritable ("mkdir /var/lib/geneza/...: permission
# denied"). Pre-create the geneza data dirs so we own them before the first mount;
# postgres and caddy manage their own. Secrets stay in .env (root-only 600).
mkdir -p "$DIR/generated" "$DIR/data/controller" "$DIR/data/relay/tls"
chown -R "$NONROOT_UID:$NONROOT_UID" "$DIR/config" "$DIR/generated" "$DIR/data/controller" "$DIR/data/relay" 2>/dev/null || true
chmod -R u=rwX,go= "$DIR/config" 2>/dev/null || true

if [ "$RENDER_ONLY" = 1 ]; then
  log "render-only: wrote $DIR (docker untouched)"; exit 0
fi

###############################################################################
# Bootstrap the controller (first install only): CA, admin password, admin identity
###############################################################################
if [ "$IS_CONTROLLER" = 1 ]; then
  log "pulling images"
  ( cd "$DIR" && "${DC[@]}" pull -q controller 2>/dev/null ) || true

  if [ "$BUNDLE_PG" = 1 ]; then
    log "starting postgres"
    ( cd "$DIR" && "${DC[@]}" up -d postgres )
    for _ in $(seq 1 30); do
      ( cd "$DIR" && "${DC[@]}" exec -T postgres pg_isready -U geneza >/dev/null 2>&1 ) && break
      sleep 1
    done
  fi

  # The config carries a __ADMIN_BCRYPT__ placeholder. Hash the admin password the
  # first time only; ADMIN_BCRYPT is then persisted in .env and re-sourced on every
  # upgrade, so a re-run never re-hashes or rotates the credential (and the var is
  # always defined — no unbound-variable abort).
  if [ -z "$ADMIN_BCRYPT" ]; then
    if [ -z "$ADMIN_PASSWORD" ]; then ADMIN_PASSWORD="$(randpw)"; GENERATED_PW=1; fi
    log "hashing the admin password"
    ADMIN_BCRYPT="$(printf '%s' "$ADMIN_PASSWORD" | docker run -i --rm "$GW_IMAGE" hash-password)"
    [ -n "$ADMIN_BCRYPT" ] || die "failed to hash admin password"
    write_env
  fi
  # The credential file the controller loads via local_users_file. Written ONCE: a
  # re-run never overwrites it, so a password changed here (or extra users added)
  # survives upgrades. The bcrypt's '$' is why this goes through sed, not a heredoc var.
  if [ ! -f "$DIR/generated/local_users.yml" ]; then
    sed "s|__ADMIN_BCRYPT__|${ADMIN_BCRYPT}|" > "$DIR/generated/local_users.yml" <<'EOF'
# Geneza local users — written once by the installer, NOT re-rendered on upgrade, so
# edits here (change a password, add users) are safe. password_bcrypt is a bcrypt
# hash; mint one with: docker run -i --rm <controller-image> hash-password.
local_users:
  - username: admin
    password_bcrypt: "__ADMIN_BCRYPT__"
    groups: [geneza-admins]
EOF
    chown "$NONROOT_UID:$NONROOT_UID" "$DIR/generated/local_users.yml"
    chmod 600 "$DIR/generated/local_users.yml"
  fi
  sed "s|__ADMIN_BCRYPT__|${ADMIN_BCRYPT}|" "$DIR/config/controller.yaml" > "$DIR/generated/controller.yaml"
  chown "$NONROOT_UID:$NONROOT_UID" "$DIR/generated/controller.yaml"
  chmod u=rw,go= "$DIR/generated/controller.yaml"

  if [ ! -f "$DIR/data/controller/ca/issuing-ca.key" ]; then
    log "initializing the controller CA + keys"
    ( cd "$DIR" && "${DC[@]}" run --rm controller init --config /etc/geneza/controller.yaml )
  else
    # Re-issue the server (controller + relay) TLS leaves from the existing CA so their
    # SANs track the current advertise config — e.g. a changed --public-ip. The CA and
    # every issued node/user cert are untouched; the controller reloads on recreate.
    log "re-issuing server TLS to match the current advertise config"
    ( cd "$DIR" && "${DC[@]}" run --rm controller reissue-tls --config /etc/geneza/controller.yaml ) || true
  fi

  # hand a colocated relay its controller-issued server cert
  if [ "$IS_RELAY" = 1 ] && [ -f "$DIR/data/controller/tls/relay.crt" ]; then
    mkdir -p "$DIR/data/relay/tls"
    cp "$DIR/data/controller/tls/relay.crt" "$DIR/data/relay/tls/relay.crt"
    cp "$DIR/data/controller/tls/relay.key" "$DIR/data/relay/tls/relay.key"
    chown -R "$NONROOT_UID:$NONROOT_UID" "$DIR/data/relay/tls"
    chmod 600 "$DIR/data/relay/tls/relay.key"
  fi

  if [ ! -f "$DIR/generated/admin/user.crt" ]; then
    log "issuing a break-glass admin identity into $DIR/generated/admin"
    mkdir -p "$DIR/generated/admin"
    # own it as the container user BEFORE the run, so issue-user-cert can write /out.
    chown "$NONROOT_UID:$NONROOT_UID" "$DIR/generated/admin"
    ( cd "$DIR" && "${DC[@]}" run --rm -v "$DIR/generated/admin:/out" controller \
        issue-user-cert --config /etc/geneza/controller.yaml \
        --name admin --roles admin,platform-admin --ttl 168h --out-dir /out )
    cat > "$DIR/generated/admin/profile.json" <<EOF
{ "controller_grpc": "127.0.0.1:7401", "controller_http": "https://127.0.0.1:7402" }
EOF
    chown -R "$NONROOT_UID:$NONROOT_UID" "$DIR/generated/admin"
  fi
fi

###############################################################################
# Bring it up
###############################################################################
if [ "$NO_START" = 1 ]; then
  log "rendered + bootstrapped at $DIR. Start with: (cd $DIR && ${DC[*]} up -d)"
  exit 0
fi
log "starting the stack"
# Force-recreate the Geneza code services (and Caddy) so a re-run ALWAYS adopts a
# freshly pulled image AND the re-rendered config — `up -d` alone skips a recreate
# when only a bind-mounted file changed, and is flaky about a :latest digest bump.
# --no-deps leaves the stateful postgres/victoriametrics running untouched.
RECREATE=""
[ "$IS_CONTROLLER" = 1 ] && RECREATE="controller caddy"
[ "$IS_RELAY" = 1 ] && RECREATE="$RECREATE relay"
( cd "$DIR" \
  && { "${DC[@]}" pull -q 2>/dev/null || true; } \
  && "${DC[@]}" up -d \
  && { [ -z "$RECREATE" ] || "${DC[@]}" up -d --force-recreate --no-deps $RECREATE; } )

echo
log "done ($ROLE) — $DIR"
if [ "$IS_CONTROLLER" = 1 ] && [ "$GENERATED_PW" = 1 ]; then
  cat <<EOF

   admin password:  ${ADMIN_PASSWORD}
   (login user 'admin'; saved nowhere else — copy it now)
EOF
fi
if [ "$IS_CONTROLLER" = 1 ] && { [ "$UPGRADE" = 0 ] || [ "$GENERATED_PW" = 1 ]; }; then
  cat <<EOF

   Drive the fleet:
     export GENEZA_HOME=$DIR/generated
     geneza --profile admin node enroll --ttl 1h     # -> an enrollment code + install one-liner
EOF
  [ -n "$SITE" ] && echo "   Console: https://${SITE}/"
fi
if [ "$ROLE" = "relay" ]; then
  echo "   relay registered to ${CONTROLLER_ADDR}; it will appear in the controller's fleet map."
fi
