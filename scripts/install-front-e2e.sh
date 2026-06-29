#!/usr/bin/env bash
# install-front-e2e.sh — end-to-end proof of the compose install path for a node
# behind a PUBLIC FRONT, the topology that hid three separate bugs (root-keys.json
# vs root.pub, the :7402-not-private curl, and the runtime cert authority).
#
# It stands up a real controller + Caddy front (Caddy's `tls internal` is a DIFFERENT
# CA than the Geneza CA on purpose), then runs the ACTUAL served install.sh inside a
# throwaway container that has fetched it over the front — exercising the same URL
# resolution a real node does. It asserts:
#
#   1. the controller serves a parseable PEM root key at /v1/root-pubkey (embedded),
#   2. `geneza node enroll` bakes the Geneza-CA runtime + gRPC endpoints into the code,
#   3. install.sh FETCHES over the front (a publicly/Caddy-trusted CA) and succeeds,
#   4. the resulting bootstrap.json runtime points at the Geneza-CA :7402 (NOT the front),
#   5. the real bootstrap POLLS that endpoint with NO "unknown authority" TLS error,
#   6. the node registers on the controller.
#
# Repeatable + self-cleaning: re-run any time; it tears its stack down on exit.
#
# Requires: docker (+ compose v2), curl, openssl, base64; the node container needs
# outbound network (apt). Host knobs (env):
#   GENEZA_IMAGE_TAG   controller image to test (default: build :local from this tree)
#   PG_APPARMOR_UNCONFINED=1   add apparmor=unconfined to postgres (hosts whose
#                              AppArmor blocks postgres-in-docker, e.g. this Proxmox box)
#   FRONT_HTTPS_PORT / FRONT_HTTP_PORT / VM_PORT   host ports for the Caddy front + VM
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${WORK:-/tmp/geneza-install-front-e2e}"
GHOME="$WORK/generated"                  # $GENEZA_HOME for the admin CLI (installer issues admin/ here)
RIG="$WORK/rig"                          # scratch (extracted CA, decoded code)
IMAGE_TAG="${GENEZA_IMAGE_TAG:-local}"
IMAGE="ghcr.io/geneza-ai/geneza-controller:${IMAGE_TAG}"
FRONT_HTTPS_PORT="${FRONT_HTTPS_PORT:-18443}"
FRONT_HTTP_PORT="${FRONT_HTTP_PORT:-18080}"
VM_PORT="${VM_PORT:-19429}"
PG_APPARMOR_UNCONFINED="${PG_APPARMOR_UNCONFINED:-0}"
NODE_CTR="geneza-front-e2e-node"

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32mOK\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

cleanup() {
	docker rm -f "$NODE_CTR" >/dev/null 2>&1 || true
	[ -f "$WORK/docker-compose.yml" ] && ( cd "$WORK" && docker compose down -v >/dev/null 2>&1 ) || true
	rm -rf "$WORK"
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || die "docker is required"
command -v curl   >/dev/null 2>&1 || die "curl is required"
command -v openssl>/dev/null 2>&1 || die "openssl is required"

cleanup                                  # start from a clean slate
mkdir -p "$WORK" "$GHOME" "$RIG"

say "build the geneza CLI + controller image ($IMAGE_TAG)"
( cd "$ROOT" && go build -o "$WORK/geneza" ./cmd/geneza ) || die "go build ./cmd/geneza"
GENEZA="$WORK/geneza"
if [ "$IMAGE_TAG" = "local" ]; then
	# Prefer BuildKit (defines $BUILDPLATFORM); fall back to stripping it for the
	# legacy builder on hosts without BuildKit.
	if ! DOCKER_BUILDKIT=1 docker build -q -t "$IMAGE" -f "$ROOT/deploy/docker/Dockerfile.controller" "$ROOT" >/dev/null 2>&1; then
		sed 's/--platform=\$BUILDPLATFORM //' "$ROOT/deploy/docker/Dockerfile.controller" > "$RIG/Dockerfile"
		docker build -q -t "$IMAGE" -f "$RIG/Dockerfile" "$ROOT" >/dev/null || die "docker build controller image"
	fi
	ok "built $IMAGE"
else
	docker pull -q "$IMAGE" >/dev/null || die "pull $IMAGE"
	ok "pulled $IMAGE"
fi

say "deploy controller + Caddy front (site=localhost, Caddy tls internal = its own CA)"
cat > "$WORK/docker-compose.override.yml" <<YAML
services:
  victoriametrics: { ports: !override ["127.0.0.1:${VM_PORT}:8428"] }
  caddy: { ports: !override ["${FRONT_HTTP_PORT}:80","${FRONT_HTTPS_PORT}:443"] }
$( [ "$PG_APPARMOR_UNCONFINED" = 1 ] && printf '  postgres: { security_opt: [apparmor=unconfined] }' )
YAML
GENEZA_DIR="$WORK" bash "$ROOT/deploy/compose/install.sh" --role controller --image-tag "$IMAGE_TAG" \
	--site localhost --public-ip 127.0.0.1 --admin-password testpass123 --yes >/dev/null 2>&1 \
	|| die "installer failed"
( cd "$WORK" && docker compose up -d >/dev/null 2>&1 ) || die "compose up"
for i in $(seq 1 45); do curl -fsSk https://127.0.0.1:7402/v1/ca-roots >/dev/null 2>&1 && break; sleep 2; done
curl -fsSk https://127.0.0.1:7402/v1/ca-roots >/dev/null 2>&1 || die "controller :7402 never came up"
ok "controller + front up"

say "1) /v1/root-pubkey serves a parseable PEM (embedded root key, no root_pubkey_file)"
grep -qE '^[[:space:]]*root_pubkey_file:' "$WORK/generated/controller.yaml" 2>/dev/null \
	&& die "controller.yaml unexpectedly sets root_pubkey_file (should use the embedded key)"
curl -fsSk https://127.0.0.1:7402/v1/root-pubkey | openssl pkey -pubin -noout 2>/dev/null \
	|| die "/v1/root-pubkey is not a parseable PEM public key"
ok "served root key parses as PEM"

say "2) enroll code carries the Geneza-CA runtime + gRPC endpoints"
for i in $(seq 1 40); do curl -fsSk -o /dev/null https://127.0.0.1:7402/v1/install/bin/geneza-bootstrap-linux-amd64 && break; sleep 3; done
CODE=$(GENEZA_HOME="$GHOME" "$GENEZA" --profile admin node enroll --ttl 1h 2>/dev/null | grep -oE 'gzk_[A-Za-z0-9_-]+')
[ -n "$CODE" ] || die "node enroll did not print a gzk_ code (root key not served?)"
DEC=$(printf %s "${CODE#gzk_}" | tr '_-' '/+' | sed 's/$/===/' | base64 -d 2>/dev/null)
echo "  decoded: $DEC"
echo "$DEC" | grep -q "127.0.0.1:7402" || die "enroll code lacks the Geneza-CA runtime endpoint"
echo "$DEC" | grep -q "127.0.0.1:7401" || die "enroll code lacks the gRPC endpoint"
ok "code carries runtime https://127.0.0.1:7402 + grpc 127.0.0.1:7401"

say "3) extract the Caddy front CA (a different authority than the Geneza CA)"
for i in $(seq 1 20); do curl -fsSk "https://localhost:${FRONT_HTTPS_PORT}/" >/dev/null 2>&1 && break; sleep 2; done
CADDY_CID=$( cd "$WORK" && docker compose ps -q caddy )
docker cp "$CADDY_CID:/data/caddy/pki/authorities/local/root.crt" "$RIG/caddy-root.crt" 2>/dev/null
[ -s "$RIG/caddy-root.crt" ] || die "could not extract the Caddy front CA"
ok "front CA extracted"

say "4-6) throwaway node: run the REAL install.sh over the front, then the bootstrap"
LOG="$RIG/node.log"
docker run --name "$NODE_CTR" --network host \
	-e CODE="$CODE" -e PORT="$FRONT_HTTPS_PORT" \
	-v "$RIG/caddy-root.crt:/caddy-root.crt:ro" debian:stable-slim bash -c '
	set -e
	apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq curl ca-certificates >/dev/null 2>&1
	cp /caddy-root.crt /usr/local/share/ca-certificates/caddy-front.crt && update-ca-certificates >/dev/null 2>&1
	echo "### install.sh (fetched over the front https://localhost:$PORT)"
	curl -fsSL "https://localhost:$PORT/install.sh" | sh -s -- "$CODE"
	echo "### bootstrap.json runtime:"; grep controller_http_url /etc/geneza/bootstrap.json
	echo "### bootstrap poll:"
	timeout 14 /opt/geneza/bin/geneza-bootstrap --config /etc/geneza/bootstrap.json 2>&1 \
		| grep -iE "root key|polling|desired|unknown authority" | head -6
' >"$LOG" 2>&1 || true
sed 's/^/  /' "$LOG"

grep -q "enrolled" "$LOG"                       || die "install.sh did not enroll the node"
ok "install.sh fetched over the front + enrolled"
grep -q 'controller_http_url": "https://127.0.0.1:7402"' "$LOG" \
	|| die "bootstrap runtime is NOT the Geneza-CA :7402 (would hit the front)"
ok "bootstrap runtime is the Geneza-CA :7402, not the front"
grep -qi "unknown authority" "$LOG" && die "bootstrap poll hit 'unknown authority' (runtime cert mismatch)"
grep -qiE "polling|desired" "$LOG"              || die "bootstrap never polled the controller"
ok "bootstrap polled the Geneza-CA endpoint with no TLS error"
for i in $(seq 1 10); do GENEZA_HOME="$GHOME" "$GENEZA" --profile admin node pending 2>/dev/null | grep -q . && break; sleep 1; done
GENEZA_HOME="$GHOME" "$GENEZA" --profile admin node ls 2>/dev/null | grep -qiE "awaiting|approved|online|node" \
	|| die "node did not register on the controller"
ok "node registered on the controller"

say "7) re-running the installer preserves local_users.yml (no password clobber)"
LUF="$WORK/generated/local_users.yml"
[ -f "$LUF" ] || die "local_users.yml was not written"
# simulate an operator changing the admin password in the file
sed -i 's#password_bcrypt: ".*"#password_bcrypt: "$2y$10$OPERATORchangedTHISpasswordHASHvaluexxxxxxxxxxxxxxxxxxx"#' "$LUF"
EDITED=$(sha256sum "$LUF" | cut -d' ' -f1)
GENEZA_DIR="$WORK" bash "$ROOT/deploy/compose/install.sh" --role controller --image-tag "$IMAGE_TAG" \
	--site localhost --public-ip 127.0.0.1 --yes >/dev/null 2>&1 || die "installer re-run failed"
[ "$(sha256sum "$LUF" | cut -d' ' -f1)" = "$EDITED" ] \
	|| die "installer re-run CLOBBERED local_users.yml — the bug this change fixes"
# and prove the re-run DID re-render the main config (it's not just skipping everything)
grep -q 'local_users_file: /etc/geneza/local_users.yml' "$WORK/generated/controller.yaml" \
	|| die "controller.yaml lost its local_users_file reference on re-render"
ok "local_users.yml survived the re-run; controller.yaml still references it"

printf '\n\033[1;32mALL CHECKS PASSED\033[0m — node-behind-a-front install works end to end.\n'
