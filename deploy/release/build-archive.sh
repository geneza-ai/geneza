#!/usr/bin/env bash
# Build every Geneza binary that supports $GOOS/$GOARCH and pack them into a
# single per-platform archive under dist/. Used by the release workflow and
# runnable locally for testing the installer and deployment examples:
#
#   GOOS=linux GOARCH=amd64 VERSION=0.0.0-test ./deploy/release/build-archive.sh
#
# The agent is Linux-only (kernel TUN + embedded node_exporter); every other
# binary cross-compiles to all targets. Static (CGO disabled) so the archives
# carry no libc dependency.
set -euo pipefail

GOOS="${GOOS:-$(go env GOOS)}"
GOARCH="${GOARCH:-$(go env GOARCH)}"
VERSION="${VERSION:-0.0.0-dev}"
export CGO_ENABLED=0

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo_root"

# Two published packages (PACKAGE=client|node). The controller and relay ship only
# as container images, and geneza-sign/geneza-trust are operator-built from
# source — so neither is packaged here.
#   client: the geneza tenant CLI + genezactl cluster CLI, every platform
#           (self-updatable, brew-installable).
#   node:   the agent stack (geneza-agent + geneza-bootstrap), Linux only —
#           served by the controller to enrolling machines.
PACKAGE="${PACKAGE:-client}"
case "$PACKAGE" in
  client)
    bins="geneza genezactl"
    pkgbase="geneza"
    ;;
  node)
    [ "$GOOS" = linux ] || { echo "the node package is Linux-only (got $GOOS)" >&2; exit 1; }
    bins="geneza-agent geneza-bootstrap"
    pkgbase="geneza-node"
    ;;
  *)
    echo "unknown PACKAGE=$PACKAGE (want client|node)" >&2; exit 1
    ;;
esac

ext=""
[ "$GOOS" = windows ] && ext=".exe"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
pkgname="${pkgbase}_${GOOS}_${GOARCH}"
pkgdir="$stage/$pkgname"
mkdir -p "$pkgdir"

# Pin the offline release ROOT public key into the binaries (the client
# self-update and controller agent-pull verify releases against it). Injected via
# -ldflags so dev builds (plain `make build`, no root.pub) stay unpinned /
# integrity-only.
ldflags="-s -w -X geneza.io/internal/version.Version=${VERSION}"
root_pub="$repo_root/deploy/release/root.pub"
if [ -f "$root_pub" ]; then
  ldflags="$ldflags -X geneza.io/internal/releasetrust.rootPubB64=$(base64 -w0 "$root_pub")"
  echo "==> pinning release root from deploy/release/root.pub"
elif [ "${ALLOW_UNSIGNED:-0}" = 1 ]; then
  echo "==> WARNING: deploy/release/root.pub missing; building UNSIGNED (ALLOW_UNSIGNED=1)" >&2
else
  echo "deploy/release/root.pub missing; refusing to build an unpinned release" >&2
  echo "(commit the public root, or set ALLOW_UNSIGNED=1 for an explicit dev build)" >&2
  exit 1
fi

echo "==> building $pkgname (version $VERSION)"
for bin in $bins; do
  GOOS="$GOOS" GOARCH="$GOARCH" go build -trimpath \
    -ldflags "$ldflags" \
    -o "$pkgdir/${bin}${ext}" "./cmd/$bin"
  echo "    ${bin}${ext}"
done

# A copyable record of what version these binaries are, for offline archives.
echo "$VERSION" > "$pkgdir/VERSION"

mkdir -p dist
if [ "$GOOS" = windows ]; then
  command -v zip >/dev/null 2>&1 || { echo "zip is required to package windows archives" >&2; exit 1; }
  archive="dist/${pkgname}.zip"
  rm -f "$repo_root/$archive"
  ( cd "$stage" && zip -qr "$repo_root/$archive" "$pkgname" )
else
  archive="dist/${pkgname}.tar.gz"
  tar -czf "$archive" -C "$stage" "$pkgname"
fi

( cd dist && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256" )
echo "==> wrote $archive"
cat "${archive}.sha256"
