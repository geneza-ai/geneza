#!/usr/bin/env bash
# Build the Geneza desktop client (Wails v2): builds the React console, stages it
# into the embed dir, and produces a native binary. Linux needs the webkit2_41
# tag (webkit2gtk-4.1); macOS/Windows bundles + code-signing run in CI on
# platform runners (Wails has no cross-compile).
#
#   VERSION=v0.1.0 ./build-desktop.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
VERSION="${VERSION:-$(git -C "$repo" describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)}"

echo "==> building the React console (web/apps/console)"
# Install + build from the web/ workspace root: the console depends on the
# workspace-only @geneza/ui package, so npm must link the workspaces first.
( cd "$repo/web" && { npm ci --no-audit --no-fund 2>/dev/null || npm install --no-audit --no-fund; } && npm run build:console )

echo "==> staging frontend into the embed dir"
rm -rf "$here/frontend/dist"
mkdir -p "$here/frontend/dist"
touch "$here/frontend/dist/.gitkeep" # keep the committed placeholder so a clean tree compiles
cp -r "$repo/web/apps/console/dist/." "$here/frontend/dist/"

# Linux uses webkit2gtk-4.1 (Debian 13+/modern distros); drop the tag on 4.0.
tags="webkit2_41"
[ "$(go env GOOS)" != linux ] && tags=""

echo "==> building the desktop binary (version $VERSION, tags='${tags:-none}')"
mkdir -p "$here/build/bin"
( cd "$here" && CGO_ENABLED=1 go build ${tags:+-tags "$tags"} \
    -ldflags "-X geneza.io/internal/version.Version=${VERSION}" \
    -o build/bin/geneza-desktop . )
echo "==> wrote $here/build/bin/geneza-desktop"
