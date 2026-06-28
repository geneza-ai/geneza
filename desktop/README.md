# Geneza desktop client (Wails v2)

A cross-platform desktop app (macOS / Windows / Linux) that renders the existing
React console (`../web/apps/console`) in the OS-native webview and binds a Go service that
drives the **shared client core in-process**. The headline win: the remote shell
runs the same **direct end-to-end Noise tunnel** as `geneza ssh`
(`client_path=native`, controller out of the data path) instead of the
controller-proxied browser WebSocket — same xterm.js renderer, more native
transport.

## Why a nested module

This is its own Go module (`geneza.io/desktop`, `replace => ../`) so the
Wails + webview + CGO dependencies **never enter the root module**. Headless
servers build only the static CLI/server binaries; a CI check
(`go list -deps ./cmd/...`) fails if a GUI import ever leaks into them. It still
imports the root's `internal/clientcore`, `internal/attachbridge`,
`internal/client` directly (Go's internal rule is import-path based, and the
desktop's path is under `geneza.io/`).

## Layout

- `service.go` — `DesktopService`: `Connect` (shared `~/.geneza` profile),
  `Nodes`, and the native shell (`OpenShell` → `clientcore.OpenSession` →
  `attachbridge`; host output streams to the UI over Wails events, keystrokes/
  resizes come back via bindings).
- `main.go` — the Wails app shell, embeds `frontend/dist`.
- `../web/apps/console/src/desktop/bridge.ts` — routes the React app to the Go bindings when
  `isDesktop()`; `web-shell.tsx` has a desktop branch that feeds xterm.js from
  the native tunnel.

## Develop / build

Prereqs: Go, Node, and (Linux) `libwebkit2gtk-4.1-dev`; the `wails` CLI for the
dev server. Identity is shared with the CLI — `geneza login` once, then the app
connects to that profile.

```bash
# live dev (Vite HMR + Go rebuilds):
wails dev -tags webkit2_41

# production binary (builds web/apps/console, embeds it, compiles native):
./build-desktop.sh
```

macOS `.app`/`.dmg` (Developer ID + notarization) and Windows `.exe`/installer
(Authenticode) are built + signed in CI on platform runners — Wails has no
cross-compile. The bundles attach to the same signed release as the CLI and
reuse `internal/selfupdate` for in-app updates.
