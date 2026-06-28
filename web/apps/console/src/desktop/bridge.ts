// Bridge to the Wails desktop backend (DesktopService). In the browser build the
// Wails globals are absent and isDesktop() is false, so the React console keeps
// talking to the controller over HTTP/WebSocket; in the desktop app these route to
// the in-process Go client core instead — so the remote shell rides the direct
// end-to-end tunnel rather than the controller-proxied WebSocket.

type WailsEventCancel = () => void

interface WailsRuntime {
  EventsOn(event: string, cb: (...data: unknown[]) => void): WailsEventCancel
}

type Bound = Record<string, (...args: unknown[]) => Promise<unknown>>

declare global {
  interface Window {
    runtime?: WailsRuntime
    go?: { main?: { DesktopService?: Bound } }
  }
}

/** True when running inside the Wails desktop app. */
export function isDesktop(): boolean {
  return (
    typeof window !== "undefined" &&
    !!window.runtime &&
    !!window.go?.main?.DesktopService
  )
}

function svc(): Bound {
  const s = window.go?.main?.DesktopService
  if (!s) throw new Error("desktop backend unavailable")
  return s
}

function on(event: string, cb: (...data: unknown[]) => void): WailsEventCancel {
  if (!window.runtime) return () => {}
  return window.runtime.EventsOn(event, cb)
}

export interface DesktopSession {
  controller: string
  user: string
  workspace: string
}

export interface DesktopNode {
  id: string
  name: string
  online: boolean
  os: string
  arch: string
  version: string
  approved: boolean
  labels: Record<string, string>
}

export const desktop = {
  connect: (profile = "default") =>
    svc().Connect(profile) as Promise<DesktopSession>,
  nodes: () => svc().Nodes() as Promise<DesktopNode[]>,

  // --- native shell over the direct tunnel ---
  openShell: (node: string, cols: number, rows: number) =>
    svc().OpenShell(node, cols, rows) as Promise<string>,
  shellInput: (id: string, data: Uint8Array) =>
    svc().ShellInput(id, bytesToB64(data)) as Promise<void>,
  shellResize: (id: string, cols: number, rows: number) =>
    svc().ShellResize(id, cols, rows) as Promise<void>,
  closeShell: (id: string) => svc().CloseShell(id) as Promise<void>,

  onShellOutput: (id: string, cb: (bytes: Uint8Array) => void) =>
    on("shell:out:" + id, (b64) => cb(b64ToBytes(String(b64)))),
  onShellExit: (id: string, cb: (code: number) => void) =>
    on("shell:exit:" + id, (code) => cb(Number(code))),
  onShellClosed: (id: string, cb: () => void) =>
    on("shell:closed:" + id, () => cb()),
}

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function bytesToB64(bytes: Uint8Array): string {
  let bin = ""
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin)
}
