import { useEffect, useRef, useState } from "react"
import { Terminal } from "@xterm/xterm"
import { FitAddon } from "@xterm/addon-fit"
import "@xterm/xterm/css/xterm.css"

import { api } from "@/api"
import { desktop, isDesktop } from "@/desktop/bridge"
import { Button } from "@geneza/ui"

type Status = "connecting" | "open" | "closed" | "error"

// WebShell renders an interactive PTY on a node. In the browser it rides the
// controller's WebSocket shell proxy (client_path=web, policy enforced server-side).
// In the desktop app it rides the in-process direct E2E tunnel (client_path=
// native, controller out of the data path) via the Wails bridge — same xterm.js
// renderer, more native transport.
export function WebShell({ nodeId, nodeName }: { nodeId: string; nodeName: string }) {
  const holder = useRef<HTMLDivElement>(null)
  const [status, setStatus] = useState<Status>("connecting")
  const [detail, setDetail] = useState<string>("")
  const [generation, setGeneration] = useState(0) // bump via Reconnect button

  useEffect(() => {
    const el = holder.current
    if (!el) return
    let cancelled = false

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily:
        'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace',
      theme: {
        background: "#0a0a0a",
        foreground: "#e5e5e5",
        cursor: "#e5e5e5",
      },
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(el)
    fit.fit()

    const enc = new TextEncoder()
    const cleanups: Array<() => void> = []
    const exitLine = (code?: number) =>
      term.write(
        `\r\n\x1b[90m[session exited${code ? ` (code ${code})` : ""}]\x1b[0m\r\n`
      )

    if (isDesktop()) {
      // Native transport: drive the in-process direct E2E tunnel via the Wails
      // bridge. Same xterm.js renderer, no controller in the data path.
      let shellId: string | null = null
      void (async () => {
        try {
          const id = await desktop.openShell(nodeId, term.cols, term.rows)
          if (cancelled) {
            void desktop.closeShell(id)
            return
          }
          shellId = id
          setStatus("open")
          setDetail("")
          term.focus()
          cleanups.push(desktop.onShellOutput(id, (bytes) => term.write(bytes)))
          cleanups.push(desktop.onShellExit(id, (code) => exitLine(code)))
          cleanups.push(
            desktop.onShellClosed(id, () => {
              if (!cancelled) setStatus((s) => (s === "error" ? "error" : "closed"))
            })
          )
        } catch (err) {
          if (!cancelled) {
            setStatus("error")
            setDetail(err instanceof Error ? err.message : String(err))
          }
        }
      })()
      const onData = term.onData((d) => {
        if (shellId) void desktop.shellInput(shellId, enc.encode(d))
      })
      const onResize = term.onResize(({ cols, rows }) => {
        if (shellId) void desktop.shellResize(shellId, cols, rows)
      })
      cleanups.push(
        () => onData.dispose(),
        () => onResize.dispose(),
        () => {
          if (shellId) void desktop.closeShell(shellId)
        }
      )
    } else {
      // Browser transport: the controller's WebSocket shell proxy.
      let ws: WebSocket | null = null
      const proto = location.protocol === "https:" ? "wss" : "ws"
      // Mint a one-time, node-scoped WS ticket first (the session token must NOT
      // ride the WS URL — it would leak into access logs/Referer), then open the
      // socket with the ticket.
      void (async () => {
        let ticket: string
        try {
          const r = await api.post<{ ticket: string }>(
            `/nodes/${encodeURIComponent(nodeId)}/shell-ticket`,
            {}
          )
          ticket = r.ticket
        } catch {
          if (!cancelled) setStatus("error")
          return
        }
        if (cancelled) return
        const url =
          `${proto}://${location.host}/api/v1/nodes/${encodeURIComponent(nodeId)}/shell` +
          `?ticket=${encodeURIComponent(ticket)}&cols=${term.cols}&rows=${term.rows}`
        ws = new WebSocket(url)
        ws.binaryType = "arraybuffer"
        setStatus("connecting")
        setDetail("")
        ws.onopen = () => {
          setStatus("open")
          term.focus()
        }
        ws.onmessage = (ev) => {
          if (typeof ev.data === "string") {
            try {
              const msg = JSON.parse(ev.data)
              if (msg.type === "exit") exitLine(msg.code)
              else if (msg.type === "error") {
                setDetail(String(msg.message || "error"))
                term.write(`\r\n\x1b[31m[${msg.message}]\x1b[0m\r\n`)
              }
            } catch {
              /* ignore */
            }
            return
          }
          term.write(new Uint8Array(ev.data as ArrayBuffer))
        }
        ws.onerror = () => setStatus("error")
        ws.onclose = () => {
          if (cancelled) return
          setStatus((s) => (s === "error" ? "error" : "closed"))
        }
      })()
      const onData = term.onData((d) => {
        if (ws && ws.readyState === WebSocket.OPEN) ws.send(enc.encode(d))
      })
      const onResize = term.onResize(({ cols, rows }) => {
        if (ws && ws.readyState === WebSocket.OPEN)
          ws.send(JSON.stringify({ type: "resize", cols, rows }))
      })
      cleanups.push(
        () => onData.dispose(),
        () => onResize.dispose(),
        () => ws?.close()
      )
    }

    const ro = new ResizeObserver(() => {
      try {
        fit.fit()
      } catch {
        /* element detached */
      }
    })
    ro.observe(el)
    cleanups.push(() => ro.disconnect())

    return () => {
      cancelled = true
      cleanups.forEach((c) => c())
      term.dispose()
    }
  }, [nodeId, generation])

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm">
          <span
            className={
              status === "open"
                ? "size-2 rounded-full bg-success"
                : status === "connecting"
                  ? "size-2 animate-pulse rounded-full bg-warning"
                  : "size-2 rounded-full bg-destructive"
            }
          />
          <span className="text-muted-foreground">
            {status === "open"
              ? `Connected to ${nodeName}`
              : status === "connecting"
                ? "Connecting…"
                : status === "error"
                  ? detail || "Connection error"
                  : detail || "Session closed"}
          </span>
        </div>
        {(status === "closed" || status === "error") && (
          <Button
            size="sm"
            variant="outline"
            onClick={() => setGeneration((g) => g + 1)}
          >
            Reconnect
          </Button>
        )}
      </div>
      <div
        ref={holder}
        className="h-[460px] w-full overflow-hidden rounded-md border bg-[#0a0a0a] p-2"
      />
    </div>
  )
}
