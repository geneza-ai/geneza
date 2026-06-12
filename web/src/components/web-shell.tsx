import { useEffect, useRef, useState } from "react"
import { Terminal } from "@xterm/xterm"
import { FitAddon } from "@xterm/addon-fit"
import "@xterm/xterm/css/xterm.css"

import { getToken } from "@/auth"
import { Button } from "@/components/ui/button"

type Status = "connecting" | "open" | "closed" | "error"

// WebShell renders an interactive PTY on a node over the gateway's WebSocket
// shell proxy. Policy is enforced server-side (client_path=web); a denial closes
// the socket with the reason, shown inline.
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

    const proto = location.protocol === "https:" ? "wss" : "ws"
    const token = getToken() ?? ""
    const url =
      `${proto}://${location.host}/api/v1/nodes/${encodeURIComponent(nodeId)}/shell` +
      `?token=${encodeURIComponent(token)}&cols=${term.cols}&rows=${term.rows}`

    const ws = new WebSocket(url)
    ws.binaryType = "arraybuffer"
    setStatus("connecting")
    setDetail("")

    ws.onopen = () => {
      setStatus("open")
      term.focus()
    }
    ws.onmessage = (ev) => {
      if (typeof ev.data === "string") {
        // Control frame: {type:"exit"|"error", ...}
        try {
          const msg = JSON.parse(ev.data)
          if (msg.type === "exit") {
            term.write(`\r\n\x1b[90m[session exited${
              msg.code ? ` (code ${msg.code})` : ""
            }]\x1b[0m\r\n`)
          } else if (msg.type === "error") {
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

    const enc = new TextEncoder()
    const onData = term.onData((d) => {
      // Keystrokes go as BINARY frames (terminal data); TEXT frames are reserved
      // for JSON control (resize). The server bridges binary -> PTY Input.
      if (ws.readyState === WebSocket.OPEN) ws.send(enc.encode(d))
    })
    const onResize = term.onResize(({ cols, rows }) => {
      if (ws.readyState === WebSocket.OPEN)
        ws.send(JSON.stringify({ type: "resize", cols, rows }))
    })

    const ro = new ResizeObserver(() => {
      try {
        fit.fit()
      } catch {
        /* element detached */
      }
    })
    ro.observe(el)

    return () => {
      cancelled = true
      ro.disconnect()
      onData.dispose()
      onResize.dispose()
      ws.close()
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
                ? "size-2 rounded-full bg-[var(--success)]"
                : status === "connecting"
                  ? "size-2 animate-pulse rounded-full bg-[var(--warning)]"
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
