import { useEffect, useState } from "react"

import { api } from "@/api"
import {
  exchangeLaunch,
  launchCode,
  renewLaunchSession,
  type LaunchScope,
} from "@/auth"
import { SessionContext } from "@/components/session-context"
import { Splash } from "@/components/splash"
import { WebShell } from "@/components/web-shell"
import type { AppConfig, Me } from "@/types"

// The hosted-UI launch surface (docs/hosted-ui-launch-spec.md): a bare terminal
// for ONE node, opened from a cloud provider's tenant portal in a new tab or an
// allow-listed iframe. Deliberately chrome-less — no nav, no workspace switcher,
// no links out — because the session behind it can address exactly one node and
// nothing else. It is a separate route from the console so the full console
// bundle is never reachable inside someone else's page.
export function EmbedShellPage() {
  const [state, setState] = useState<"exchanging" | "ready" | "failed">("exchanging")
  const [scope, setScope] = useState<LaunchScope | null>(null)
  const [me, setMe] = useState<Me | null>(null)
  const [config, setConfig] = useState<AppConfig | null>(null)
  const [error, setError] = useState<string>("")

  useEffect(() => {
    let cancelled = false
    void (async () => {
      const code = launchCode()
      // Strip the code from the address bar as the FIRST action, so it survives
      // neither a reload nor the browser history.
      if (window.location.hash) {
        window.history.replaceState({}, "", window.location.pathname + window.location.search)
      }
      if (!code) {
        if (!cancelled) {
          setError("This console link is missing its launch code.")
          setState("failed")
        }
        return
      }
      const sc = await exchangeLaunch(code)
      if (cancelled) return
      if (!sc) {
        setError("This console link has expired or was already used. Open the console again from your cloud portal.")
        setState("failed")
        return
      }
      try {
        const [m, cfg] = await Promise.all([api.getSession(), api.getConfig()])
        if (cancelled) return
        setScope(sc)
        setMe(m)
        setConfig(cfg)
        setState("ready")
      } catch (err) {
        if (cancelled) return
        setError(err instanceof Error ? err.message : "Could not start the session.")
        setState("failed")
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  if (state === "exchanging") return <Splash label="Opening console…" />

  if (state === "failed") {
    return (
      <div className="flex min-h-screen items-center justify-center p-6">
        <div className="max-w-md rounded-lg border border-destructive/30 bg-destructive/5 p-6 text-center">
          <p className="text-sm font-medium">Console unavailable</p>
          <p className="mt-2 text-sm text-muted-foreground">{error}</p>
        </div>
      </div>
    )
  }

  if (!scope || !me || !config) return <Splash />

  return (
    <SessionContext.Provider value={{ config, me, signOut: () => {} }}>
      <div className="min-h-screen bg-background p-4">
        <WebShell nodeId={scope.nodeId} nodeName={scope.nodeName} />
        <SessionLifetime />
      </div>
    </SessionContext.Provider>
  )
}

const RENEW_INTERVAL_MS = 60_000
const CEILING_WARNING_MS = 10 * 60_000

/**
 * Keeps the launch session alive while the shell is attached, and says so when
 * it can't. A launch session has an idle window (renewed here) and an absolute
 * ceiling (which renewal cannot pass) — so an attended shell keeps working, an
 * abandoned one lapses, and a very long one ends with warning rather than
 * vanishing mid-keystroke.
 */
function SessionLifetime() {
  const [endsAt, setEndsAt] = useState<number | null>(null)
  const [ending, setEnding] = useState(false)

  useEffect(() => {
    let cancelled = false
    const tick = async () => {
      const r = await renewLaunchSession()
      if (cancelled) return
      if (!r) {
        // Revoked, suspended, or past the ceiling — none of which recover by
        // retrying, so stop asking and tell the operator.
        setEnding(true)
        return
      }
      setEndsAt(r.maxExpiresUnix > 0 ? r.maxExpiresUnix * 1000 : null)
    }
    void tick()
    const id = setInterval(tick, RENEW_INTERVAL_MS)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  if (ending) {
    return (
      <p className="mt-3 text-center font-mono text-xs text-destructive">
        This session is ending. Reopen the console from your cloud portal to continue.
      </p>
    )
  }
  if (endsAt === null) return null
  const remaining = endsAt - Date.now()
  if (remaining > CEILING_WARNING_MS) return null
  return (
    <p className="mt-3 text-center font-mono text-xs text-muted-foreground">
      This session ends in {Math.max(0, Math.round(remaining / 60_000))} min — reopen
      from your cloud portal to continue.
    </p>
  )
}
