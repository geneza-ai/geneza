import { useCallback, useEffect, useRef, useState } from "react"

import { setUnauthorizedHandler } from "@/api"
import {
  clearSession,
  completeLogin,
  getAuthConfig,
  getMe,
  hasAuthCallbackParams,
  hasSession,
  logout,
  type AuthConfig,
  type Me,
} from "@/auth"
import { LoginPage } from "@/pages/login"
import { SessionContext } from "@/components/session-context"

type Phase = "boot" | "callback" | "login" | "ready" | "fatal"

function Splash({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background text-sm text-muted-foreground">
      {label}
    </div>
  )
}

export function AuthGate({ children }: { children: React.ReactNode }) {
  const [phase, setPhase] = useState<Phase>("boot")
  const [config, setConfig] = useState<AuthConfig | null>(null)
  const [me, setMe] = useState<Me | null>(null)
  const [authError, setAuthError] = useState<string | null>(null)
  const ran = useRef(false)

  const goLogin = useCallback(() => {
    setMe(null)
    setPhase("login")
  }, [])

  useEffect(() => {
    // A 401/403 from the API (session expired/revoked, and no cert backs it)
    // drops back to the login screen.
    setUnauthorizedHandler(() => {
      if (me?.auth === "cert") return // a cert operator stays; the 403 is a real error
      clearSession()
      goLogin()
    })
    return () => setUnauthorizedHandler(null)
  }, [goLogin, me])

  // Resolve the current principal (cluster session or break-glass cert).
  const probe = useCallback(async () => {
    const m = await getMe()
    if (m) {
      setMe(m)
      setPhase("ready")
    } else {
      clearSession()
      setPhase("login")
    }
  }, [])

  useEffect(() => {
    if (ran.current) return
    ran.current = true
    let cancelled = false

    async function bootstrap() {
      let cfg: AuthConfig
      try {
        cfg = await getAuthConfig()
      } catch (e) {
        if (cancelled) return
        setAuthError((e as Error).message || "Failed to load configuration")
        setPhase("fatal")
        return
      }
      if (cancelled) return
      setConfig(cfg)

      // Returned from the IdP: exchange the code for an id_token, swap it for a
      // cluster session, then probe.
      if (hasAuthCallbackParams() && cfg.oidc) {
        setPhase("callback")
        const err = await completeLogin(cfg.oidc)
        if (cancelled) return
        if (err) {
          setAuthError(err)
          setPhase("login")
          return
        }
        await probe()
        return
      }

      // A bearer session OR a break-glass cert (the /me probe sees both). Always
      // probe: even with no bearer, a cert may authenticate.
      if (hasSession()) {
        await probe()
        return
      }
      // No bearer — but a cert might still authenticate. Probe once; fall to login
      // if it doesn't.
      await probe()
    }

    bootstrap()
    return () => {
      cancelled = true
    }
  }, [probe])

  const signOut = useCallback(() => {
    logout()
  }, [])

  if (phase === "boot") return <Splash label="Loading Geneza…" />
  if (phase === "callback") return <Splash label="Completing sign-in…" />

  if (phase === "fatal") {
    return (
      <div className="flex min-h-screen items-center justify-center p-6">
        <div className="max-w-md rounded-lg border border-destructive/30 bg-destructive/5 p-6 text-center">
          <p className="text-sm font-medium">Unable to reach the controller</p>
          <p className="mt-2 text-sm text-muted-foreground">{authError}</p>
        </div>
      </div>
    )
  }

  if (phase === "login" && config) {
    return <LoginPage config={config} error={authError} />
  }

  if (phase === "ready" && me) {
    return (
      <SessionContext.Provider value={{ me, signOut }}>
        {children}
      </SessionContext.Provider>
    )
  }

  return <Splash />
}
