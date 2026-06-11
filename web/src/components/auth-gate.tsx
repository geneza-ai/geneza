import { useCallbackRef } from "@/hooks/use-callback-ref"
import { useEffect, useState } from "react"
import { useNavigate } from "react-router-dom"

import { api, setUnauthorizedHandler } from "@/api"
import {
  clearSession,
  handleRedirectCallback,
  hasAuthCallbackParams,
  hasValidSession,
  logout,
} from "@/auth"
import { LoginPage } from "@/pages/login"
import { SessionContext } from "@/components/session-context"
import { Splash } from "@/components/splash"
import type { AppConfig, Me } from "@/types"

type Phase = "boot" | "callback" | "login" | "ready" | "fatal"

export function AuthGate({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate()
  const [phase, setPhase] = useState<Phase>("boot")
  const [config, setConfig] = useState<AppConfig | null>(null)
  const [me, setMe] = useState<Me | null>(null)
  const [authError, setAuthError] = useState<string | null>(null)

  const goLogin = useCallbackRef(() => {
    setMe(null)
    setPhase("login")
  })

  useEffect(() => {
    setUnauthorizedHandler(() => {
      clearSession()
      goLogin()
    })
    return () => setUnauthorizedHandler(null)
  }, [goLogin])

  useEffect(() => {
    let cancelled = false

    async function bootstrap() {
      // 1. Public config (no auth).
      let cfg: AppConfig
      try {
        cfg = await api.getConfig()
      } catch (err) {
        if (cancelled) return
        setAuthError((err as Error).message || "Failed to load configuration")
        setPhase("fatal")
        return
      }
      if (cancelled) return
      setConfig(cfg)

      // 2. If we returned from the IdP, finish the code exchange.
      if (hasAuthCallbackParams()) {
        setPhase("callback")
        const result = await handleRedirectCallback(cfg.oidc)
        if (cancelled) return
        if (!result.ok) {
          setAuthError(result.error || "Sign-in failed")
          // Strip query params so a refresh doesn't retry a stale code.
          window.history.replaceState({}, "", "/")
          setPhase("login")
          return
        }
        // Clean the URL of code/state and restore the original path.
        const dest = result.postLoginPath || "/"
        window.history.replaceState({}, "", "/")
        navigate(dest, { replace: true })
      }

      // 3. Need a session?
      if (!hasValidSession()) {
        setPhase("login")
        return
      }

      // 4. Resolve identity.
      try {
        const meResult = await api.getMe()
        if (cancelled) return
        setMe(meResult)
        setPhase("ready")
      } catch {
        if (cancelled) return
        clearSession()
        setPhase("login")
      }
    }

    bootstrap()
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const signOut = useCallbackRef(() => {
    if (config) {
      logout(config.oidc)
    } else {
      clearSession()
      goLogin()
    }
  })

  if (phase === "boot") return <Splash label="Loading Geneza…" />
  if (phase === "callback") return <Splash label="Completing sign-in…" />

  if (phase === "fatal") {
    return (
      <div className="flex min-h-screen items-center justify-center p-6">
        <div className="max-w-md rounded-lg border border-destructive/30 bg-destructive/5 p-6 text-center">
          <p className="text-sm font-medium">Unable to reach the gateway</p>
          <p className="mt-2 text-sm text-muted-foreground">{authError}</p>
        </div>
      </div>
    )
  }

  if (phase === "login" && config) {
    return <LoginPage config={config} error={authError} />
  }

  if (phase === "ready" && config && me) {
    return (
      <SessionContext.Provider value={{ config, me, signOut }}>
        {children}
      </SessionContext.Provider>
    )
  }

  return <Splash />
}
