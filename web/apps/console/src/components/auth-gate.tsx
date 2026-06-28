import { useCallbackRef } from "@/hooks/use-callback-ref"
import { useEffect, useState } from "react"
import { useNavigate } from "react-router-dom"

import { api, setUnauthorizedHandler } from "@/api"
import {
  clearSession,
  exchangeHandoff,
  exchangeOidc,
  handleRedirectCallback,
  handoffCode,
  hasAuthCallbackParams,
  hasValidSession,
  logout,
  stashPendingOidc,
} from "@/auth"
import { desktop, isDesktop } from "@/desktop/bridge"
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

  // Resolve the current session into `me` and go ready (or fall back to login).
  const probe = useCallbackRef(async () => {
    try {
      const m = await api.getSession()
      setMe(m)
      setPhase("ready")
    } catch {
      clearSession()
      setPhase("login")
    }
  })

  useEffect(() => {
    let cancelled = false

    async function bootstrap() {
      // Desktop app: establish the mTLS proxy to the controller first (using the
      // `geneza login` cert), so every /api/v1 call below is cert-authenticated.
      if (isDesktop()) {
        try {
          await desktop.connect()
        } catch (err) {
          if (cancelled) return
          setAuthError(
            (err as Error).message ||
              "Couldn't connect to the controller. Run `geneza login` first."
          )
          setPhase("fatal")
          return
        }
      }

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

      // Desktop is authenticated by the mTLS cert — no bearer login screen.
      if (isDesktop()) {
        if (!cancelled) await probe()
        return
      }

      // Trusted-dashboard handoff (?handoff=): strip the code from the URL as the
      // FIRST action (RT-F2), then swap it (+ the HttpOnly cookie) for a session.
      const hc = handoffCode()
      if (hc) {
        window.history.replaceState({}, "", "/")
        setPhase("callback")
        const ok = await exchangeHandoff(hc)
        if (cancelled) return
        if (!ok) {
          setAuthError("Sign-in handoff failed or expired.")
          setPhase("login")
          return
        }
        await probe()
        return
      }

      // Returned from the IdP: exchange the code for an id_token, then swap that
      // for a controller session at /session/oidc.
      if (hasAuthCallbackParams() && cfg.auth.oidc) {
        setPhase("callback")
        const result = await handleRedirectCallback(cfg.auth.oidc)
        if (cancelled) return
        if (!result.ok || !result.idToken) {
          setAuthError(result.error || "Sign-in failed")
          window.history.replaceState({}, "", "/")
          setPhase("login")
          return
        }
        try {
          const ex = await exchangeOidc(result.idToken)
          if (cancelled) return
          if (!ex.ok) {
            // Multiple workspaces — hand the id_token to the login picker.
            stashPendingOidc(result.idToken)
            window.history.replaceState({}, "", "/")
            setPhase("login")
            return
          }
          const dest = result.postLoginPath || "/"
          window.history.replaceState({}, "", "/")
          navigate(dest, { replace: true })
        } catch (e) {
          if (cancelled) return
          setAuthError((e as Error).message || "Sign-in failed")
          window.history.replaceState({}, "", "/")
          setPhase("login")
          return
        }
      }

      if (!hasValidSession()) {
        setPhase("login")
        return
      }
      if (!cancelled) await probe()
    }

    bootstrap()
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const signOut = useCallbackRef(() => {
    logout()
  })

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
    return <LoginPage config={config} error={authError} onLoggedIn={() => probe()} />
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
