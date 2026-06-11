import { useState } from "react"
import { Activity, LogIn } from "lucide-react"

import { Button } from "@/components/ui/button"
import { beginLogin } from "@/auth"
import type { AppConfig } from "@/types"

export function LoginPage({
  config,
  error,
}: {
  config: AppConfig
  error?: string | null
}) {
  const [busy, setBusy] = useState(false)
  const [localError, setLocalError] = useState<string | null>(null)

  const signIn = async () => {
    setBusy(true)
    setLocalError(null)
    try {
      await beginLogin(config.oidc)
      // Page redirects away; keep busy state.
    } catch (err) {
      setBusy(false)
      setLocalError((err as Error).message || "Could not start sign-in")
    }
  }

  const shownError = localError ?? error

  return (
    <div className="flex min-h-screen w-full items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="mb-4 flex size-11 items-center justify-center rounded-xl bg-primary text-primary-foreground">
            <Activity className="size-5" />
          </div>
          <h1 className="text-xl font-semibold tracking-tight">
            Sign in to Geneza
          </h1>
          <p className="mt-1.5 text-sm text-muted-foreground">
            {config.clusterName} · identity-aware remote access
          </p>
        </div>

        <div className="rounded-lg border bg-card p-6 shadow-sm">
          <Button className="w-full" onClick={signIn} disabled={busy}>
            <LogIn className="size-4" />
            {busy ? "Redirecting…" : "Sign in with SSO"}
          </Button>

          {shownError && (
            <p className="mt-4 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              {shownError}
            </p>
          )}

          <p className="mt-4 text-center text-xs text-muted-foreground">
            You’ll be redirected to your identity provider.
          </p>
        </div>

        <p className="mt-6 text-center text-xs text-muted-foreground/70">
          {config.externalUrl}
        </p>
      </div>
    </div>
  )
}
