import { useState } from "react"
import { beginLogin, type AuthConfig } from "@/auth"
import { Button, GenezaMark } from "@geneza/ui"

export function LoginPage({
  config,
  error,
}: {
  config: AuthConfig
  error?: string | null
}) {
  const [busy, setBusy] = useState(false)
  const [localError, setLocalError] = useState<string | null>(null)
  const oidc = config.oidc

  async function onSignIn() {
    if (!oidc) return
    setBusy(true)
    setLocalError(null)
    try {
      await beginLogin(oidc)
    } catch (e) {
      setBusy(false)
      setLocalError((e as Error).message || "Could not start sign-in")
    }
  }

  const shown = localError || error

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-6 text-foreground">
      <div className="w-full max-w-sm rounded-xl border bg-card p-8 shadow-sm">
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <GenezaMark size={44} />
          <div>
            <h1 className="font-serif text-xl font-medium tracking-tight">Geneza Cluster</h1>
            <p className="text-sm text-muted-foreground">
              {config.clusterName} · operator console
            </p>
          </div>
        </div>

        {shown && (
          <p className="mb-4 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-center text-sm text-destructive">
            {shown}
          </p>
        )}

        {oidc ? (
          <Button className="w-full" onClick={onSignIn} disabled={busy}>
            {busy ? "Redirecting…" : "Sign in with SSO"}
          </Button>
        ) : (
          <p className="text-center text-sm text-muted-foreground">
            OIDC login is not configured. Reach this console with a break-glass
            cluster admin certificate.
          </p>
        )}

        <p className="mt-6 text-center text-[11px] text-muted-foreground">
          Restricted to cluster administrators.
        </p>
      </div>
    </div>
  )
}
