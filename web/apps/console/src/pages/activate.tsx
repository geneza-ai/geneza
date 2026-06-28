import { useEffect, useState } from "react"
import { useSearchParams } from "react-router-dom"
import { MonitorSmartphone, ShieldCheck } from "lucide-react"

import { api } from "@/api"
import { Button } from "@geneza/ui"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@geneza/ui"
import { useSession } from "@/components/session-context"

interface GrantInfo {
  clientName: string
  sourceIp: string
  requestedUnix: number
}

// The device-approval page (RFC 8628). A signed-in operator confirms a CLI's
// login by typing the user code shown in their terminal — never a one-click link
// (RT-F7). On approval the controller issues the CLI a cert with THIS operator's
// workspace + roles.
export function ActivatePage() {
  const { me } = useSession()
  const [params] = useSearchParams()
  const hint = params.get("user_code") || ""
  const [code, setCode] = useState("")
  const [grant, setGrant] = useState<GrantInfo | null>(null)
  const [status, setStatus] = useState<"idle" | "approved" | "denied">("idle")
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  // Reset the looked-up grant whenever the code changes.
  useEffect(() => setGrant(null), [code])

  const lookup = async () => {
    setBusy(true)
    setError(null)
    try {
      const g = await api.get<GrantInfo>(`/device/${encodeURIComponent(code.trim())}`)
      setGrant(g)
    } catch {
      setError("No pending sign-in matches that code (check it and try again).")
    } finally {
      setBusy(false)
    }
  }

  const decide = async (approve: boolean) => {
    setBusy(true)
    setError(null)
    try {
      await api.post(`/device/${approve ? "approve" : "deny"}`, { userCode: code.trim() })
      setStatus(approve ? "approved" : "denied")
    } catch (e) {
      setError((e as Error).message || "Could not record your decision.")
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mx-auto flex max-w-md flex-col gap-6 py-10">
      <Card>
        <CardHeader>
          <div className="mb-1 flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
            <MonitorSmartphone className="size-5" />
          </div>
          <CardTitle>Approve a CLI sign-in</CardTitle>
          <CardDescription>
            Enter the code shown in your terminal. The command line will receive access
            as <span className="font-medium text-foreground">{me.user}</span> in workspace{" "}
            <span className="font-medium text-foreground">{me.workspace}</span>.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {status === "approved" ? (
            <div className="flex items-center gap-2 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-600 dark:text-emerald-400">
              <ShieldCheck className="size-4" /> Approved — your terminal can continue.
            </div>
          ) : status === "denied" ? (
            <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              Denied. The sign-in request was rejected.
            </div>
          ) : (
            <>
              <div className="space-y-1.5">
                <Label htmlFor="user-code">Device code</Label>
                <Input
                  id="user-code"
                  placeholder="XXXX-XXXX"
                  autoComplete="off"
                  value={code}
                  onChange={(e) => setCode(e.target.value.toUpperCase())}
                  className="font-mono tracking-widest"
                />
                {hint && !code && (
                  <p className="text-xs text-muted-foreground">
                    From your link: <span className="font-mono">{hint}</span> — type it above to confirm.
                  </p>
                )}
              </div>

              {!grant ? (
                <Button className="w-full" disabled={busy || code.trim().length < 4} onClick={lookup}>
                  Continue
                </Button>
              ) : (
                <div className="space-y-3">
                  <div className="rounded-md border bg-muted/40 p-3 text-sm">
                    <div className="font-medium">{grant.clientName}</div>
                    <div className="text-muted-foreground">from {grant.sourceIp}</div>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Only approve if you started this sign-in. Approving grants the CLI your
                    current access.
                  </p>
                  <div className="flex gap-2">
                    <Button variant="outline" className="flex-1" disabled={busy} onClick={() => decide(false)}>
                      Deny
                    </Button>
                    <Button className="flex-1" disabled={busy} onClick={() => decide(true)}>
                      Approve
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}

          {error && (
            <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              {error}
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
