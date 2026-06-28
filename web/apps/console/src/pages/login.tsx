import { useEffect, useState } from "react"
import { Activity, LogIn, KeyRound } from "lucide-react"

import { Button } from "@geneza/ui"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  beginLogin,
  clearPendingOidc,
  exchangeOidc,
  loginKeystone,
  loginLocal,
  pendingOidc,
  type LoginChoice,
  type LoginResult,
} from "@/auth"
import type { AppConfig } from "@/types"

// An attempt is a login bound to a set of credentials; the picker re-invokes it
// with the chosen workspace/project.
type Attempt = (choice?: LoginChoice) => Promise<LoginResult>

interface Pending {
  title: string
  items: { value: string; label: string }[]
  pick: (value: string) => void
}

export function LoginPage({
  config,
  error,
  onLoggedIn,
}: {
  config: AppConfig
  error?: string | null
  onLoggedIn: () => void
}) {
  const { auth } = config
  const [busy, setBusy] = useState(false)
  const [localError, setLocalError] = useState<string | null>(null)
  const [pending, setPending] = useState<Pending | null>(null)

  // Runs an attempt and, if the principal must choose, builds the picker that
  // re-runs the SAME attempt with the choice applied.
  const run = async (attempt: Attempt) => {
    setBusy(true)
    setLocalError(null)
    try {
      const res = await attempt()
      if (res.ok) {
        clearPendingOidc()
        onLoggedIn()
        return
      }
      if (res.kind === "workspace") {
        setPending({
          title: "You belong to several workspaces. Choose one:",
          items: res.workspaces.map((w) => ({ value: w, label: w })),
          pick: (w) => run(() => attempt({ workspace: w })),
        })
      } else {
        setPending({
          title: "Choose an OpenStack project:",
          items: res.projects.map((p) => ({ value: p.id, label: p.name })),
          pick: (id) => run(() => attempt({ projectId: id })),
        })
      }
    } catch (e) {
      setPending(null)
      setLocalError((e as Error).message || "Sign-in failed")
    } finally {
      setBusy(false)
    }
  }

  // Resume an OIDC login that needs a workspace choice (id_token stashed).
  useEffect(() => {
    const tok = pendingOidc()
    if (tok) run((choice) => exchangeOidc(tok, choice))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const shownError = localError ?? error

  return (
    <div className="flex min-h-screen w-full items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="mb-4 flex size-11 items-center justify-center rounded-xl bg-primary text-primary-foreground">
            <Activity className="size-5" />
          </div>
          <h1 className="text-xl font-semibold tracking-tight">Sign in to Geneza</h1>
          <p className="mt-1.5 text-sm text-muted-foreground">
            {config.clusterName} · identity-aware remote access
          </p>
        </div>

        <div className="space-y-4 rounded-lg border bg-card p-6 shadow-sm">
          {pending ? (
            <Picker pending={pending} busy={busy} onCancel={() => setPending(null)} />
          ) : (
            <>
              {auth.oidc && (
                <Button className="w-full" onClick={() => beginLogin(auth.oidc!)} disabled={busy}>
                  <LogIn className="size-4" />
                  Sign in with SSO
                </Button>
              )}

              {auth.oidc && (auth.local || auth.keystone.length > 0) && <Divider />}

              {auth.local && (
                <LocalForm busy={busy} onSubmit={(u, p) => run((c) => loginLocal(u, p, c))} />
              )}

              {auth.local && auth.keystone.length > 0 && <Divider />}

              {auth.keystone.length > 0 && (
                <KeystoneForm
                  clouds={auth.keystone}
                  busy={busy}
                  onSubmit={(cloud, u, p) => run((c) => loginKeystone(cloud, u, p, c))}
                />
              )}
            </>
          )}

          {shownError && (
            <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              {shownError}
            </p>
          )}
        </div>

        <p className="mt-6 text-center text-xs text-muted-foreground/70">{config.externalUrl}</p>
      </div>
    </div>
  )
}

function Divider() {
  return (
    <div className="relative py-1">
      <div className="absolute inset-0 flex items-center">
        <span className="w-full border-t" />
      </div>
      <div className="relative flex justify-center text-2xs uppercase tracking-wide">
        <span className="bg-card px-2 text-muted-foreground">or</span>
      </div>
    </div>
  )
}

function LocalForm({ busy, onSubmit }: { busy: boolean; onSubmit: (u: string, p: string) => void }) {
  const [u, setU] = useState("")
  const [p, setP] = useState("")
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault()
        onSubmit(u, p)
      }}
    >
      <div className="space-y-1.5">
        <Label htmlFor="local-user">Username</Label>
        <Input id="local-user" autoComplete="username" value={u} onChange={(e) => setU(e.target.value)} />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="local-pass">Password</Label>
        <Input id="local-pass" type="password" autoComplete="current-password" value={p} onChange={(e) => setP(e.target.value)} />
      </div>
      <Button type="submit" variant="outline" className="w-full" disabled={busy || !u || !p}>
        <KeyRound className="size-4" />
        Sign in
      </Button>
    </form>
  )
}

function KeystoneForm({
  clouds,
  busy,
  onSubmit,
}: {
  clouds: { cloud: string; label: string }[]
  busy: boolean
  onSubmit: (cloud: string, u: string, p: string) => void
}) {
  const [cloud, setCloud] = useState(clouds[0]?.cloud ?? "")
  const [u, setU] = useState("")
  const [p, setP] = useState("")
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault()
        onSubmit(cloud, u, p)
      }}
    >
      <div className="space-y-1.5">
        <Label>OpenStack cloud</Label>
        <Select value={cloud} onValueChange={setCloud}>
          <SelectTrigger>
            <SelectValue placeholder="Choose a cloud" />
          </SelectTrigger>
          <SelectContent>
            {clouds.map((c) => (
              <SelectItem key={c.cloud} value={c.cloud}>
                {c.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="ks-user">Username</Label>
        <Input id="ks-user" autoComplete="username" value={u} onChange={(e) => setU(e.target.value)} />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="ks-pass">Password</Label>
        <Input id="ks-pass" type="password" autoComplete="current-password" value={p} onChange={(e) => setP(e.target.value)} />
      </div>
      <Button type="submit" variant="outline" className="w-full" disabled={busy || !cloud || !u || !p}>
        <KeyRound className="size-4" />
        Sign in with OpenStack
      </Button>
    </form>
  )
}

function Picker({
  pending,
  busy,
  onCancel,
}: {
  pending: Pending
  busy: boolean
  onCancel: () => void
}) {
  const [value, setValue] = useState(pending.items[0]?.value ?? "")
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">{pending.title}</p>
      <Select value={value} onValueChange={setValue}>
        <SelectTrigger>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {pending.items.map((it) => (
            <SelectItem key={it.value} value={it.value}>
              {it.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <div className="flex gap-2">
        <Button variant="ghost" className="flex-1" onClick={onCancel} disabled={busy}>
          Back
        </Button>
        <Button className="flex-1" disabled={busy || !value} onClick={() => pending.pick(value)}>
          Continue
        </Button>
      </div>
    </div>
  )
}
