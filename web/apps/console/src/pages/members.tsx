import { useState } from "react"
import { Ban, Plus, Trash2, UserPlus, Users } from "lucide-react"
import { toast } from "sonner"

import { api, ApiError } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import { Button, Card, Skeleton } from "@geneza/ui"
import { Badge } from "@/components/ui/badge"
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { EmptyState, ErrorState } from "@/components/states"
import { PageToolbar } from "@/components/page-toolbar"
import { relativeTime } from "@/lib/format"
import type { Member, MembersResponse, SuspensionsResponse } from "@/types"

// A provider=local row grants roles but cannot grant a credential: local
// passwords come from controller.yaml's local_users and have no runtime write
// path, so the person still cannot sign in. Saying so here is the difference
// between "I added them" and "I added them and they can actually get in".
const LOCAL_WARNING =
  "A local member gets roles but no password. Local credentials live in the controller's config (local_users) — this row alone will not let them sign in."

export function MembersPage() {
  const { data, error, initialLoading, refresh } = usePolling<MembersResponse>(
    (s) => api.getMembers(s),
    30000
  )
  // Suspension is a property OF a member, so show it on the member's own row
  // rather than on a separate page nobody would think to open mid-incident.
  const { data: susp, refresh: refreshSusp } = usePolling<SuspensionsResponse>(
    (s) => api.getSuspensions(s),
    30000
  )
  const suspended = new Map(
    (susp?.suspensions ?? []).map((x) => [`${x.provider}:${x.subject}`, x])
  )
  const [suspending, setSuspending] = useState<Member | null>(null)
  const [suspendReason, setSuspendReason] = useState("")
  const [alsoRevoke, setAlsoRevoke] = useState(true)
  const [editing, setEditing] = useState<Member | null>(null)
  const [adding, setAdding] = useState(false)
  const [removing, setRemoving] = useState<Member | null>(null)
  const [busy, setBusy] = useState(false)

  const members = data?.members ?? []
  const grantable = data?.grantableRoles ?? []
  const providers = data?.providers ?? ["oidc", "keystone", "local"]

  async function suspend(m: Member) {
    setBusy(true)
    try {
      const res = await api.suspendPrincipal({
        provider: m.provider,
        subject: m.subject,
        username: m.username,
        reason: suspendReason.trim(),
        revokeSessions: alsoRevoke,
      })
      toast.success("Principal suspended", {
        description: alsoRevoke
          ? `${m.username} — ${res.sessionsRevoked} session(s) revoked`
          : m.username,
      })
      setSuspending(null)
      setSuspendReason("")
      refreshSusp()
    } catch (err) {
      toast.error("Failed to suspend", {
        description: err instanceof ApiError ? err.message : String(err),
      })
    } finally {
      setBusy(false)
    }
  }

  async function lift(m: Member) {
    setBusy(true)
    try {
      await api.liftSuspension(m.provider, m.subject)
      toast.success("Suspension lifted", { description: m.username })
      refreshSusp()
    } catch (err) {
      toast.error("Failed to lift suspension", {
        description: err instanceof ApiError ? err.message : String(err),
      })
    } finally {
      setBusy(false)
    }
  }

  async function remove(m: Member) {
    setBusy(true)
    try {
      await api.deleteMember(m.provider, m.subject)
      toast.success("Member removed", { description: m.username })
      setRemoving(null)
      refresh()
    } catch (err) {
      toast.error("Failed to remove member", {
        description: err instanceof ApiError ? err.message : String(err),
      })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      <PageToolbar
        description="Principals bound to this workspace, and the roles they hold here."
        onRefresh={refresh}
      >
        <Button size="sm" onClick={() => setAdding(true)}>
          <UserPlus className="size-4" />
          Add member
        </Button>
      </PageToolbar>

      <Card className="overflow-hidden p-0">
        {error && !data ? (
          <ErrorState message={error} onRetry={refresh} />
        ) : initialLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : members.length === 0 ? (
          <EmptyState
            icon={<Users className="size-8" />}
            title="No members"
            message="Nobody is bound to this workspace yet. OIDC users may also receive roles from the workspace policy; Keystone users can only be granted roles here."
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="pl-5">User</TableHead>
                <TableHead>Provider</TableHead>
                <TableHead>Roles</TableHead>
                <TableHead>Added</TableHead>
                <TableHead className="pr-5" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {members.map((m) => (
                <TableRow key={`${m.provider}:${m.subject}`}>
                  <TableCell className="py-3 pl-5">
                    <div className="font-medium">{m.username}</div>
                    <div className="font-mono text-2xs text-faint">
                      {m.subject}
                    </div>
                  </TableCell>
                  <TableCell className="py-3">
                    <Badge variant="outline">{m.provider}</Badge>
                  </TableCell>
                  <TableCell className="py-3">
                    <div className="flex flex-wrap gap-1.5">
                      {suspended.has(`${m.provider}:${m.subject}`) && (
                        <Badge variant="destructive" title={suspended.get(`${m.provider}:${m.subject}`)?.reason}>
                          suspended
                        </Badge>
                      )}
                      {m.roles.length === 0 ? (
                        <span className="font-mono text-2xs text-warning">
                          no roles
                        </span>
                      ) : (
                        m.roles.map((r) => (
                          <Badge key={r} variant="outline" className="font-mono">
                            {r}
                          </Badge>
                        ))
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="py-3 font-mono text-[11.5px] text-muted-foreground">
                    {relativeTime(m.createdUnix)}
                    <div className="text-2xs text-faint">{m.addedBy}</div>
                  </TableCell>
                  <TableCell className="py-3 pr-5 text-right">
                    <div className="flex justify-end gap-1.5">
                      {suspended.has(`${m.provider}:${m.subject}`) ? (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => lift(m)}
                          disabled={busy}
                        >
                          Lift suspension
                        </Button>
                      ) : (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            setSuspendReason("")
                            setAlsoRevoke(true)
                            setSuspending(m)
                          }}
                        >
                          <Ban className="size-3.5" />
                          Suspend
                        </Button>
                      )}
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setEditing(m)}
                      >
                        Edit roles
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        title="Remove member"
                        onClick={() => setRemoving(m)}
                      >
                        <Trash2 className="size-3.5" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>

      <MemberDialog
        open={adding || editing !== null}
        member={editing}
        grantable={grantable}
        providers={providers}
        onClose={() => {
          setAdding(false)
          setEditing(null)
        }}
        onSaved={() => {
          setAdding(false)
          setEditing(null)
          refresh()
        }}
      />

      <Dialog
        open={suspending !== null}
        onOpenChange={(o) => !o && !busy && setSuspending(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Suspend {suspending?.username}?</DialogTitle>
            <DialogDescription>
              Suspension blocks the NEXT authorization — new sessions, new
              certificates, console login. It does not by itself end what is
              already running.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="reason">Reason</Label>
              <Input
                id="reason"
                value={suspendReason}
                onChange={(e) => setSuspendReason(e.target.value)}
                placeholder="incident reference, ticket, or cause"
              />
            </div>
            <Label className="flex items-start gap-2.5 font-normal">
              <input
                type="checkbox"
                className="mt-0.5 size-4 shrink-0 accent-primary"
                checked={alsoRevoke}
                onChange={(e) => setAlsoRevoke(e.target.checked)}
              />
              <span className="text-sm">
                Also revoke their live sessions now
                <span className="block text-xs text-muted-foreground">
                  Leave this on if you are responding to an incident — otherwise
                  an existing shell keeps running.
                </span>
              </span>
            </Label>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setSuspending(null)}
              disabled={busy}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => suspending && suspend(suspending)}
              disabled={busy || !suspendReason.trim()}
            >
              {busy ? "Suspending…" : "Suspend principal"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={removing !== null}
        onOpenChange={(o) => !o && !busy && setRemoving(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Remove {removing?.username}?</DialogTitle>
            <DialogDescription>
              They lose every role they hold in this workspace. Live sessions are
              not torn down by this — quarantine the node or revoke the session to
              do that.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setRemoving(null)}
              disabled={busy}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => removing && remove(removing)}
              disabled={busy}
            >
              {busy ? "Removing…" : "Remove member"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

// MemberDialog adds a principal or edits an existing one's roles. Identity fields
// are locked when editing: provider+subject are the record's key, so changing them
// would create a second member rather than rename this one.
function MemberDialog({
  open,
  member,
  grantable,
  providers,
  onClose,
  onSaved,
}: {
  open: boolean
  member: Member | null
  grantable: string[]
  providers: string[]
  onClose: () => void
  onSaved: () => void
}) {
  const [provider, setProvider] = useState(member?.provider ?? "oidc")
  const [username, setUsername] = useState(member?.username ?? "")
  const [subject, setSubject] = useState(member?.subject ?? "")
  const [roles, setRoles] = useState<string[]>(member?.roles ?? [])
  const [groups, setGroups] = useState((member?.groups ?? []).join(", "))
  const [busy, setBusy] = useState(false)
  // Re-seed the form whenever the dialog opens for a different subject.
  const [seeded, setSeeded] = useState<string | null>(null)
  const key = member ? `${member.provider}:${member.subject}` : "new"
  if (open && seeded !== key) {
    setSeeded(key)
    setProvider(member?.provider ?? providers[0] ?? "oidc")
    setUsername(member?.username ?? "")
    setSubject(member?.subject ?? "")
    setRoles(member?.roles ?? [])
    setGroups((member?.groups ?? []).join(", "))
  }
  if (!open && seeded !== null) setSeeded(null)

  const toggleRole = (r: string) =>
    setRoles((cur) =>
      cur.includes(r) ? cur.filter((x) => x !== r) : [...cur, r]
    )

  async function save() {
    setBusy(true)
    try {
      await api.putMember({
        provider,
        username: username.trim(),
        subject: subject.trim() || undefined,
        roles,
        groups: groups
          .split(",")
          .map((g) => g.trim())
          .filter(Boolean),
      })
      toast.success(member ? "Roles updated" : "Member added", {
        description: username.trim(),
      })
      onSaved()
    } catch (err) {
      toast.error("Failed to save member", {
        description: err instanceof ApiError ? err.message : String(err),
      })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && !busy && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{member ? "Edit roles" : "Add member"}</DialogTitle>
          <DialogDescription>
            {member
              ? `Roles ${member.username} holds in this workspace.`
              : "Bind a principal to this workspace and grant workspace roles."}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {!member && (
            <>
              <div className="space-y-1.5">
                <Label htmlFor="provider">Identity provider</Label>
                <Select value={provider} onValueChange={setProvider}>
                  <SelectTrigger id="provider">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {providers.map((p) => (
                      <SelectItem key={p} value={p}>
                        {p}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {provider === "local" && (
                  <p className="text-xs text-warning">{LOCAL_WARNING}</p>
                )}
              </div>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor="username">Username</Label>
                  <Input
                    id="username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="alice"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="subject">Subject</Label>
                  <Input
                    id="subject"
                    value={subject}
                    onChange={(e) => setSubject(e.target.value)}
                    placeholder="defaults to the username"
                    className="font-mono text-xs"
                  />
                  <p className="text-xs text-muted-foreground">
                    The provider's stable id for this person — the OIDC sub or the
                    Keystone user id. It, not the username, is the key.
                  </p>
                </div>
              </div>
            </>
          )}

          <div className="space-y-2">
            <Label>Workspace roles</Label>
            <div className="flex flex-wrap gap-2">
              {grantable.map((r) => (
                <button
                  key={r}
                  type="button"
                  onClick={() => toggleRole(r)}
                  className={
                    roles.includes(r)
                      ? "rounded-[7px] border border-brand-line bg-brand-tint px-3 py-[7px] font-mono text-[11.5px] text-foreground"
                      : "rounded-[7px] border border-border px-3 py-[7px] font-mono text-[11.5px] text-muted-foreground hover:text-foreground"
                  }
                >
                  {r}
                </button>
              ))}
            </div>
            <p className="text-xs text-muted-foreground">
              Only these are grantable. The reserved cluster roles (admin,
              platform-admin) are break-glass certificate only and the controller
              refuses them here.
            </p>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="groups">Groups</Label>
            <Input
              id="groups"
              value={groups}
              onChange={(e) => setGroups(e.target.value)}
              placeholder="comma separated, optional"
              className="font-mono text-xs"
            />
            <p className="text-xs text-muted-foreground">
              Used by workspace policy bindings that grant by group rather than by
              name.
            </p>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            onClick={save}
            disabled={busy || (!member && !username.trim()) || roles.length === 0}
          >
            <Plus className="size-4" />
            {busy ? "Saving…" : member ? "Save roles" : "Add member"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
