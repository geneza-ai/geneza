import { useEffect, useState } from "react"
import { Check, TerminalSquare, X } from "lucide-react"
import { toast } from "sonner"

import { api, ApiError } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import { useListControls } from "@/hooks/use-list-controls"
import { useSession } from "@/components/session-context"
import { Button } from "@geneza/ui"
import { Card } from "@geneza/ui"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@geneza/ui"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
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
import { Pagination, SortableHead } from "@/components/data-pagination"
import { CopyId } from "@/components/copy-id"
import { ActionBadge, StateBadge } from "@/components/session-badges"
import { relativeTime } from "@/lib/format"
import type { SessionInfo, SessionsResponse } from "@/types"

const STATES = ["all", "active", "detached", "pending", "ended", "revoked"]
const PAGE_SIZE = 25

// A session is live (kickable) while it is not in a terminal state.
const KICKABLE = new Set(["active", "detached", "pending"])

export function SessionsPage() {
  const { me } = useSession()
  // Filter / sort / page live in the URL (bookmarkable, shareable, survive refresh).
  const ctl = useListControls({ pageSize: PAGE_SIZE, defaultSort: "started", defaultOrder: "desc" })

  // The search box is local + debounced into the URL so typing doesn't spam history.
  const [search, setSearch] = useState(ctl.q)
  useEffect(() => setSearch(ctl.q), [ctl.q]) // sync when the URL changes (back/forward)
  useEffect(() => {
    const t = setTimeout(() => {
      if (search !== ctl.q) ctl.setQ(search)
    }, 300)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search])

  const { data, error, initialLoading, loading, refresh } =
    usePolling<SessionsResponse>(
      (s) =>
        api.getSessions(
          {
            limit: PAGE_SIZE,
            offset: ctl.offset,
            state: ctl.state === "all" ? undefined : ctl.state,
            q: ctl.q || undefined,
            sort: ctl.sort,
            order: ctl.order,
          },
          s
        ),
      10000,
      [ctl.offset, ctl.state, ctl.q, ctl.sort, ctl.order]
    )

  const sessions = data?.sessions ?? []
  const total = data?.total ?? 0
  const [target, setTarget] = useState<SessionInfo | null>(null)
  const [revoking, setRevoking] = useState(false)

  const canRevoke = me.admin
  const showActions = canRevoke && sessions.some((s) => KICKABLE.has(s.state))
  const filtering = ctl.state !== "all" || ctl.q !== ""

  async function revoke() {
    if (!target) return
    setRevoking(true)
    try {
      await api.revokeSession(target.sessionId)
      toast.success("Session revoked", {
        description: `${target.user} · ${target.nodeName || target.nodeId}`,
      })
      setTarget(null)
      refresh()
    } catch (err) {
      toast.error("Revoke failed", {
        description: err instanceof ApiError ? err.message : String(err),
      })
    } finally {
      setRevoking(false)
    }
  }

  return (
    <div className="space-y-4">
      <PageToolbar
        description={`${total} session${total === 1 ? "" : "s"}`}
        onRefresh={refresh}
        refreshing={loading}
      >
        <Input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search user, node, action…"
          className="w-56"
        />
        <Select value={ctl.state} onValueChange={ctl.setState}>
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {STATES.map((s) => (
              <SelectItem key={s} value={s} className="capitalize">
                {s === "all" ? "All states" : s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </PageToolbar>

      <Card className="overflow-hidden p-0">
        {error && !data ? (
          <ErrorState message={error} onRetry={refresh} />
        ) : initialLoading ? (
          <RowsSkeleton />
        ) : total === 0 ? (
          <EmptyState
            icon={<TerminalSquare className="size-8" />}
            title={filtering ? "No matches" : "No sessions"}
            message={
              filtering
                ? "No sessions match the current filter."
                : "No access sessions have been opened yet."
            }
          />
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Session ID</TableHead>
                  <SortableHead label="Node" col="node" sort={ctl} onSort={(s) => ctl.setSort(s.sort, s.order)} />
                  <SortableHead label="User" col="user" sort={ctl} onSort={(s) => ctl.setSort(s.sort, s.order)} />
                  <SortableHead label="Action" col="action" sort={ctl} onSort={(s) => ctl.setSort(s.sort, s.order)} />
                  <SortableHead label="State" col="state" sort={ctl} onSort={(s) => ctl.setSort(s.sort, s.order)} />
                  <SortableHead label="Started" col="started" sort={ctl} onSort={(s) => ctl.setSort(s.sort, s.order)} />
                  <TableHead className="text-center">Detachable</TableHead>
                  {showActions && (
                    <TableHead className="text-right">Manage</TableHead>
                  )}
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map((s) => (
                  <TableRow key={s.sessionId}>
                    <TableCell>
                      <CopyId value={s.sessionId} label="Session ID copied" />
                    </TableCell>
                    <TableCell className="font-medium">
                      {s.nodeName || (
                        <span className="font-mono text-xs text-muted-foreground">
                          {s.nodeId}
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="text-sm">{s.user}</TableCell>
                    <TableCell>
                      <ActionBadge action={s.action} />
                    </TableCell>
                    <TableCell>
                      <StateBadge state={s.state} />
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {relativeTime(s.startedUnix)}
                    </TableCell>
                    <TableCell className="text-center">
                      {s.detachable ? (
                        <Check
                          className="mx-auto size-4 text-success"
                          aria-label="Detachable"
                        />
                      ) : (
                        <X
                          className="mx-auto size-4 text-muted-foreground/50"
                          aria-label="Not detachable"
                        />
                      )}
                    </TableCell>
                    {showActions && (
                      <TableCell className="text-right">
                        {KICKABLE.has(s.state) && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                            onClick={() => setTarget(s)}
                          >
                            Revoke
                          </Button>
                        )}
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <Pagination
              total={total}
              pageSize={PAGE_SIZE}
              page={ctl.page}
              onPage={ctl.setPage}
              loading={loading}
            />
          </>
        )}
      </Card>

      <Dialog
        open={target !== null}
        onOpenChange={(open) => !open && !revoking && setTarget(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke session?</DialogTitle>
            <DialogDescription>
              This immediately tears down the live tunnel and blocks reattach.
              The user will be disconnected from{" "}
              <span className="font-medium text-foreground">
                {target?.nodeName || target?.nodeId}
              </span>
              .
            </DialogDescription>
          </DialogHeader>
          {target && (
            <div className="rounded-md border bg-muted/30 px-3 py-2 text-sm">
              <div className="flex justify-between gap-4">
                <span className="text-muted-foreground">User</span>
                <span className="font-medium">{target.user}</span>
              </div>
              <div className="mt-1 flex justify-between gap-4">
                <span className="text-muted-foreground">Action</span>
                <span className="font-medium">{target.action}</span>
              </div>
              <div className="mt-1 flex justify-between gap-4">
                <span className="text-muted-foreground">Session</span>
                <span className="font-mono text-xs">{target.sessionId}</span>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setTarget(null)}
              disabled={revoking}
            >
              Cancel
            </Button>
            <Button variant="destructive" onClick={revoke} disabled={revoking}>
              {revoking ? "Revoking…" : "Revoke session"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function RowsSkeleton() {
  return (
    <div className="divide-y">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="flex items-center gap-4 px-3 py-3">
          <Skeleton className="h-4 w-36" />
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-5 w-14" />
          <Skeleton className="ml-auto h-4 w-16" />
        </div>
      ))}
    </div>
  )
}
