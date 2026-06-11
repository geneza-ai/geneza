import { useMemo, useState } from "react"
import { Check, TerminalSquare, X } from "lucide-react"

import { api } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import { Card } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
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
import { CopyId } from "@/components/copy-id"
import { ActionBadge, StateBadge } from "@/components/session-badges"
import { relativeTime } from "@/lib/format"
import type { SessionsResponse } from "@/types"

const STATES = ["all", "active", "detached", "pending", "ended"]

export function SessionsPage() {
  const { data, error, initialLoading, loading, refresh } =
    usePolling<SessionsResponse>((s) => api.getSessions(s), 10000)
  const [state, setState] = useState("all")

  const sessions = useMemo(() => data?.sessions ?? [], [data])
  const filtered = useMemo(() => {
    if (state === "all") return sessions
    return sessions.filter((s) => s.state === state)
  }, [sessions, state])

  return (
    <div className="space-y-4">
      <PageToolbar
        description={
          data
            ? `${sessions.filter((s) => s.state === "active").length} active · ${sessions.length} total`
            : "Live and detached access sessions."
        }
        onRefresh={refresh}
        refreshing={loading}
      >
        <Select value={state} onValueChange={setState}>
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
        ) : sessions.length === 0 ? (
          <EmptyState
            icon={<TerminalSquare className="size-8" />}
            title="No sessions"
            message="No access sessions have been opened yet."
          />
        ) : filtered.length === 0 ? (
          <EmptyState title="No matches" message={`No ${state} sessions.`} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Session ID</TableHead>
                <TableHead>Node</TableHead>
                <TableHead>User</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Started</TableHead>
                <TableHead className="text-center">Detachable</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((s) => (
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
                        className="mx-auto size-4 text-[var(--success)]"
                        aria-label="Detachable"
                      />
                    ) : (
                      <X
                        className="mx-auto size-4 text-muted-foreground/50"
                        aria-label="Not detachable"
                      />
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>
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
