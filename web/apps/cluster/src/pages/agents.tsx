import { useCallback, useState } from "react"

import { api } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import type { Agent } from "@/types"
import {
  Card,
  CardContent,
} from "@geneza/ui"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Button } from "@geneza/ui"
import { Skeleton } from "@geneza/ui"
import { EmptyState, ErrorState } from "@/components/states"
import { OnlineBadge, OutdatedBadge } from "@/components/badges"
import { PageHeading, RefreshButton } from "@/components/page-section"
import { StatusDot } from "@/components/status-dot"

export function AgentsPage() {
  const [outdatedOnly, setOutdatedOnly] = useState(false)
  const fetcher = useCallback(
    (s: AbortSignal) => api.agents(s, outdatedOnly),
    [outdatedOnly]
  )
  const { data, error, initialLoading, loading, refresh } = usePolling(
    fetcher,
    10000,
    [outdatedOnly]
  )
  const rows: Agent[] = data?.agents ?? []

  return (
    <div>
      <PageHeading
        title="Agents"
        description="Every node across all workspaces and how its agent version compares to the version it should be running."
        actions={
          <>
            <Button
              variant={outdatedOnly ? "default" : "outline"}
              size="sm"
              onClick={() => setOutdatedOnly((v) => !v)}
            >
              Outdated only
            </Button>
            <RefreshButton loading={loading} onClick={refresh} />
          </>
        }
      />
      <Card>
        <CardContent className="pt-6">
          {initialLoading ? (
            <Skeleton className="h-40 w-full" />
          ) : error ? (
            <ErrorState message={error} onRetry={refresh} />
          ) : rows.length === 0 ? (
            <EmptyState
              title={outdatedOnly ? "No outdated agents" : "No agents"}
              message={
                outdatedOnly
                  ? "Every node is on its desired version."
                  : "No node has reported in yet."
              }
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Node</TableHead>
                  <TableHead>Workspace</TableHead>
                  <TableHead>Agent version</TableHead>
                  <TableHead>Desired version</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((a) => (
                  <TableRow key={`${a.workspace}/${a.nodeId}`}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <StatusDot online={a.online} />
                        <span className="font-medium">{a.name || a.nodeId}</span>
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{a.workspace}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {a.agentVersion || "—"}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {a.desiredVersion || "—"}
                    </TableCell>
                    <TableCell>
                      <OutdatedBadge outdated={a.outdated} />
                    </TableCell>
                    <TableCell>
                      <OnlineBadge online={a.online} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
