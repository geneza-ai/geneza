import { useCallback, useState } from "react"

import { api } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import type { RiskAgent } from "@/types"
import { Card, CardContent } from "@geneza/ui"
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
import { OutdatedBadge, SeverityBadge } from "@/components/badges"
import { PageHeading, RefreshButton } from "@/components/page-section"
import { StatusDot } from "@/components/status-dot"

// Highlights a non-zero KEV count: a node carrying a known-exploited vulnerability
// is the most urgent thing on this screen.
function KevCount({ count }: { count: number }) {
  if (count <= 0) return <span className="text-muted-foreground">0</span>
  return <span className="font-semibold text-destructive">{count}</span>
}

export function RiskPage() {
  const [outdatedOnly, setOutdatedOnly] = useState(false)
  const fetcher = useCallback(
    (s: AbortSignal) => api.risk(s, outdatedOnly),
    [outdatedOnly]
  )
  const { data, error, initialLoading, loading, refresh } = usePolling(
    fetcher,
    15000,
    [outdatedOnly]
  )
  // The API already sorts this list (outdated + KEV/critical first); render as-is.
  const rows: RiskAgent[] = data?.agents ?? []

  return (
    <div>
      <PageHeading
        title="Risk"
        description="Which nodes are both behind on their agent version and carrying known vulnerabilities. Sorted most-urgent first."
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
              title="Nothing at risk"
              message={
                outdatedOnly
                  ? "No outdated node has reported vulnerabilities."
                  : "No node has reported vulnerabilities."
              }
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Node</TableHead>
                  <TableHead>Workspace</TableHead>
                  <TableHead>Agent version</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>Worst severity</TableHead>
                  <TableHead className="text-right">KEV</TableHead>
                  <TableHead className="text-right">CVEs</TableHead>
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
                    <TableCell>
                      <OutdatedBadge outdated={a.outdated} />
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={a.worstSeverity} />
                    </TableCell>
                    <TableCell className="text-right">
                      <KevCount count={a.kevCount} />
                    </TableCell>
                    <TableCell className="text-right">{a.cveCount}</TableCell>
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
