import { useCallback } from "react"

import { api } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import { relativeTime } from "@/lib/format"
import type { Controller, Relay } from "@/types"
import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@geneza/ui"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Skeleton } from "@geneza/ui"
import { EmptyState, ErrorState } from "@/components/states"
import { OnlineBadge } from "@/components/badges"
import { PageHeading, RefreshButton } from "@/components/page-section"

function Addrs({ addrs }: { addrs: string[] }) {
  if (!addrs || addrs.length === 0)
    return <span className="text-muted-foreground">—</span>
  return (
    <span className="font-mono text-xs">{addrs.join(", ")}</span>
  )
}

function ControllersCard() {
  const fetcher = useCallback((s: AbortSignal) => api.controllers(s), [])
  const { data, error, initialLoading, loading, refresh } = usePolling(fetcher, 10000)
  const rows: Controller[] = data?.controllers ?? []

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <div className="space-y-1.5">
          <CardTitle>Controllers</CardTitle>
          <CardDescription>Control-plane nodes across all regions</CardDescription>
        </div>
        <RefreshButton loading={loading} onClick={refresh} />
      </CardHeader>
      <CardContent>
        {initialLoading ? (
          <Skeleton className="h-24 w-full" />
        ) : error ? (
          <ErrorState message={error} onRetry={refresh} />
        ) : rows.length === 0 ? (
          <EmptyState title="No controllers" message="No controller is reporting yet." />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Controller</TableHead>
                <TableHead>Region</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Addresses</TableHead>
                <TableHead>Last seen</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((g) => (
                <TableRow key={g.controllerId}>
                  <TableCell className="font-mono text-xs">{g.controllerId}</TableCell>
                  <TableCell>{g.region || "—"}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {g.version || "—"}
                  </TableCell>
                  <TableCell>
                    <Addrs addrs={g.addrs} />
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {relativeTime(g.lastSeenUnix)}
                  </TableCell>
                  <TableCell>
                    <OnlineBadge online={g.online} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}

function RelaysCard() {
  const fetcher = useCallback((s: AbortSignal) => api.relays(s), [])
  const { data, error, initialLoading, loading, refresh } = usePolling(fetcher, 10000)
  const rows: Relay[] = data?.relays ?? []

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <div className="space-y-1.5">
          <CardTitle>Relays</CardTitle>
          <CardDescription>
            Payload-blind data-plane relays (configured and heartbeating)
          </CardDescription>
        </div>
        <RefreshButton loading={loading} onClick={refresh} />
      </CardHeader>
      <CardContent>
        {initialLoading ? (
          <Skeleton className="h-24 w-full" />
        ) : error ? (
          <ErrorState message={error} onRetry={refresh} />
        ) : rows.length === 0 ? (
          <EmptyState title="No relays" message="No relay is configured or reporting." />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Relay</TableHead>
                <TableHead>Region</TableHead>
                <TableHead>Addresses</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Last seen</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r) => (
                <TableRow key={r.relayId}>
                  <TableCell className="font-mono text-xs">{r.relayId}</TableCell>
                  <TableCell>{r.regionId || "—"}</TableCell>
                  <TableCell>
                    <Addrs addrs={r.addrs} />
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {r.static ? (
                      <Badge variant="outline">Static</Badge>
                    ) : (
                      r.version || "—"
                    )}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {r.static ? "—" : relativeTime(r.lastSeenUnix)}
                  </TableCell>
                  <TableCell>
                    <OnlineBadge online={r.online} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}

export function TopologyPage() {
  return (
    <div>
      <PageHeading
        title="Cluster topology"
        description="Controllers and relays forming the Geneza control and data plane."
      />
      <div className="space-y-6">
        <ControllersCard />
        <RelaysCard />
      </div>
    </div>
  )
}
