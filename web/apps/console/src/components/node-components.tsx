import { useState } from "react"
import { Package } from "lucide-react"

import { usePolling } from "@/hooks/use-polling"
import { api } from "@/api"
import { Card } from "@geneza/ui"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { EmptyState, ErrorState } from "@/components/states"
import { Pagination } from "@/components/data-pagination"
import type { NodeComponentsResponse } from "@/types"

const PAGE_SIZE = 50

// NodeComponentsList renders a node's resolved software inventory — the component
// set the matcher joins advisories against.
export function NodeComponentsList({ nodeId }: { nodeId: string }) {
  const [page, setPage] = useState(1)
  const offset = (page - 1) * PAGE_SIZE

  const { data, error, initialLoading, loading, refresh } =
    usePolling<NodeComponentsResponse>(
      (s) => api.getNodeComponents(nodeId, { limit: PAGE_SIZE, offset }, s),
      30000,
      [nodeId, offset]
    )

  const rows = data?.components ?? []
  const total = data?.total ?? 0

  return (
    <Card className="overflow-hidden p-0">
      {error && !data ? (
        <ErrorState message={error} onRetry={refresh} />
      ) : initialLoading ? (
        <div className="px-4 py-10 text-center text-sm text-muted-foreground">
          Loading…
        </div>
      ) : total === 0 ? (
        <EmptyState
          icon={<Package className="size-8" />}
          title="No inventory"
          message="This node has not reported a software inventory yet."
        />
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Ecosystem</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Distro</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((c) => (
                <TableRow key={c.purl}>
                  <TableCell className="font-medium" title={c.purl}>
                    {c.name || c.purl}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {c.version || "—"}
                  </TableCell>
                  <TableCell className="text-sm">{c.ecosystem || "—"}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {c.source || "—"}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {c.distro || "—"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Pagination
            total={total}
            pageSize={PAGE_SIZE}
            page={page}
            onPage={setPage}
            loading={loading}
          />
        </>
      )}
    </Card>
  )
}
