import { useMemo, useState } from "react"
import { useSearchParams } from "react-router-dom"
import { ChevronDown, ChevronRight, Search, ShieldX } from "lucide-react"

import { api } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import { Card } from "@geneza/ui"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@geneza/ui"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { SeverityBadge, StatusBadge } from "@/components/vuln-badges"
import { EmptyState, ErrorState } from "@/components/states"
import { PageToolbar } from "@/components/page-toolbar"
import { Pagination } from "@/components/data-pagination"
import type { WorkspaceCVE, WorkspaceCVEsResponse } from "@/types"

const PAGE_SIZE = 50

// VulnerabilitiesPage is the fleet rollup: every CVE affecting any node in the
// workspace, with severity, the representative status, and the count of distinct
// affected nodes. A row expands to reveal the affected node list. The CVE
// filter lives in the URL so a view is bookmarkable and shareable, and is sent to
// the server so paging stays correct under the filter.
export function VulnerabilitiesPage() {
  const [params, setParams] = useSearchParams()
  const cve = params.get("cve") ?? ""

  const [term, setTerm] = useState(cve)
  const [page, setPage] = useState(1)
  const [expanded, setExpanded] = useState<string | null>(null)

  const { data, error, initialLoading, refresh } =
    usePolling<WorkspaceCVEsResponse>(
      (s) =>
        api.getWorkspaceCVEs(
          { cve: cve || undefined, limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE },
          s
        ),
      15000,
      [cve, page]
    )

  const rows = useMemo(() => data?.cves ?? [], [data])
  const total = data?.total ?? 0

  function applyFilter(next: string) {
    const q = next.trim()
    setParams(q ? { cve: q } : {}, { replace: true })
    setPage(1)
    setExpanded(null)
  }

  return (
    <div className="space-y-4">
      <PageToolbar description="Every CVE affecting a node across this workspace, with severity, status and the number of affected nodes.">
        <form
          className="flex items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault()
            applyFilter(term)
          }}
        >
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={term}
              onChange={(e) => setTerm(e.target.value)}
              placeholder="Filter by CVE…"
              className="w-64 pl-8 font-mono"
            />
          </div>
        </form>
      </PageToolbar>

      <Card className="overflow-hidden p-0">
        {error ? (
          <ErrorState message={error} onRetry={refresh} />
        ) : initialLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : total === 0 ? (
          <EmptyState
            icon={<ShieldX className="size-8" />}
            title={cve ? "No matching CVEs" : "No vulnerabilities"}
            message={
              cve
                ? `No CVE matching "${cve}" affects a node in this workspace.`
                : "No node in this workspace is currently matched against a CVE."
            }
          />
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead>CVE</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Nodes</TableHead>
                  <TableHead>Fixed in</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((r) => (
                  <CVERollupRow
                    key={r.cve}
                    row={r}
                    open={expanded === r.cve}
                    onToggle={() =>
                      setExpanded((cur) => (cur === r.cve ? null : r.cve))
                    }
                  />
                ))}
              </TableBody>
            </Table>
            <Pagination
              total={total}
              pageSize={PAGE_SIZE}
              page={page}
              onPage={(p) => {
                setExpanded(null)
                setPage(p)
              }}
              loading={false}
            />
          </>
        )}
      </Card>
    </div>
  )
}

// CVERollupRow is one rollup row, click-to-expand to reveal the affected nodes.
function CVERollupRow({
  row,
  open,
  onToggle,
}: {
  row: WorkspaceCVE
  open: boolean
  onToggle: () => void
}) {
  return (
    <>
      <TableRow className="cursor-pointer" onClick={onToggle}>
        <TableCell className="text-muted-foreground">
          {open ? (
            <ChevronDown className="size-4" />
          ) : (
            <ChevronRight className="size-4" />
          )}
        </TableCell>
        <TableCell className="font-mono text-xs font-medium">{row.cve}</TableCell>
        <TableCell>
          <SeverityBadge severity={row.severity} />
        </TableCell>
        <TableCell>
          <StatusBadge status={row.status} />
        </TableCell>
        <TableCell className="text-right tabular-nums">{row.nodeCount}</TableCell>
        <TableCell className="font-mono text-xs">
          {row.fixedVersion || (
            <span className="font-sans text-muted-foreground">—</span>
          )}
        </TableCell>
      </TableRow>
      {open && (
        <TableRow className="bg-muted/30 hover:bg-muted/30">
          <TableCell />
          <TableCell colSpan={5} className="py-3">
            <div className="flex flex-wrap gap-1.5">
              {row.nodes.length === 0 ? (
                <span className="text-sm text-muted-foreground">
                  No nodes listed.
                </span>
              ) : (
                row.nodes.map((n) => (
                  <span
                    key={n}
                    className="rounded bg-background px-2 py-0.5 font-mono text-xs text-muted-foreground"
                  >
                    {n}
                  </span>
                ))
              )}
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  )
}
