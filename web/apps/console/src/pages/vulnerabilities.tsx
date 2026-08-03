import { useMemo, useState } from "react"
import { useSearchParams } from "react-router-dom"
import { ChevronDown, ChevronRight, Search, ShieldX } from "lucide-react"

import { api } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import { Card, Skeleton, cn } from "@geneza/ui"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { SeverityDot, StatusBadge } from "@/components/vuln-badges"
import { severityKey } from "@/lib/severity"
import { EmptyState, ErrorState } from "@/components/states"
import { Pagination } from "@/components/data-pagination"
import type { WorkspaceCVE, WorkspaceCVEsResponse } from "@/types"

const PAGE_SIZE = 50

type SevFilter = "all" | "critical" | "high" | "medium"

const SEV_FILTERS: { key: SevFilter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
]

// VulnerabilitiesPage is the fleet rollup: every CVE affecting any node in the
// workspace, with severity, the representative status, and the count of distinct
// affected nodes. A row expands to reveal the affected node list. The CVE
// filter lives in the URL so a view is bookmarkable and shareable, and is sent to
// the server so paging stays correct under the filter.
export function VulnerabilitiesPage() {
  const [params, setParams] = useSearchParams()
  const cve = params.get("cve") ?? ""

  const [term, setTerm] = useState(cve)
  const [sev, setSev] = useState<SevFilter>("all")
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

  const rows = useMemo(() => {
    const all = data?.cves ?? []
    if (sev === "all") return all
    return all.filter((r) => {
      const s = r.severity.toLowerCase()
      return sev === "medium" ? s === "medium" || s === "moderate" : s === sev
    })
  }, [data, sev])
  const total = data?.total ?? 0

  function applyFilter(next: string) {
    const q = next.trim()
    setParams(q ? { cve: q } : {}, { replace: true })
    setPage(1)
    setExpanded(null)
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <form
          className="flex min-w-60 flex-1 items-center gap-2.5 rounded-[9px] border bg-card px-3.5 py-[9px]"
          onSubmit={(e) => {
            e.preventDefault()
            applyFilter(term)
          }}
        >
          <Search className="size-[15px] shrink-0 text-faint" />
          <input
            value={term}
            onChange={(e) => setTerm(e.target.value)}
            placeholder="Search by CVE id…"
            className="w-full border-none bg-transparent font-mono text-[12.5px] text-foreground outline-none placeholder:text-faint"
          />
        </form>
        <div className="flex flex-wrap gap-[7px]">
          {SEV_FILTERS.map((f) => (
            <button
              key={f.key}
              onClick={() => setSev(f.key)}
              className={cn(
                "rounded-[7px] border px-3 py-[7px] font-mono text-[11.5px] transition-colors",
                sev === f.key
                  ? "border-brand-line bg-brand-tint text-foreground"
                  : "border-border text-muted-foreground hover:text-foreground"
              )}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      <Card className="overflow-hidden p-0">
        {error && !data ? (
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
        ) : rows.length === 0 ? (
          <div className="p-10 text-center font-mono text-[13px] text-faint">
            No vulnerabilities match your filters.
          </div>
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-8 pl-5" />
                  <TableHead>CVE</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Fixed in</TableHead>
                  <TableHead>Affected</TableHead>
                  <TableHead className="pr-5">State</TableHead>
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
  const key = severityKey(row.severity)
  return (
    <>
      <TableRow className="cursor-pointer" onClick={onToggle}>
        <TableCell className="py-3.5 pl-5 text-faint">
          {open ? (
            <ChevronDown className="size-4" />
          ) : (
            <ChevronRight className="size-4" />
          )}
        </TableCell>
        <TableCell className="py-3.5">
          <span className="flex items-center gap-2.5">
            <SeverityDot severity={row.severity} />
            <span className="font-mono text-xs font-medium">{row.cve}</span>
          </span>
        </TableCell>
        <TableCell
          className={cn(
            "py-3.5 font-mono text-[11.5px] lowercase",
            key === "sev-crit" && "text-sev-crit",
            key === "sev-high" && "text-sev-high",
            key === "sev-med" && "text-sev-med",
            key === "sev-low" && "text-sev-low",
            !key && "text-muted-foreground"
          )}
        >
          {row.severity || "—"}
        </TableCell>
        <TableCell className="py-3.5 font-mono text-xs text-muted-foreground">
          {row.fixedVersion || <span className="text-faint">—</span>}
        </TableCell>
        <TableCell className="py-3.5 font-mono text-[11.5px] text-brand">
          {row.nodeCount} node{row.nodeCount === 1 ? "" : "s"}
        </TableCell>
        <TableCell className="py-3.5 pr-5">
          <StatusBadge status={row.status} />
        </TableCell>
      </TableRow>
      {open && (
        <TableRow className="bg-muted/30 hover:bg-muted/30">
          <TableCell className="pl-5" />
          <TableCell colSpan={5} className="py-3">
            <div className="flex flex-wrap gap-1.5">
              {row.nodes.length === 0 ? (
                <span className="font-mono text-[13px] text-faint">
                  No nodes listed.
                </span>
              ) : (
                row.nodes.map((n) => (
                  <span
                    key={n}
                    className="rounded-full border bg-elev px-2.5 py-1 font-mono text-[11.5px] text-muted-foreground"
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
