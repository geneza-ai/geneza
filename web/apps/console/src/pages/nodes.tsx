import { useEffect, useMemo, useRef, useState } from "react"
import { useLocation, useNavigate } from "react-router-dom"
import { Search, Server } from "lucide-react"
import { toast } from "sonner"

import { api } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import { useSession } from "@/components/session-context"
import { Button, Card, Skeleton, cn } from "@geneza/ui"
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
import { NodeCvePills } from "@/components/fleet-cves"
import { riskEdgeClass, useFleetCves } from "@/hooks/use-fleet-cves"
import { useListControls } from "@/hooks/use-list-controls"
import { StatusDot } from "@/components/status-dot"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { OsIcon } from "@/components/os-icon"
import { distroFromLabels } from "@/lib/os"
import { ReapproveDialog } from "@/components/reapprove-dialog"
import { relativeTime, truncateMiddle } from "@/lib/format"
import type { NodeInfo, NodesResponse } from "@/types"

// Nodes is a live view: a tight poll keeps status, session counts and
// last-seen current without a manual refresh.
const POLL_MS = 5000
const PAGE_SIZE = 50
// The controller's maxPageLimit. Only the derived "at risk" view needs it: that
// filter is computed from the CVE rollup rather than a node column, so the whole
// fleet has to be in hand to narrow it correctly.
const MAX_PAGE = 1000

type StatusFilter = "all" | "online" | "offline" | "pending" | "atrisk"

const FILTERS: { key: StatusFilter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "online", label: "Online" },
  { key: "offline", label: "Offline" },
  { key: "pending", label: "Pending" },
  { key: "atrisk", label: "At risk" },
]

function FilterChip({
  active,
  onClick,
  children,
}: {
  active: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "rounded-[7px] border px-3 py-[7px] font-mono text-[11.5px] transition-colors",
        active
          ? "border-brand-line bg-brand-tint text-foreground"
          : "border-border text-muted-foreground hover:text-foreground"
      )}
    >
      {children}
    </button>
  )
}

export function NodesPage() {
  const { me } = useSession()
  const navigate = useNavigate()
  const location = useLocation()
  const ctl = useListControls({
    pageSize: PAGE_SIZE,
    defaultSort: "name",
    defaultOrder: "asc",
  })
  // "At risk" is derived from the workspace CVE rollup, not from a node column, so
  // the server cannot filter it. Fetch the fleet in one page for that view only and
  // narrow it here; every other filter is applied server-side where the total and
  // the rows describe the same set.
  const atRiskView = ctl.state === "atrisk"
  const { data, error, initialLoading, refresh } = usePolling<NodesResponse>(
    (s) =>
      api.getNodes(
        atRiskView
          ? { limit: MAX_PAGE }
          : {
              q: ctl.q || undefined,
              state: ctl.state === "all" ? undefined : ctl.state,
              sort: ctl.sort,
              order: ctl.order,
              limit: PAGE_SIZE,
              offset: ctl.offset,
            },
        s
      ),
    POLL_MS,
    [ctl.q, ctl.state, ctl.sort, ctl.order, ctl.offset]
  )
  const fleetCves = useFleetCves()
  const [query, setQuery] = useState(ctl.q)

  // The header's search affordance (and ⌘K) land here asking for focus.
  const searchRef = useRef<HTMLInputElement>(null)
  useEffect(() => {
    if ((location.state as { focusSearch?: boolean } | null)?.focusSearch) {
      searchRef.current?.focus()
      window.history.replaceState({}, "")
    }
  }, [location.state])

  const [busy, setBusy] = useState<string | null>(null)
  const [reapprove, setReapprove] = useState<NodeInfo | null>(null)
  async function approve(node: NodeInfo) {
    // Re-approving a quarantined node needs a recorded reason — collect it in
    // a dialog. A freshly pending node is approved in one click.
    if (node.quarantineReason) {
      setReapprove(node)
      return
    }
    setBusy(node.nodeId)
    try {
      await api.approveNode(node.nodeId, true)
      toast.success("Node approved", { description: node.name })
      refresh()
    } catch (e) {
      toast.error("Approve failed", {
        description: e instanceof Error ? e.message : String(e),
      })
    } finally {
      setBusy(null)
    }
  }

  const nodes = useMemo(() => data?.nodes ?? [], [data])
  const nodeCounts = (n: NodeInfo) =>
    fleetCves.perNode.get(n.nodeId) ?? fleetCves.perNode.get(n.name)
  const filtered = useMemo(() => {
    if (!atRiskView) return nodes
    return nodes.filter((n) => {
      const c = fleetCves.perNode.get(n.nodeId) ?? fleetCves.perNode.get(n.name)
      return !!c && (c.crit > 0 || c.high > 0)
    })
  }, [nodes, atRiskView, fleetCves.perNode])
  const total = atRiskView ? filtered.length : (data?.total ?? filtered.length)

  return (
    <div className="space-y-5">
      {/* Toolbar: fleet search + status chips */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex min-w-60 flex-1 items-center gap-2.5 rounded-[9px] border bg-card px-3.5 py-[9px]">
          <Search className="size-[15px] shrink-0 text-faint" />
          <input
            ref={searchRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") ctl.setQ(query.trim())
            }}
            onBlur={() => ctl.setQ(query.trim())}
            placeholder="Search by name, OS, or label…"
            className="w-full border-none bg-transparent font-mono text-[12.5px] text-foreground outline-none placeholder:text-faint"
          />
        </div>
        <div className="flex flex-wrap gap-[7px]">
          {FILTERS.map((f) => (
            <FilterChip
              key={f.key}
              active={ctl.state === f.key}
              onClick={() => ctl.setState(f.key)}
            >
              {f.label}
            </FilterChip>
          ))}
        </div>
      </div>

      <Card className="overflow-hidden p-0">
        {error && !data ? (
          <ErrorState message={error} onRetry={refresh} />
        ) : initialLoading ? (
          <TableSkeleton />
        ) : nodes.length === 0 ? (
          <EmptyState
            icon={<Server className="size-8" />}
            title="No nodes enrolled"
            message="Create an enrollment code under Node enrollment and run the install one-liner on a machine to see it here."
          />
        ) : filtered.length === 0 ? (
          <div className="p-10 text-center font-mono text-[13px] text-faint">
            No nodes match your filters.
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="pl-5">Node</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>OS · agent</TableHead>
                <TableHead>Vulnerabilities</TableHead>
                <TableHead>Last seen</TableHead>
                <TableHead className="pr-5" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((node) => {
                const distro = node.distro || distroFromLabels(node.labels)
                const counts = nodeCounts(node)
                return (
                  <TableRow
                    key={node.nodeId}
                    muted={!node.online}
                    className={cn(
                      "cursor-pointer border-line2 border-l-2",
                      riskEdgeClass(counts)
                    )}
                    onClick={() => navigate(`/nodes/${node.nodeId}`)}
                  >
                    <TableCell className="py-3.5 pl-5">
                      <div className="flex items-center gap-2.5">
                        <OsIcon os={node.os} distro={distro} colored={node.online} />
                        <div className="min-w-0">
                          <div className="truncate font-mono text-[13px] text-foreground">
                            {node.name}
                          </div>
                          <div className="mt-0.5 truncate font-mono text-2xs text-faint">
                            {node.overlayIp || truncateMiddle(node.nodeId)}
                          </div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="py-3.5">
                      <div className="flex items-center gap-2">
                        <StatusDot online={node.online} />
                        <span className="text-[12.5px] text-muted-foreground">
                          {node.online ? "online" : "offline"}
                        </span>
                        {!node.approved && (
                          <span
                            className="inline-flex items-center gap-1.5"
                            onClick={(e) => e.stopPropagation()}
                          >
                            {/* Quarantined and freshly-pending are very different
                                states — a binary_tamper host must not read as a
                                machine that simply has not been approved yet. The
                                cause has always been on the wire; it was only ever
                                shown after clicking approve. */}
                            {node.quarantineReason ? (
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <span className="rounded-[5px] border border-destructive/40 px-1.5 py-0.5 font-mono text-[11px] text-destructive">
                                    quarantined
                                  </span>
                                </TooltipTrigger>
                                <TooltipContent>
                                  {node.quarantineReason}
                                </TooltipContent>
                              </Tooltip>
                            ) : (
                              <span className="rounded-[5px] border border-warning/35 px-1.5 py-0.5 font-mono text-[11px] text-warning">
                                pending
                              </span>
                            )}
                            {me.admin && (
                              <Button
                                variant="chip"
                                size="chip"
                                disabled={busy === node.nodeId}
                                onClick={() => approve(node)}
                              >
                                approve
                              </Button>
                            )}
                          </span>
                        )}
                      </div>
                      {node.activeSessions > 0 && (
                        <div className="mt-0.5 font-mono text-2xs text-faint">
                          {node.activeSessions} active session
                          {node.activeSessions > 1 ? "s" : ""}
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="py-3.5">
                      <div className="text-[12.5px] text-muted-foreground">
                        {node.osPretty || node.os}
                        <span className="text-faint"> / {node.arch}</span>
                      </div>
                      <div className="mt-0.5 font-mono text-2xs text-faint">
                        {node.version ? `agent ${node.version}` : "—"}
                      </div>
                    </TableCell>
                    <TableCell className="py-3.5">
                      {fleetCves.loaded ? (
                        <NodeCvePills counts={counts} scanned={fleetCves.scanned} />
                      ) : (
                        <span className="font-mono text-2xs text-faint">…</span>
                      )}
                    </TableCell>
                    <TableCell className="py-3.5 font-mono text-[11.5px] text-muted-foreground">
                      {relativeTime(node.lastSeenUnix)}
                    </TableCell>
                    <TableCell
                      className="py-3.5 pr-5"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <div className="flex justify-end gap-1.5">
                        {node.online && (
                          <Button
                            variant="chip"
                            size="chip"
                            onClick={() =>
                              navigate(`/nodes/${node.nodeId}?tab=shell`)
                            }
                          >
                            shell
                          </Button>
                        )}
                        <Button
                          variant="chip"
                          size="chip"
                          onClick={() => navigate(`/nodes/${node.nodeId}`)}
                        >
                          open
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        )}
        {/* The pager stays mounted whenever there is a result set, including when
            the current page is empty — otherwise a filter that matches nothing on
            this page also removes the only control that could page out of it. */}
        {!atRiskView && total > 0 && (
          <Pagination
            total={total}
            pageSize={PAGE_SIZE}
            page={ctl.page}
            onPage={ctl.setPage}
            loading={false}
          />
        )}
      </Card>

      {atRiskView && (
        <p className="font-mono text-xs text-faint">
          Showing {filtered.length} at-risk node
          {filtered.length === 1 ? "" : "s"} — derived from the CVE rollup, so this
          view is not paged.
        </p>
      )}

      <ReapproveDialog
        node={reapprove}
        onClose={() => setReapprove(null)}
        onApproved={() => {
          setReapprove(null)
          refresh()
        }}
      />
    </div>
  )
}

function TableSkeleton() {
  return (
    <div className="divide-y divide-line2">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="flex items-center gap-4 px-5 py-4">
          <Skeleton className="size-2 rounded-full" />
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-4 w-16" />
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-4 w-24" />
          <Skeleton className="ml-auto h-4 w-40" />
        </div>
      ))}
    </div>
  )
}
