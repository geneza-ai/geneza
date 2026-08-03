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
import { NodeCvePills } from "@/components/fleet-cves"
import { riskEdgeClass, useFleetCves } from "@/hooks/use-fleet-cves"
import { StatusDot } from "@/components/status-dot"
import { OsIcon } from "@/components/os-icon"
import { distroFromLabels } from "@/lib/os"
import { ReapproveDialog } from "@/components/reapprove-dialog"
import { relativeTime, truncateMiddle } from "@/lib/format"
import type { NodeInfo, NodesResponse } from "@/types"

// Nodes is a live view: a tight poll keeps status, session counts and
// last-seen current without a manual refresh.
const POLL_MS = 5000

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
  const { data, error, initialLoading, refresh } =
    usePolling<NodesResponse>((s) => api.getNodes(undefined, s), POLL_MS)
  const fleetCves = useFleetCves()
  const [query, setQuery] = useState("")
  const [status, setStatus] = useState<StatusFilter>("all")

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
    const q = query.trim().toLowerCase()
    let out = nodes
    if (q) {
      out = out.filter((n) => {
        if (n.name.toLowerCase().includes(q)) return true
        if (n.nodeId.toLowerCase().includes(q)) return true
        if (n.os.toLowerCase().includes(q)) return true
        if ((n.overlayIp ?? "").toLowerCase().includes(q)) return true
        return Object.entries(n.labels).some(
          ([k, v]) => k.toLowerCase().includes(q) || v.toLowerCase().includes(q)
        )
      })
    }
    switch (status) {
      case "online":
        return out.filter((n) => n.online)
      case "offline":
        return out.filter((n) => !n.online)
      case "pending":
        return out.filter((n) => !n.approved)
      case "atrisk":
        return out.filter((n) => {
          const c = nodeCounts(n)
          return !!c && (c.crit > 0 || c.high > 0)
        })
      default:
        return out
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, query, status, fleetCves.perNode])

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
            placeholder="Search by name, OS, IP, or label…"
            className="w-full border-none bg-transparent font-mono text-[12.5px] text-foreground outline-none placeholder:text-faint"
          />
        </div>
        <div className="flex flex-wrap gap-[7px]">
          {FILTERS.map((f) => (
            <FilterChip
              key={f.key}
              active={status === f.key}
              onClick={() => setStatus(f.key)}
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
            message="Mint a join token under Access Tokens and enroll an agent to see it here."
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
                            <span className="rounded-[5px] border border-warning/35 px-1.5 py-0.5 font-mono text-[11px] text-warning">
                              pending
                            </span>
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
                        <NodeCvePills counts={counts} />
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
      </Card>

      {filtered.length > 0 && query && (
        <p className="font-mono text-xs text-faint">
          Showing {filtered.length} of {nodes.length}
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
