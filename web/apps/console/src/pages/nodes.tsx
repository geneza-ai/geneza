import { useMemo, useState } from "react"
import { useNavigate } from "react-router-dom"
import { Search, Server, ShieldAlert, ShieldCheck } from "lucide-react"
import { toast } from "sonner"

import { api } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import { useSession } from "@/components/session-context"
import { Card } from "@geneza/ui"
import { Button } from "@geneza/ui"
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
import { EmptyState, ErrorState } from "@/components/states"
import { PageToolbar } from "@/components/page-toolbar"
import { StatusDot } from "@/components/status-dot"
import { OsIcon } from "@/components/os-icon"
import { distroFromLabels } from "@/lib/os"
import { CopyId } from "@/components/copy-id"
import { LabelTags } from "@/components/label-tags"
import { ReapproveDialog } from "@/components/reapprove-dialog"
import { relativeTime } from "@/lib/format"
import type { NodeInfo, NodesResponse } from "@/types"

// Nodes is a live view: a tight poll keeps status, session counts and
// last-seen current without a manual refresh.
const POLL_MS = 5000

export function NodesPage() {
  const { me } = useSession()
  const navigate = useNavigate()
  const { data, error, initialLoading, loading, refresh } =
    usePolling<NodesResponse>((s) => api.getNodes(undefined, s), POLL_MS)
  const [query, setQuery] = useState("")

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
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return nodes
    return nodes.filter((n) => {
      if (n.name.toLowerCase().includes(q)) return true
      if (n.nodeId.toLowerCase().includes(q)) return true
      return Object.entries(n.labels).some(
        ([k, v]) =>
          k.toLowerCase().includes(q) || v.toLowerCase().includes(q)
      )
    })
  }, [nodes, query])

  return (
    <div className="space-y-4">
      <PageToolbar
        description={
          data
            ? `${nodes.filter((n) => n.online).length} of ${nodes.length} nodes online`
            : "Agent nodes enrolled in this cluster."
        }
        onRefresh={refresh}
        refreshing={loading}
      >
        <span className="hidden items-center gap-1.5 text-xs text-muted-foreground sm:inline-flex">
          <StatusDot online pulse className="size-1.5" />
          Live
        </span>
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search name or label…"
            className="w-56 pl-8"
          />
        </div>
      </PageToolbar>

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
          <EmptyState
            title="No matches"
            message={`Nothing matches “${query}”.`}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-6 pr-0" />
                <TableHead>Name</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Admission</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>OS / Arch</TableHead>
                <TableHead>Labels</TableHead>
                <TableHead className="text-center">Sessions</TableHead>
                <TableHead>Node ID</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((node) => {
                const distro = node.distro || distroFromLabels(node.labels)
                return (
                  <TableRow
                    key={node.nodeId}
                    muted={!node.online}
                    className="cursor-pointer"
                    onClick={() => navigate(`/nodes/${node.nodeId}`)}
                  >
                    {/* Leading status rail: a dot for online nodes, blank for
                        offline — the greyed row already carries "offline". */}
                    <TableCell className="pr-0">
                      {node.online && <StatusDot online />}
                    </TableCell>
                    <TableCell className="font-medium">
                      <span className="flex items-center gap-2">
                        <OsIcon
                          os={node.os}
                          distro={distro}
                          colored={node.online}
                        />
                        {node.name}
                      </span>
                    </TableCell>
                    <TableCell className="text-sm">
                      {node.online ? (
                        "Online"
                      ) : (
                        <span className="text-muted-foreground">
                          Offline · {relativeTime(node.lastSeenUnix)}
                        </span>
                      )}
                    </TableCell>
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      {node.approved ? (
                        <span className="inline-flex items-center gap-1 text-xs text-success">
                          <ShieldCheck className="size-3.5" /> Approved
                        </span>
                      ) : (
                        <div className="flex items-center gap-2">
                          <span className="inline-flex items-center gap-1 rounded bg-warning/15 px-1.5 py-0.5 text-xs font-medium text-warning">
                            <ShieldAlert className="size-3.5" /> Pending
                          </span>
                          {me.admin && (
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-6 px-2 text-xs"
                              disabled={busy === node.nodeId}
                              onClick={() => approve(node)}
                            >
                              Approve
                            </Button>
                          )}
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {node.version || "—"}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {node.os}
                      <span className="text-muted-foreground/60"> / </span>
                      {node.arch}
                    </TableCell>
                    <TableCell className="max-w-56">
                      <LabelTags labels={node.labels} max={3} />
                    </TableCell>
                    <TableCell className="text-center tabular-nums">
                      <span title="active">{node.activeSessions}</span>
                      {node.detachedSessions > 0 && (
                        <span
                          className="text-muted-foreground"
                          title="detached"
                        >
                          {" "}
                          / {node.detachedSessions}
                        </span>
                      )}
                    </TableCell>
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <CopyId value={node.nodeId} label="Node ID copied" />
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        )}
      </Card>

      {filtered.length > 0 && query && (
        <p className="text-xs text-muted-foreground">
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
    <div className="divide-y">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="flex items-center gap-4 px-3 py-2.5">
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
