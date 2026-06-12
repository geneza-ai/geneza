import { useMemo, useState } from "react"
import { useNavigate } from "react-router-dom"
import { Search, Server, ShieldCheck, ShieldAlert } from "lucide-react"
import { toast } from "sonner"

import { api } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
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
import { CopyId } from "@/components/copy-id"
import { LabelTags } from "@/components/label-tags"
import { relativeTime } from "@/lib/format"
import type { NodesResponse } from "@/types"

export function MachinesPage() {
  const navigate = useNavigate()
  const { data, error, initialLoading, loading, refresh } =
    usePolling<NodesResponse>((s) => api.getNodes(s), 10000)
  const [query, setQuery] = useState("")

  const [busy, setBusy] = useState<string | null>(null)
  async function approve(nodeId: string, name: string) {
    setBusy(nodeId)
    try {
      await api.approveNode(nodeId, true)
      toast.success("Machine approved", { description: name })
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
            ? `${nodes.filter((n) => n.online).length} of ${nodes.length} machines online`
            : "Agent nodes enrolled in this cluster."
        }
        onRefresh={refresh}
        refreshing={loading}
      >
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
            title="No machines enrolled"
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
              {filtered.map((node) => (
                <TableRow
                  key={node.nodeId}
                  className="cursor-pointer"
                  onClick={() => navigate(`/machines/${node.nodeId}`)}
                >
                  <TableCell className="font-medium">{node.name}</TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <StatusDot online={node.online} />
                      <span className="text-sm">
                        {node.online ? "Online" : "Offline"}
                      </span>
                      {!node.online && (
                        <span className="text-xs text-muted-foreground">
                          {relativeTime(node.lastSeenUnix)}
                        </span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell onClick={(e) => e.stopPropagation()}>
                    {node.approved ? (
                      <span className="inline-flex items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400">
                        <ShieldCheck className="size-3.5" /> Approved
                      </span>
                    ) : (
                      <div className="flex items-center gap-2">
                        <span className="inline-flex items-center gap-1 rounded bg-amber-500/15 px-1.5 py-0.5 text-xs font-medium text-amber-600 dark:text-amber-400">
                          <ShieldAlert className="size-3.5" /> Pending
                        </span>
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-6 px-2 text-xs"
                          disabled={busy === node.nodeId}
                          onClick={() => approve(node.nodeId, node.name)}
                        >
                          Approve
                        </Button>
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
                  <TableCell className="max-w-[220px]">
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
              ))}
            </TableBody>
          </Table>
        )}
      </Card>

      {filtered.length > 0 && query && (
        <p className="text-xs text-muted-foreground">
          Showing {filtered.length} of {nodes.length}
        </p>
      )}
    </div>
  )
}

function TableSkeleton() {
  return (
    <div className="divide-y">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="flex items-center gap-4 px-3 py-3">
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
