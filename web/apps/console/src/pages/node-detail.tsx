import { useEffect, useMemo, useState } from "react"
import { Link, useParams } from "react-router-dom"
import {
  ArrowLeft,
  Power,
  TerminalSquare,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
} from "lucide-react"
import { toast } from "sonner"

import { api, ApiError } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import { useSession } from "@/components/session-context"
import { Button } from "@geneza/ui"
import { Card, CardContent } from "@geneza/ui"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { StatusDot } from "@/components/status-dot"
import { OsIcon } from "@/components/os-icon"
import { distroFromLabels } from "@/lib/os"
import { CopyId } from "@/components/copy-id"
import { LabelTags } from "@/components/label-tags"
import { ReapproveDialog } from "@/components/reapprove-dialog"
import { ActionBadge, StateBadge } from "@/components/session-badges"
import { NodeMetricsGrid } from "@/components/node-metrics"
import { NodeVulnerabilities } from "@/components/node-vulnerabilities"
import { NodeComponentsList } from "@/components/node-components"
import { WebShell } from "@/components/web-shell"
import { ErrorState } from "@/components/states"
import { RANGES } from "@/components/node-metrics"
import { relativeTime } from "@/lib/format"
import type { NodeInfo, NodesResponse, SessionInfo, SessionsResponse } from "@/types"

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs uppercase tracking-wide text-muted-foreground">
        {label}
      </span>
      <span className="text-sm">{children}</span>
    </div>
  )
}

export function NodeDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { me } = useSession()
  const { data, error, refresh } = usePolling<NodesResponse>(
    (s) => api.getNodes(undefined, s),
    10000
  )
  const fresh = useMemo<NodeInfo | undefined>(
    () => data?.nodes.find((n) => n.nodeId === id),
    [data, id]
  )
  // Hold the last-seen node so a transient poll (empty list, refetch) never
  // collapses the page to "loading" and tears down a live terminal/tab.
  const [node, setNode] = useState<NodeInfo | undefined>(fresh)
  useEffect(() => {
    if (fresh) setNode(fresh)
  }, [fresh])

  const [rangeSec, setRangeSec] = useState(RANGES[1].sec)
  const [monOn, setMonOn] = useState<boolean | null>(null)
  const [busy, setBusy] = useState(false)
  const [reapprove, setReapprove] = useState(false)

  useEffect(() => {
    if (!node) return
    let active = true
    api
      .getNodeModules(node.nodeId)
      .then((r) =>
        active &&
        // modules is null when none are configured yet — guard before .some so
        // the fetch resolves (otherwise monOn stays null and the toggle is
        // permanently disabled).
        setMonOn((r.modules ?? []).some((m) => m.name === "node-exporter" && m.enabled))
      )
      .catch(() => active && setMonOn(null))
    return () => {
      active = false
    }
  }, [node])

  async function toggleMonitoring() {
    if (!node) return
    setBusy(true)
    const next = !monOn
    try {
      await api.setNodeModules(node.nodeId, [{ name: "node-exporter", enabled: next }])
      setMonOn(next)
      toast.success(next ? "Monitoring enabled" : "Monitoring disabled", {
        description: node.name,
      })
    } catch (err) {
      toast.error("Failed to update monitoring", {
        description: err instanceof ApiError ? err.message : String(err),
      })
    } finally {
      setBusy(false)
    }
  }

  async function setApproval(approve: boolean) {
    if (!node) return
    // Re-approving a quarantined node needs a recorded reason — collect it in
    // a dialog. Fresh pending approval and quarantine are one click.
    if (approve && node.quarantineReason) {
      setReapprove(true)
      return
    }
    setBusy(true)
    try {
      await api.approveNode(node.nodeId, approve)
      toast.success(approve ? "Node approved" : "Node quarantined", {
        description: node.name,
      })
      refresh()
    } catch (err) {
      toast.error("Failed to update admission", {
        description: err instanceof ApiError ? err.message : String(err),
      })
    } finally {
      setBusy(false)
    }
  }

  if (error && !data) {
    return <ErrorState message={error} />
  }
  if (!node) {
    return (
      <div className="space-y-4">
        <BackLink />
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            {data ? "Node not found." : "Loading…"}
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <BackLink />
      <ReapproveDialog
        node={reapprove ? node : null}
        onClose={() => setReapprove(false)}
        onApproved={() => {
          setReapprove(false)
          refresh()
        }}
      />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <StatusDot online={node.online} />
          <OsIcon
            os={node.os}
            distro={node.distro || distroFromLabels(node.labels)}
            colored={node.online}
            className="size-5"
          />
          <h1 className="text-xl font-semibold">{node.name}</h1>
          <span className="text-sm text-muted-foreground">
            {node.online ? "Online" : `Offline · ${relativeTime(node.lastSeenUnix)}`}
          </span>
          {!node.approved && (
            <span className="inline-flex items-center gap-1 rounded bg-warning/15 px-1.5 py-0.5 text-xs font-medium text-warning">
              <ShieldAlert className="size-3.5" /> Pending approval
            </span>
          )}
        </div>
        {me.admin && (
          <div className="flex items-center gap-2">
            {node.approved ? (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setApproval(false)}
                disabled={busy}
              >
                <ShieldAlert className="size-4" />
                Quarantine
              </Button>
            ) : (
              <Button size="sm" onClick={() => setApproval(true)} disabled={busy}>
                <ShieldCheck className="size-4" />
                Approve
              </Button>
            )}
            <Button
              variant={monOn ? "outline" : "default"}
              size="sm"
              onClick={toggleMonitoring}
              disabled={busy || monOn === null}
            >
              <Power className="size-4" />
              {monOn ? "Disable monitoring" : "Enable monitoring"}
            </Button>
          </div>
        )}
      </div>

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="metrics">Metrics</TabsTrigger>
          <TabsTrigger value="sessions">Sessions</TabsTrigger>
          <TabsTrigger value="vulnerabilities">
            <ShieldX className="size-4" />
            Vulnerabilities
          </TabsTrigger>
          <TabsTrigger value="inventory">Inventory</TabsTrigger>
          {node.online && (
            <TabsTrigger value="shell">
              <TerminalSquare className="size-4" />
              Shell
            </TabsTrigger>
          )}
        </TabsList>

        <TabsContent value="overview" className="mt-4">
          <Card>
            <CardContent className="grid gap-5 py-5 sm:grid-cols-2 lg:grid-cols-3">
              <Field label="Node ID">
                <CopyId value={node.nodeId} label="Node ID copied" />
              </Field>
              <Field label="Version">
                <span className="font-mono text-xs">{node.version || "—"}</span>
              </Field>
              <Field label="Platform">
                {node.osPretty || node.os} / {node.arch}
              </Field>
              <Field label="Sessions">
                {node.activeSessions} active
                {node.detachedSessions > 0 && ` · ${node.detachedSessions} detached`}
              </Field>
              <Field label="Last seen">{relativeTime(node.lastSeenUnix)}</Field>
              <Field label="Monitoring">
                {monOn === null ? "—" : monOn ? "Enabled" : "Disabled"}
              </Field>
              <Field label="Admission">
                {node.approved ? (
                  <span className="inline-flex items-center gap-1 text-success">
                    <ShieldCheck className="size-3.5" /> Approved
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 text-warning">
                    <ShieldAlert className="size-3.5" /> Pending
                  </span>
                )}
              </Field>
              <Field label="DNS name">
                <span className="font-mono text-xs">{node.name}.geneza</span>
              </Field>
              <Field label="Overlay IP">
                <span className="font-mono text-xs">{node.overlayIp || "—"}</span>
              </Field>
              <div className="sm:col-span-2 lg:col-span-3">
                <Field label="Labels">
                  <LabelTags labels={node.labels} max={12} />
                </Field>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="metrics" className="mt-4 space-y-4">
          <div className="flex justify-end">
            <Select value={String(rangeSec)} onValueChange={(v) => setRangeSec(Number(v))}>
              <SelectTrigger className="w-36">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {RANGES.map((r) => (
                  <SelectItem key={r.sec} value={String(r.sec)}>
                    {r.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <NodeMetricsGrid node={node.name} rangeSec={rangeSec} />
        </TabsContent>

        <TabsContent value="sessions" className="mt-4">
          <NodeSessions nodeId={node.nodeId} admin={me.admin} />
        </TabsContent>

        <TabsContent value="vulnerabilities" className="mt-4">
          <NodeVulnerabilities nodeId={node.nodeId} />
        </TabsContent>

        <TabsContent value="inventory" className="mt-4">
          <NodeComponentsList nodeId={node.nodeId} />
        </TabsContent>

        {node.online && (
          <TabsContent value="shell" className="mt-4">
            <WebShell nodeId={node.nodeId} nodeName={node.name} />
          </TabsContent>
        )}
      </Tabs>
    </div>
  )
}

function BackLink() {
  return (
    <Link
      to="/nodes"
      className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground"
    >
      <ArrowLeft className="size-4" />
      Nodes
    </Link>
  )
}

const KICKABLE = new Set(["active", "detached", "pending"])

function NodeSessions({ nodeId, admin }: { nodeId: string; admin: boolean }) {
  const { data, refresh } = usePolling<SessionsResponse>(
    (s) => api.getSessions(undefined, s),
    10000
  )
  const sessions = useMemo(
    () => (data?.sessions ?? []).filter((s) => s.nodeId === nodeId),
    [data, nodeId]
  )

  async function revoke(s: SessionInfo) {
    try {
      await api.revokeSession(s.sessionId)
      toast.success("Session revoked", { description: s.user })
      refresh()
    } catch (err) {
      toast.error("Revoke failed", {
        description: err instanceof ApiError ? err.message : String(err),
      })
    }
  }

  if (sessions.length === 0) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-sm text-muted-foreground">
          No sessions on this node.
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="overflow-hidden p-0">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>User</TableHead>
            <TableHead>Action</TableHead>
            <TableHead>State</TableHead>
            <TableHead>Started</TableHead>
            {admin && <TableHead className="text-right">Manage</TableHead>}
          </TableRow>
        </TableHeader>
        <TableBody>
          {sessions.map((s) => (
            <TableRow key={s.sessionId}>
              <TableCell className="text-sm">{s.user}</TableCell>
              <TableCell>
                <ActionBadge action={s.action} />
              </TableCell>
              <TableCell>
                <StateBadge state={s.state} />
              </TableCell>
              <TableCell className="text-sm text-muted-foreground">
                {relativeTime(s.startedUnix)}
              </TableCell>
              {admin && (
                <TableCell className="text-right">
                  {KICKABLE.has(s.state) && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                      onClick={() => revoke(s)}
                    >
                      Revoke
                    </Button>
                  )}
                </TableCell>
              )}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Card>
  )
}
