import { useEffect, useMemo, useState } from "react"
import { useNavigate, useParams, useSearchParams } from "react-router-dom"
import { Download, ShieldAlert, ShieldCheck, Trash2 } from "lucide-react"
import { toast } from "sonner"

import { api, ApiError } from "@/api"
import { setNodeModuleMerged } from "@/lib/modules"
import { usePolling } from "@/hooks/use-polling"
import { useSession } from "@/components/session-context"
import { Button, Card, CardContent, cn } from "@geneza/ui"
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
import { CardLabel } from "@/components/card-label"
import { usePageHeader } from "@/components/layout/page-header-context"
import { useFleetCves } from "@/hooks/use-fleet-cves"
import { StatusDot } from "@/components/status-dot"
import { OsIcon } from "@/components/os-icon"
import { distroFromLabels } from "@/lib/os"
import { CopyId } from "@/components/copy-id"
import { LabelTags } from "@/components/label-tags"
import { ReapproveDialog } from "@/components/reapprove-dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { ActionBadge, StateBadge } from "@/components/session-badges"
import { NodeMetricsGrid } from "@/components/node-metrics"
import { NodeVulnerabilities } from "@/components/node-vulnerabilities"
import { NodeComponentsList } from "@/components/node-components"
import { WebShell } from "@/components/web-shell"
import { ErrorState } from "@/components/states"
import { RANGES } from "@/components/node-metrics"
import { relativeTime, saveBlob } from "@/lib/format"
import type { NodeInfo, SessionInfo, SessionsResponse } from "@/types"

// One mono-labelled detail entry in the design's Details card.
function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="mb-1 font-mono text-2xs text-faint">{label}</div>
      <div className="text-[13.5px]">{children}</div>
    </div>
  )
}

// The count pill riding a tab label (sessions, CVEs).
function TabCount({ children }: { children: React.ReactNode }) {
  return (
    <span className="rounded-full border bg-elev px-[7px] py-px font-mono text-2xs font-normal text-muted-foreground group-data-[state=active]:bg-brand-tint">
      {children}
    </span>
  )
}

export function NodeDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { me } = useSession()
  const [params, setParams] = useSearchParams()
  const tab = params.get("tab") ?? "overview"
  const setTab = (v: string) =>
    setParams(v === "overview" ? {} : { tab: v }, { replace: true })

  // Fetch THIS node, not the fleet. This used to poll the node list every 10s and
  // search it for the id, so past the first page a node that plainly exists
  // rendered "Node not found." — and every open detail page pulled the whole
  // fleet's worth of rows on a tight loop to read one of them.
  const { data, error, refresh } = usePolling<NodeInfo>(
    (s) => api.getNode(id ?? "", s),
    10000,
    [id]
  )
  const fleetCves = useFleetCves()
  const fresh = data ?? undefined
  // Hold the last-seen node so a transient poll (empty list, refetch) never
  // collapses the page to "loading" and tears down a live terminal/tab.
  const [node, setNode] = useState<NodeInfo | undefined>(fresh)
  useEffect(() => {
    if (fresh) setNode(fresh)
  }, [fresh])

  usePageHeader(node?.name ?? null, node ? `Nodes / ${node.name}` : undefined)

  const [rangeSec, setRangeSec] = useState(RANGES[1].sec)
  const [monOn, setMonOn] = useState<boolean | null>(null)
  const [busy, setBusy] = useState(false)
  const navigate = useNavigate()
  const [reapprove, setReapprove] = useState(false)
  const [quarantine, setQuarantine] = useState(false)
  const [retire, setRetire] = useState(false)
  const [quarantineReason, setQuarantineReason] = useState("")

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
      await setNodeModuleMerged(node.nodeId, "node-exporter", next)
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

  async function setApproval(approve: boolean, reason?: string) {
    if (!node) return
    // Re-approving a quarantined node needs a recorded reason — collect it in
    // a dialog. Fresh pending approval is one click.
    if (approve && node.quarantineReason) {
      setReapprove(true)
      return
    }
    setBusy(true)
    try {
      await api.approveNode(node.nodeId, approve, reason)
      toast.success(approve ? "Node approved" : "Node quarantined", {
        description: node.name,
      })
      setQuarantine(false)
      refresh()
    } catch (err) {
      toast.error("Failed to update admission", {
        description: err instanceof ApiError ? err.message : String(err),
      })
    } finally {
      setBusy(false)
    }
  }

  // Retiring deletes the node's record; it must re-enroll to come back. The route
  // and client have existed all along with no caller, so the console could approve
  // and quarantine a node but never remove one.
  async function retireNode() {
    if (!node) return
    setBusy(true)
    try {
      await api.removeNode(node.nodeId)
      toast.success("Node retired", {
        description: `${node.name} must re-enroll to return.`,
      })
      navigate("/nodes")
    } catch (err) {
      toast.error("Failed to retire node", {
        description: err instanceof ApiError ? err.message : String(err),
      })
      setBusy(false)
    }
  }

  // The CycloneDX SBOM and the OpenVEX findings are exactly what `geneza node
  // inventory export [--vex]` produces; both routes were already served.
  async function exportDocument(kind: "sbom" | "findings.vex") {
    if (!node) return
    try {
      const { blob, filename } = await api.downloadNodeDocument(node.nodeId, kind)
      saveBlob(blob, filename)
    } catch (err) {
      toast.error("Export failed", {
        description: err instanceof ApiError ? err.message : String(err),
      })
    }
  }

  if (error && !data) {
    return <ErrorState message={error} />
  }
  if (!node) {
    return (
      <Card>
        <CardContent className="py-10 text-center font-mono text-[13px] text-faint">
          {data ? "Node not found." : "Loading…"}
        </CardContent>
      </Card>
    )
  }

  const counts = fleetCves.perNode.get(node.nodeId) ?? fleetCves.perNode.get(node.name)
  const cveTotal = counts ? counts.crit + counts.high + counts.med : 0
  const sessionTotal = node.activeSessions + node.detachedSessions

  return (
    <div>
      <ReapproveDialog
        node={reapprove ? node : null}
        onClose={() => setReapprove(false)}
        onApproved={() => {
          setReapprove(false)
          refresh()
        }}
      />

      {/* Quarantining kills live sessions, so it collects the reason the audit
          log records — the same --reason the CLI takes. It used to be one
          unconfirmed click with no cause captured. */}
      <Dialog
        open={quarantine}
        onOpenChange={(open) => !open && !busy && setQuarantine(false)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Quarantine {node.name}?</DialogTitle>
            <DialogDescription>
              This revokes the node's approval and immediately kills its live
              sessions. It stays enrolled and can be re-approved.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-1.5">
            <Label htmlFor="qreason">Reason</Label>
            <Input
              id="qreason"
              value={quarantineReason}
              onChange={(e) => setQuarantineReason(e.target.value)}
              placeholder="why this node is being quarantined"
            />
            <p className="text-xs text-muted-foreground">
              Recorded in the audit log and shown on the node until it is
              re-approved.
            </p>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setQuarantine(false)}
              disabled={busy}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => setApproval(false, quarantineReason)}
              disabled={busy || !quarantineReason.trim()}
            >
              {busy ? "Quarantining…" : "Quarantine node"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={retire}
        onOpenChange={(open) => !open && !busy && setRetire(false)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Retire {node.name}?</DialogTitle>
            <DialogDescription>
              This deletes the node's record entirely — its inventory, verdicts
              and history go with it. The machine must enroll again with a new
              code to come back. To merely block access, quarantine it instead.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setRetire(false)}
              disabled={busy}
            >
              Cancel
            </Button>
            <Button variant="destructive" onClick={retireNode} disabled={busy}>
              {busy ? "Retiring…" : "Retire node"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Identity header */}
      <div className="mb-5 flex flex-wrap items-start justify-between gap-5">
        <div className="min-w-0">
          <div className="mb-2 flex items-center gap-3">
            <StatusDot online={node.online} />
            <OsIcon
              os={node.os}
              distro={node.distro || distroFromLabels(node.labels)}
              colored={node.online}
              className="size-5"
            />
            <h2 className="truncate font-serif text-[26px] font-medium tracking-tight">
              {node.name}
            </h2>
            <span className="rounded-[5px] border px-2 py-0.5 font-mono text-[11.5px] text-muted-foreground">
              {node.online ? "online" : "offline"}
            </span>
            {!node.approved && (
              <span className="rounded-[5px] border border-warning/35 px-2 py-0.5 font-mono text-[11.5px] text-warning">
                pending approval
              </span>
            )}
          </div>
          <div className="truncate font-mono text-xs text-faint">
            geneza://node/{node.name}
            {node.overlayIp && ` · ${node.overlayIp}`} · {node.osPretty || node.os} /{" "}
            {node.arch}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {node.online && (
            <Button size="sm" onClick={() => setTab("shell")}>
              Open shell
            </Button>
          )}
          {me.admin && (
            <>
              {node.approved ? (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setQuarantine(true)}
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
                variant="outline"
                size="sm"
                onClick={toggleMonitoring}
                disabled={busy || monOn === null}
              >
                {monOn ? "Disable monitoring" : "Enable monitoring"}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setRetire(true)}
                disabled={busy}
              >
                <Trash2 className="size-4" />
                Retire
              </Button>
            </>
          )}
        </div>
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="mb-5">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="metrics">Metrics</TabsTrigger>
          <TabsTrigger value="sessions">
            Sessions
            {sessionTotal > 0 && <TabCount>{sessionTotal}</TabCount>}
          </TabsTrigger>
          <TabsTrigger value="vulnerabilities">
            Vulnerabilities
            {cveTotal > 0 && <TabCount>{cveTotal}</TabCount>}
          </TabsTrigger>
          <TabsTrigger value="inventory">Inventory</TabsTrigger>
          {node.online && <TabsTrigger value="shell">Shell</TabsTrigger>}
        </TabsList>

        <TabsContent value="overview">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1.4fr_1fr]">
            <div className="flex flex-col gap-4">
              <Card className="p-5">
                <CardLabel className="mb-4">Details</CardLabel>
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <Field label="operating system">
                    {node.osPretty || node.os} / {node.arch}
                  </Field>
                  <Field label="agent version">
                    <span className="font-mono text-[13px]">
                      {node.version || "—"}
                    </span>
                  </Field>
                  <Field label="overlay address">
                    <span className="font-mono text-[13px]">
                      {node.overlayIp || "—"}
                    </span>
                  </Field>
                  <Field label="dns name">
                    <span className="font-mono text-[13px]">{node.name}.geneza</span>
                  </Field>
                  <Field label="last seen">{relativeTime(node.lastSeenUnix)}</Field>
                  <Field label="monitoring">
                    {monOn === null ? "—" : monOn ? "enabled" : "disabled"}
                  </Field>
                  <Field label="admission">
                    {node.approved ? (
                      <span className="inline-flex items-center gap-1 text-success">
                        <ShieldCheck className="size-3.5" /> approved
                      </span>
                    ) : node.quarantineReason ? (
                      <span className="inline-flex flex-wrap items-center gap-1 text-destructive">
                        <ShieldAlert className="size-3.5" /> quarantined
                        <span className="text-muted-foreground">
                          ({node.quarantineReason})
                        </span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-warning">
                        <ShieldAlert className="size-3.5" /> pending
                      </span>
                    )}
                  </Field>
                  <Field label="node id">
                    <CopyId value={node.nodeId} label="Node ID copied" />
                  </Field>
                  <div className="sm:col-span-2">
                    <div className="mb-1.5 font-mono text-2xs text-faint">labels</div>
                    <LabelTags labels={node.labels} max={12} />
                  </div>
                </div>
              </Card>

              <Card className="p-5">
                <div className="mb-4 flex items-center justify-between">
                  <CardLabel>Exposure</CardLabel>
                  <button
                    onClick={() => setTab("vulnerabilities")}
                    className="font-mono text-[11px] text-brand hover:underline"
                  >
                    view CVEs →
                  </button>
                </div>
                {!fleetCves.loaded ? (
                  <p className="font-mono text-xs text-faint">scanning…</p>
                ) : cveTotal === 0 ? (
                  <p className="font-mono text-[13px] text-success">
                    ✓ No known open vulnerabilities on this node.
                  </p>
                ) : (
                  <div className="flex gap-6">
                    {[
                      { n: counts?.crit ?? 0, label: "critical", cls: "text-sev-crit" },
                      { n: counts?.high ?? 0, label: "high", cls: "text-sev-high" },
                      { n: counts?.med ?? 0, label: "medium", cls: "text-sev-med" },
                    ].map((s) => (
                      <div key={s.label}>
                        <div
                          className={cn(
                            "font-serif text-3xl font-medium leading-none",
                            s.cls
                          )}
                        >
                          {s.n}
                        </div>
                        <div className="mt-1.5 font-mono text-2xs text-faint">
                          {s.label}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            </div>

            <div className="flex flex-col gap-4">
              {node.activeSessions > 0 && (
                <Card className="border-brand-line p-5">
                  <div className="mb-3 flex items-center gap-2 font-mono">
                    <span className="size-[7px] rounded-full bg-brand animate-live-pulse" />
                    <span className="text-[11px] text-brand">
                      live session{node.activeSessions > 1 ? "s" : ""}
                    </span>
                  </div>
                  <div className="font-mono text-xs leading-[1.7] text-muted-foreground">
                    {node.activeSessions} active
                    {node.detachedSessions > 0 && (
                      <>
                        <br />
                        <span className="text-faint">
                          {node.detachedSessions} detached
                        </span>
                      </>
                    )}
                  </div>
                  <Button
                    variant="outline"
                    className="mt-3.5 w-full"
                    size="sm"
                    onClick={() => setTab("sessions")}
                  >
                    View sessions
                  </Button>
                </Card>
              )}

              <Card className="p-5">
                <CardLabel className="mb-3.5">Quick actions</CardLabel>
                <div className="flex flex-col gap-2">
                  {node.online && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="w-full justify-start"
                      onClick={() => setTab("shell")}
                    >
                      Open shell
                    </Button>
                  )}
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full justify-start"
                    onClick={() => setTab("sessions")}
                  >
                    View sessions
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full justify-start"
                    onClick={() => setTab("metrics")}
                  >
                    View metrics
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full justify-start"
                    onClick={() => setTab("inventory")}
                  >
                    Browse inventory
                  </Button>
                </div>
              </Card>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="metrics" className="space-y-4">
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

        <TabsContent value="sessions">
          <NodeSessions nodeId={node.nodeId} admin={me.admin} />
        </TabsContent>

        <TabsContent value="vulnerabilities">
          <NodeVulnerabilities nodeId={node.nodeId} />
        </TabsContent>

        <TabsContent value="inventory">
          <div className="mb-3 flex flex-wrap justify-end gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => exportDocument("sbom")}
            >
              <Download className="size-4" />
              CycloneDX SBOM
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => exportDocument("findings.vex")}
            >
              <Download className="size-4" />
              OpenVEX findings
            </Button>
          </div>
          <NodeComponentsList nodeId={node.nodeId} />
        </TabsContent>

        {node.online && (
          <TabsContent value="shell">
            <WebShell nodeId={node.nodeId} nodeName={node.name} />
          </TabsContent>
        )}
      </Tabs>
    </div>
  )
}

const KICKABLE = new Set(["active", "detached", "pending"])

function NodeSessions({ nodeId, admin }: { nodeId: string; admin: boolean }) {
  // Ask the server for THIS node's sessions. Fetching the workspace's first page
  // and grepping it meant the tab body and the tab's own count badge could disagree
  // — two numbers on one screen, both derived from the same fetch.
  const { data, refresh } = usePolling<SessionsResponse>(
    (s) => api.getSessions({ q: nodeId, limit: 100 }, s),
    10000,
    [nodeId]
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
        <CardContent className="py-9 text-center font-mono text-[13px] text-faint">
          No sessions on this node.
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="overflow-hidden p-0">
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className="pl-5">User</TableHead>
            <TableHead>Action</TableHead>
            <TableHead>State</TableHead>
            <TableHead>Started</TableHead>
            {admin && <TableHead className="pr-5 text-right">Manage</TableHead>}
          </TableRow>
        </TableHeader>
        <TableBody>
          {sessions.map((s) => (
            <TableRow key={s.sessionId}>
              <TableCell className="py-3 pl-5 text-sm">{s.user}</TableCell>
              <TableCell className="py-3">
                <ActionBadge action={s.action} />
              </TableCell>
              <TableCell className="py-3">
                <StateBadge state={s.state} />
              </TableCell>
              <TableCell className="py-3 font-mono text-[11.5px] text-muted-foreground">
                {relativeTime(s.startedUnix)}
              </TableCell>
              {admin && (
                <TableCell className="py-3 pr-5 text-right">
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
