import { Link, useNavigate } from "react-router-dom"

import { api } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import { Button, Card, Skeleton, cn } from "@geneza/ui"
import { AuditTag } from "@/components/audit-type-badge"
import { CardLabel } from "@/components/card-label"
import { NodeCvePills } from "@/components/fleet-cves"
import { useFleetCves, type SevCount } from "@/hooks/use-fleet-cves"
import { ErrorState } from "@/components/states"
import { StatusDot } from "@/components/status-dot"
import { relativeTime } from "@/lib/format"
import type {
  AuditRecord,
  NodesResponse,
  Overview,
  SessionsResponse,
} from "@/types"

function StatCard({
  label,
  value,
  sub,
  accent,
  to,
}: {
  label: string
  value: React.ReactNode
  sub: React.ReactNode
  accent?: boolean
  to?: string
}) {
  const navigate = useNavigate()
  return (
    <Card
      onClick={to ? () => navigate(to) : undefined}
      className={cn("p-5", to && "cursor-pointer", accent && "border-brand-line")}
    >
      <CardLabel className="mb-3.5">{label}</CardLabel>
      <div
        className={cn(
          "font-serif text-[38px] font-medium leading-none tabular-nums",
          accent && "text-brand"
        )}
      >
        {value}
      </div>
      <div className="mt-2.5 font-mono text-[11px] text-muted-foreground">{sub}</div>
    </Card>
  )
}

export function DashboardPage() {
  const overview = usePolling<Overview>((s) => api.getOverview(s), 10000)
  const nodes = usePolling<NodesResponse>((s) => api.getNodes(undefined, s), 10000)
  const cves = useFleetCves()
  const live = usePolling<SessionsResponse>(
    (s) => api.getSessions({ state: "active", limit: 1 }, s),
    10000
  )
  const recent = usePolling((s) => api.getAudit({ limit: 8 }, s), 15000)

  const o = overview.data
  const { counts, perNode, atRisk } = cves
  const openCves = cves.loaded ? cves.open.length : null
  const fleet = (nodes.data?.nodes ?? []).slice(0, 6)
  const liveSession = live.data?.sessions[0]

  if (overview.error && !o) {
    return (
      <Card>
        <ErrorState message={overview.error} onRetry={overview.refresh} />
      </Card>
    )
  }

  return (
    <div className="space-y-4">
      {/* Stat cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {!o ? (
          Array.from({ length: 4 }).map((_, i) => (
            <Card key={i} className="p-5">
              <Skeleton className="mb-4 h-3 w-24" />
              <Skeleton className="h-9 w-16" />
              <Skeleton className="mt-3 h-3 w-32" />
            </Card>
          ))
        ) : (
          <>
            <StatCard
              label="Nodes"
              to="/nodes"
              value={o.nodes.total}
              sub={`${o.nodes.online} online · ${o.nodes.total - o.nodes.online} offline`}
            />
            <StatCard
              label="Open CVEs"
              to="/vulnerabilities"
              value={openCves ?? "—"}
              sub={
                <>
                  <span className="text-sev-crit">{counts.crit} critical</span>
                  {" · "}
                  <span className="text-sev-high">{counts.high} high</span>
                </>
              }
            />
            <StatCard
              label="Nodes at risk"
              to="/vulnerabilities"
              value={cves.loaded ? atRisk : "—"}
              sub="critical or high exposure"
            />
            <StatCard
              label="Active sessions"
              to="/sessions"
              accent
              value={o.sessions.active}
              sub={`${o.sessions.detached} detached · ${o.sessions.total} total`}
            />
          </>
        )}
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1.5fr_1fr]">
        {/* Fleet */}
        <Card className="self-start overflow-hidden p-0">
          <div className="flex items-center justify-between border-b px-5 py-4">
            <span className="font-serif text-[17px] font-medium">Fleet</span>
            <Link
              to="/nodes"
              className="font-mono text-[11px] text-brand hover:underline"
            >
              view all →
            </Link>
          </div>
          {nodes.error && !nodes.data ? (
            <ErrorState message={nodes.error} onRetry={nodes.refresh} />
          ) : nodes.initialLoading ? (
            <div className="space-y-3 p-5">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-8 w-full" />
              ))}
            </div>
          ) : fleet.length === 0 ? (
            <p className="px-5 py-10 text-center font-mono text-[13px] text-faint">
              No nodes enrolled yet.
            </p>
          ) : (
            fleet.map((n) => (
              <Link
                key={n.nodeId}
                to={`/nodes/${n.nodeId}`}
                className="grid cursor-pointer grid-cols-[1.5fr_0.8fr_1.3fr] items-center gap-3 border-b border-line2 px-5 py-3 transition-colors last:border-b-0 hover:bg-muted/40"
              >
                <div className="flex min-w-0 items-center gap-2.5">
                  <StatusDot online={n.online} />
                  <span className="truncate font-mono text-[12.5px]">
                    {n.name || n.nodeId}
                  </span>
                </div>
                <span className="font-mono text-[11px] text-muted-foreground">
                  {n.online ? "online" : "offline"}
                </span>
                <div className="flex justify-end sm:justify-start">
                  <NodeCvePills
                    counts={perNode.get(n.nodeId) ?? perNode.get(n.name)}
                  />
                </div>
              </Link>
            ))
          )}
        </Card>

        {/* Right column */}
        <div className="flex flex-col gap-4">
          {liveSession && (
            <Card className="border-brand-line p-5">
              <div className="mb-3.5 flex items-center gap-2 font-mono">
                <span className="size-[7px] rounded-full bg-brand animate-live-pulse" />
                <span className="text-[11px] text-brand">
                  active session · {liveSession.action}
                </span>
              </div>
              <div className="font-mono text-xs leading-[1.7] text-muted-foreground">
                geneza://user/{liveSession.user}
                <br />
                <span className="text-faint">
                  {"  "}→ node/{liveSession.nodeName || liveSession.nodeId}
                </span>
              </div>
              <div className="my-3.5 h-px bg-border" />
              <div className="flex flex-col gap-2 font-mono text-xs">
                <div className="flex justify-between">
                  <span className="text-faint">state</span>
                  <span className="text-muted-foreground">{liveSession.state}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-faint">started</span>
                  <span className="text-muted-foreground">
                    {relativeTime(liveSession.startedUnix)}
                  </span>
                </div>
              </div>
              <Button asChild className="mt-4 w-full">
                <Link to="/sessions">View sessions</Link>
              </Button>
            </Card>
          )}

          <Card className="p-5">
            <CardLabel className="mb-4">Open vulnerabilities</CardLabel>
            {!cves.loaded ? (
              <div className="space-y-3">
                {Array.from({ length: 3 }).map((_, i) => (
                  <Skeleton key={i} className="h-6 w-full" />
                ))}
              </div>
            ) : (
              <SeverityBars counts={counts} />
            )}
          </Card>

          {o && (
            <Card className="p-5">
              <CardLabel className="mb-4">Control plane</CardLabel>
              <div className="flex flex-col gap-2.5 font-mono text-xs">
                <div className="flex justify-between">
                  <span className="text-faint">stable</span>
                  <span className="text-muted-foreground">
                    {o.versions.stable || "—"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-faint">canary</span>
                  <span className="text-muted-foreground">
                    {o.versions.canary || "none"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-faint">audit chain</span>
                  <span className={o.audit.chainOk ? "text-success" : "text-destructive"}>
                    {o.audit.chainOk ? "✓ verified" : "✗ broken"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-faint">records</span>
                  <span className="text-muted-foreground">
                    {o.audit.count.toLocaleString()}
                  </span>
                </div>
              </div>
            </Card>
          )}
        </div>
      </div>

      {/* Recent activity */}
      <Card className="overflow-hidden p-0">
        <div className="border-b px-5 py-4">
          <span className="font-serif text-[17px] font-medium">Recent activity</span>
        </div>
        <RecentActivity
          records={recent.data?.records}
          loading={recent.initialLoading}
          error={recent.error}
          onRetry={recent.refresh}
        />
      </Card>
    </div>
  )
}

function SeverityBars({ counts }: { counts: SevCount }) {
  const max = Math.max(counts.crit, counts.high, counts.med, 1)
  const rows = [
    { label: "Critical", count: counts.crit, cls: "bg-sev-crit" },
    { label: "High", count: counts.high, cls: "bg-sev-high" },
    { label: "Medium", count: counts.med, cls: "bg-sev-med" },
  ]
  return (
    <div>
      {rows.map((r) => (
        <div key={r.label} className="mb-3.5 last:mb-0">
          <div className="mb-1.5 flex justify-between">
            <span className="text-[12.5px] text-muted-foreground">{r.label}</span>
            <span className="font-mono text-xs">{r.count}</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded bg-line2">
            <div
              className={cn("h-full rounded", r.cls)}
              style={{ width: `${Math.round((r.count / max) * 100)}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  )
}

function RecentActivity({
  records,
  loading,
  error,
  onRetry,
}: {
  records?: AuditRecord[]
  loading: boolean
  error: string | null
  onRetry: () => void
}) {
  if (loading) {
    return (
      <div className="space-y-3 p-5">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-6 w-full" />
        ))}
      </div>
    )
  }

  if (error) return <ErrorState message={error} onRetry={onRetry} />

  if (!records || records.length === 0) {
    return (
      <p className="px-5 py-10 text-center font-mono text-[13px] text-faint">
        No recent activity.
      </p>
    )
  }

  return (
    <ol>
      {records.map((rec) => (
        <li
          key={rec.seq}
          className="flex items-center gap-3.5 border-b border-line2 px-5 py-3 last:border-b-0"
        >
          <AuditTag type={rec.type} />
          <span className="min-w-0 truncate text-[13px] text-muted-foreground">
            {[rec.actor, rec.node, rec.session].filter(Boolean).join(" · ") || "—"}
          </span>
          <span className="ml-auto shrink-0 font-mono text-[11px] text-faint">
            {relativeTime(rec.ts)}
          </span>
        </li>
      ))}
    </ol>
  )
}
