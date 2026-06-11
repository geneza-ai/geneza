import {
  CheckCircle2,
  GitBranch,
  Radio,
  Server,
  ShieldAlert,
  TerminalSquare,
} from "lucide-react"

import { api } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Badge } from "@/components/ui/badge"
import { ErrorState } from "@/components/states"
import { PageToolbar } from "@/components/page-toolbar"
import { AuditTypeIcon } from "@/components/audit-type-badge"
import { relativeTime } from "@/lib/format"
import type { AuditRecord, Overview } from "@/types"
import { cn } from "@/lib/utils"

function StatCard({
  label,
  value,
  sub,
  icon: Icon,
  tone,
}: {
  label: string
  value: React.ReactNode
  sub?: React.ReactNode
  icon: React.ElementType
  tone?: "success" | "warning"
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          {label}
        </CardTitle>
        <Icon
          className={cn(
            "size-4 text-muted-foreground",
            tone === "success" && "text-[var(--success)]",
            tone === "warning" && "text-[var(--warning)]"
          )}
        />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-semibold tabular-nums">{value}</div>
        {sub && (
          <p className="mt-1 text-xs text-muted-foreground">{sub}</p>
        )}
      </CardContent>
    </Card>
  )
}

export function DashboardPage() {
  const overview = usePolling<Overview>((s) => api.getOverview(s), 10000)
  const recent = usePolling(
    (s) => api.getAudit({ limit: 10 }, s),
    15000
  )

  const o = overview.data

  return (
    <div className="space-y-6">
      <PageToolbar
        description="Fleet health at a glance."
        onRefresh={() => {
          overview.refresh()
          recent.refresh()
        }}
        refreshing={overview.loading}
      />

      {overview.error && !o ? (
        <Card>
          <ErrorState message={overview.error} onRetry={overview.refresh} />
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">
          {!o ? (
            Array.from({ length: 5 }).map((_, i) => (
              <Card key={i}>
                <CardHeader className="pb-2">
                  <Skeleton className="h-4 w-24" />
                </CardHeader>
                <CardContent>
                  <Skeleton className="h-7 w-16" />
                </CardContent>
              </Card>
            ))
          ) : (
            <>
              <StatCard
                label="Nodes online"
                icon={Server}
                value={
                  <span>
                    {o.nodes.online}{" "}
                    <span className="text-muted-foreground">
                      / {o.nodes.total}
                    </span>
                  </span>
                }
                sub={`${o.nodes.total} registered`}
              />
              <StatCard
                label="Active sessions"
                icon={TerminalSquare}
                value={o.sessions.active}
                sub={`${o.sessions.total} total`}
              />
              <StatCard
                label="Detached"
                icon={TerminalSquare}
                value={o.sessions.detached}
                sub="resumable"
                tone={o.sessions.detached > 0 ? "warning" : undefined}
              />
              <StatCard
                label="Fleet version"
                icon={GitBranch}
                value={
                  <span className="font-mono text-lg">{o.versions.stable}</span>
                }
                sub={
                  o.versions.canary ? (
                    <span>
                      canary{" "}
                      <span className="font-mono">{o.versions.canary}</span>
                    </span>
                  ) : (
                    "no canary"
                  )
                }
              />
              <StatCard
                label="Audit chain"
                icon={o.audit.chainOk ? CheckCircle2 : ShieldAlert}
                tone={o.audit.chainOk ? "success" : "warning"}
                value={
                  <span className="text-lg">
                    {o.audit.chainOk ? "Verified" : "Broken"}
                  </span>
                }
                sub={`${o.audit.count.toLocaleString()} records`}
              />
            </>
          )}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between space-y-0">
            <CardTitle className="text-sm">Recent activity</CardTitle>
            <Badge variant="muted">last 10 events</Badge>
          </CardHeader>
          <CardContent>
            <RecentActivity
              records={recent.data?.records}
              loading={recent.initialLoading}
              error={recent.error}
              onRetry={recent.refresh}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Relays</CardTitle>
          </CardHeader>
          <CardContent>
            {!o ? (
              <Skeleton className="h-5 w-32" />
            ) : o.relays.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No relays — direct only.
              </p>
            ) : (
              <ul className="space-y-2">
                {o.relays.map((r) => (
                  <li key={r} className="flex items-center gap-2 text-sm">
                    <Radio className="size-3.5 text-muted-foreground" />
                    <span className="font-mono text-xs">{r}</span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
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
      <div className="space-y-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="flex items-center gap-3">
            <Skeleton className="size-7 rounded-full" />
            <div className="flex-1 space-y-1.5">
              <Skeleton className="h-3.5 w-48" />
              <Skeleton className="h-3 w-24" />
            </div>
          </div>
        ))}
      </div>
    )
  }

  if (error) return <ErrorState message={error} onRetry={onRetry} />

  if (!records || records.length === 0) {
    return (
      <p className="py-6 text-center text-sm text-muted-foreground">
        No recent activity.
      </p>
    )
  }

  return (
    <ol className="space-y-1">
      {records.map((rec) => (
        <li
          key={rec.seq}
          className="flex items-start gap-3 rounded-md px-1 py-2 transition-colors hover:bg-muted/40"
        >
          <div className="mt-0.5 flex size-7 shrink-0 items-center justify-center rounded-full bg-muted text-muted-foreground">
            <AuditTypeIcon type={rec.type} className="size-3.5" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-sm">
              <span className="font-mono text-xs text-foreground">
                {rec.type}
              </span>
              {rec.actor && (
                <span className="text-muted-foreground"> · {rec.actor}</span>
              )}
              {rec.node && (
                <span className="text-muted-foreground"> · {rec.node}</span>
              )}
            </p>
            <p className="text-xs text-muted-foreground">
              {relativeTime(rec.ts)}
            </p>
          </div>
        </li>
      ))}
    </ol>
  )
}
