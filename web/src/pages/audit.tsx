import { useState } from "react"
import {
  ChevronDown,
  ChevronRight,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react"

import { api } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
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
import { EmptyState, ErrorState } from "@/components/states"
import { PageToolbar } from "@/components/page-toolbar"
import { CopyId } from "@/components/copy-id"
import { AuditTypeIcon } from "@/components/audit-type-badge"
import { absoluteTime, relativeTime } from "@/lib/format"
import { cn } from "@/lib/utils"
import type { AuditRecord } from "@/types"

const COMMON_TYPES = [
  "login_success",
  "session_request",
  "session_event",
  "enroll",
  "token_create",
  "cert_renew",
]

const SINCE_OPTIONS: { label: string; seconds: number }[] = [
  { label: "Last 1 hour", seconds: 3600 },
  { label: "Last 24 hours", seconds: 86400 },
  { label: "Last 7 days", seconds: 604800 },
  { label: "All time", seconds: 0 },
]

const LIMITS = [50, 100, 250, 500]

export function AuditPage() {
  const [type, setType] = useState("")
  const [sinceSeconds, setSinceSeconds] = useState(86400)
  const [limit, setLimit] = useState(100)

  const { data, error, initialLoading, loading, refresh } = usePolling(
    (s) =>
      api.getAudit(
        {
          type: type || undefined,
          since: sinceSeconds
            ? Math.floor(Date.now() / 1000) - sinceSeconds
            : undefined,
          limit,
        },
        s
      ),
    0,
    [type, sinceSeconds, limit]
  )

  const records = data?.records ?? []

  return (
    <div className="space-y-4">
      <ChainBanner chainOk={data?.chainOk} loading={initialLoading} />

      <PageToolbar onRefresh={refresh} refreshing={loading}>
        <Input
          value={type}
          onChange={(e) => setType(e.target.value)}
          placeholder="Filter by type…"
          list="audit-types"
          className="w-44"
        />
        <datalist id="audit-types">
          {COMMON_TYPES.map((t) => (
            <option key={t} value={t} />
          ))}
        </datalist>

        <Select
          value={String(sinceSeconds)}
          onValueChange={(v) => setSinceSeconds(Number(v))}
        >
          <SelectTrigger className="w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {SINCE_OPTIONS.map((o) => (
              <SelectItem key={o.seconds} value={String(o.seconds)}>
                {o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={String(limit)} onValueChange={(v) => setLimit(Number(v))}>
          <SelectTrigger className="w-24">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {LIMITS.map((l) => (
              <SelectItem key={l} value={String(l)}>
                {l} rows
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </PageToolbar>

      <Card className="overflow-hidden p-0">
        {error && !data ? (
          <ErrorState message={error} onRetry={refresh} />
        ) : initialLoading ? (
          <RowsSkeleton />
        ) : records.length === 0 ? (
          <EmptyState
            icon={<ScrollText className="size-8" />}
            title="No audit records"
            message="No events match the current filters."
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-10" />
                <TableHead className="w-16">Seq</TableHead>
                <TableHead>Time</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Actor</TableHead>
                <TableHead>Node</TableHead>
                <TableHead>Session</TableHead>
                <TableHead>Hash</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {records.map((rec) => (
                <AuditRow key={rec.seq} rec={rec} />
              ))}
            </TableBody>
          </Table>
        )}
      </Card>

      {records.length > 0 && (
        <p className="text-xs text-muted-foreground">
          {records.length} record{records.length === 1 ? "" : "s"}
        </p>
      )}
    </div>
  )
}

function AuditRow({ rec }: { rec: AuditRecord }) {
  const [open, setOpen] = useState(false)
  const hasDetail = rec.detail && Object.keys(rec.detail).length > 0

  return (
    <>
      <TableRow
        className={cn(hasDetail && "cursor-pointer")}
        onClick={() => hasDetail && setOpen((v) => !v)}
      >
        <TableCell className="text-muted-foreground">
          {hasDetail ? (
            open ? (
              <ChevronDown className="size-4" />
            ) : (
              <ChevronRight className="size-4" />
            )
          ) : null}
        </TableCell>
        <TableCell className="font-mono text-xs tabular-nums text-muted-foreground">
          {rec.seq}
        </TableCell>
        <TableCell
          className="whitespace-nowrap text-sm text-muted-foreground"
          title={absoluteTime(rec.ts)}
        >
          {relativeTime(rec.ts)}
        </TableCell>
        <TableCell>
          <span className="inline-flex items-center gap-1.5">
            <AuditTypeIcon
              type={rec.type}
              className="size-3.5 text-muted-foreground"
            />
            <span className="font-mono text-xs">{rec.type}</span>
          </span>
        </TableCell>
        <TableCell className="text-sm">{rec.actor || "—"}</TableCell>
        <TableCell className="text-sm">{rec.node || "—"}</TableCell>
        <TableCell onClick={(e) => e.stopPropagation()}>
          {rec.session ? (
            <CopyId value={rec.session} head={6} tail={4} label="Session copied" />
          ) : (
            <span className="text-muted-foreground">—</span>
          )}
        </TableCell>
        <TableCell onClick={(e) => e.stopPropagation()}>
          <CopyId value={rec.hash} head={6} tail={4} label="Hash copied" />
        </TableCell>
      </TableRow>
      {open && hasDetail && (
        <TableRow className="bg-muted/30 hover:bg-muted/30">
          <TableCell />
          <TableCell colSpan={7} className="py-3">
            <dl className="grid grid-cols-1 gap-x-6 gap-y-1.5 sm:grid-cols-2">
              {Object.entries(rec.detail!).map(([k, v]) => (
                <div key={k} className="flex gap-2 text-xs">
                  <dt className="shrink-0 font-medium text-muted-foreground">
                    {k}
                  </dt>
                  <dd className="min-w-0 break-all font-mono">{v}</dd>
                </div>
              ))}
            </dl>
            <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 border-t pt-2 text-xs text-muted-foreground">
              <span className="inline-flex items-center gap-1.5">
                prev
                <CopyId value={rec.prev} head={6} tail={4} label="Prev hash copied" />
              </span>
              <span className="inline-flex items-center gap-1.5">
                hash
                <CopyId value={rec.hash} head={6} tail={4} label="Hash copied" />
              </span>
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  )
}

function ChainBanner({
  chainOk,
  loading,
}: {
  chainOk?: boolean
  loading: boolean
}) {
  if (loading) return <Skeleton className="h-14 w-full rounded-lg" />

  const ok = chainOk !== false
  return (
    <div
      className={cn(
        "flex items-center gap-3 rounded-lg border px-4 py-3",
        ok
          ? "border-[var(--success)]/30 bg-[var(--success)]/5"
          : "border-destructive/40 bg-destructive/10"
      )}
    >
      {ok ? (
        <ShieldCheck className="size-5 shrink-0 text-[var(--success)]" />
      ) : (
        <ShieldAlert className="size-5 shrink-0 text-destructive" />
      )}
      <div>
        <p className="text-sm font-medium">
          {ok ? "Audit chain verified" : "Audit chain BROKEN"}
        </p>
        <p className="text-xs text-muted-foreground">
          {ok
            ? "Each record’s hash links to its predecessor; the log is tamper-evident."
            : "Hash chain integrity check failed — records may have been altered or dropped."}
        </p>
      </div>
      <Badge
        variant={ok ? "success" : "destructive"}
        className="ml-auto"
      >
        {ok ? "OK" : "FAILED"}
      </Badge>
    </div>
  )
}

function RowsSkeleton() {
  return (
    <div className="divide-y">
      {Array.from({ length: 8 }).map((_, i) => (
        <div key={i} className="flex items-center gap-4 px-3 py-3">
          <Skeleton className="h-4 w-8" />
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-4 w-28" />
          <Skeleton className="h-4 w-24" />
          <Skeleton className="ml-auto h-4 w-24" />
        </div>
      ))}
    </div>
  )
}
