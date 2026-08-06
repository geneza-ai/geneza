import { useState } from "react"
import {
  ChevronDown,
  ChevronRight,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Download,
} from "lucide-react"

import { toast } from "sonner"

import { api, ApiError } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import { Button, Card } from "@geneza/ui"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@geneza/ui"
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
import { Pagination } from "@/components/data-pagination"
import { useDebounced } from "@/hooks/use-debounced"
import { saveBlob } from "@/lib/format"
import { CopyId } from "@/components/copy-id"
import { AuditTag } from "@/components/audit-type-badge"
import { absoluteTime, relativeTime } from "@/lib/format"
import { cn } from "@geneza/ui"
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
  const [actor, setActor] = useState("")
  const [sinceSeconds, setSinceSeconds] = useState(86400)
  const [limit, setLimit] = useState(100)
  const [page, setPage] = useState(1)
  // The filter inputs are query dependencies, and every audit read takes the same
  // mutex Append needs while scanning the whole file — so an undebounced keystroke
  // stalled audit writes fleet-wide. Debounce what the query actually sees.
  const debouncedType = useDebounced(type, 300)
  const debouncedActor = useDebounced(actor, 300)

  // The window is resolved when the request is MADE, not during render: reading
  // the clock in the render body makes it impure and the value stale by the time
  // it is used anyway.
  const buildQuery = () => ({
    type: debouncedType || undefined,
    actor: debouncedActor || undefined,
    since: sinceSeconds ? Math.floor(Date.now() / 1000) - sinceSeconds : undefined,
    limit,
    offset: (page - 1) * limit,
  })

  const { data, error, initialLoading, loading, refresh } = usePolling(
    (s) => api.getAudit(buildQuery(), s),
    0,
    [debouncedType, debouncedActor, sinceSeconds, limit, page]
  )

  const records = data?.records ?? []
  const total = data?.total ?? records.length

  async function exportJSONL() {
    try {
      saveBlob(
        await api.downloadAuditJSONL({ ...buildQuery(), limit: 5000, offset: 0 }),
        "audit.jsonl"
      )
    } catch (err) {
      toast.error("Export failed", {
        description: err instanceof ApiError ? err.message : String(err),
      })
    }
  }

  return (
    <div className="space-y-4">
      <ChainBanner chainOk={data?.chainOk} loading={initialLoading} />

      <PageToolbar onRefresh={refresh} refreshing={loading}>
        <Input
          value={type}
          onChange={(e) => {
            setType(e.target.value)
            setPage(1)
          }}
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
          onValueChange={(v) => {
            setSinceSeconds(Number(v))
            setPage(1)
          }}
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

        <Input
          value={actor}
          onChange={(e) => {
            setActor(e.target.value)
            setPage(1)
          }}
          placeholder="Filter by actor…"
          className="w-40"
        />

        <Select
          value={String(limit)}
          onValueChange={(v) => {
            setLimit(Number(v))
            setPage(1)
          }}
        >
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

        <Button variant="outline" size="sm" onClick={exportJSONL}>
          <Download className="size-4" />
          Export
        </Button>
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
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-10 pl-5" />
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
        {total > 0 && (
          <Pagination
            total={total}
            pageSize={limit}
            page={page}
            onPage={setPage}
            loading={loading}
          />
        )}
      </Card>

      {records.length > 0 && (
        <p className="text-xs text-muted-foreground">
          {records.length} of {total} record{total === 1 ? "" : "s"} matching
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
        <TableCell className="pl-5 text-faint">
          {hasDetail ? (
            open ? (
              <ChevronDown className="size-4" />
            ) : (
              <ChevronRight className="size-4" />
            )
          ) : null}
        </TableCell>
        <TableCell className="font-mono text-xs tabular-nums text-faint">
          {rec.seq}
        </TableCell>
        <TableCell
          className="whitespace-nowrap font-mono text-[11.5px] text-muted-foreground"
          title={absoluteTime(rec.ts)}
        >
          {relativeTime(rec.ts)}
        </TableCell>
        <TableCell>
          <AuditTag type={rec.type} />
        </TableCell>
        <TableCell className="text-[13px] text-muted-foreground">
          {rec.actor || "—"}
        </TableCell>
        <TableCell className="text-[13px] text-muted-foreground">
          {rec.node || "—"}
        </TableCell>
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

// Three states, not two. `chainOk` is undefined whenever the fetch failed or has
// not returned — and claiming "Audit chain verified" on the strength of no data
// is the worst thing this page can do, because it is the console's single most
// security-load-bearing assertion and nobody investigates a green badge.
function ChainBanner({
  chainOk,
  loading,
}: {
  chainOk?: boolean
  loading: boolean
}) {
  if (loading) return <Skeleton className="h-14 w-full rounded-[14px]" />

  const state = chainOk === true ? "ok" : chainOk === false ? "broken" : "unknown"
  const style = {
    ok: "border-success/30 bg-success/5",
    broken: "border-destructive/40 bg-destructive/10",
    unknown: "border-border bg-muted/30",
  }[state]
  const icon = {
    ok: <ShieldCheck className="size-5 shrink-0 text-success" />,
    broken: <ShieldAlert className="size-5 shrink-0 text-destructive" />,
    unknown: <ShieldQuestion className="size-5 shrink-0 text-muted-foreground" />,
  }[state]
  const title = {
    ok: "Audit chain verified",
    broken: "Audit chain BROKEN",
    unknown: "Audit chain not verified",
  }[state]
  const detail = {
    ok: "Each record’s hash links to its predecessor; the log is tamper-evident.",
    broken:
      "Hash chain integrity check failed — records may have been altered or dropped.",
    unknown:
      "The integrity check did not run — the controller did not return a verdict. This is not an assertion that the log is intact.",
  }[state]
  const badge = { ok: "OK", broken: "FAILED", unknown: "UNKNOWN" }[state]

  return (
    <div
      className={cn(
        "flex items-center gap-3 rounded-[14px] border px-4 py-3",
        style
      )}
    >
      {icon}
      <div>
        <p className="text-sm font-medium">{title}</p>
        <p className="text-xs text-muted-foreground">{detail}</p>
      </div>
      <Badge
        variant={
          state === "ok"
            ? "success"
            : state === "broken"
              ? "destructive"
              : "outline"
        }
        className="ml-auto"
      >
        {badge}
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
