import { useMemo, useState } from "react"
import { Play, Search, User, Video, X } from "lucide-react"

import { api } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import { Card, Skeleton, cn } from "@geneza/ui"
import { EmptyState, ErrorState } from "@/components/states"
import { Pagination } from "@/components/data-pagination"
import { RecordingPlayer } from "@/components/recording-player"
import { formatBytes } from "@/lib/recording"
import { formatDuration, relativeTime } from "@/lib/format"
import type { RecordingInfo, RecordingsResponse } from "@/types"

const PAGE_SIZE = 24

// A recording is playable once the session has ended (it carries an end time) — a
// still-running session's cast is incomplete.
function isPlayable(r: RecordingInfo): boolean {
  return r.endedUnix > 0
}

// One recording card: play tile, identity line, and the size/duration strip in
// machine text — the Console design's recording tile.
function RecordingCard({
  rec,
  onPlay,
}: {
  rec: RecordingInfo
  onPlay: () => void
}) {
  const playable = isPlayable(rec)
  return (
    <Card
      onClick={playable ? onPlay : undefined}
      className={cn(
        "flex items-center gap-4 p-4",
        playable && "cursor-pointer transition-colors hover:border-input"
      )}
    >
      <div className="flex size-[46px] shrink-0 items-center justify-center rounded-[10px] border bg-elev text-brand">
        <Play className="size-[18px]" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="mb-1 flex items-center gap-2">
          <span className="truncate font-mono text-[12.5px]">{rec.sessionId}</span>
          {!playable && (
            <span className="shrink-0 rounded border border-brand-line px-1.5 py-px font-mono text-[9.5px] text-brand">
              ● LIVE
            </span>
          )}
          {rec.truncated && (
            <span className="shrink-0 rounded border border-warning/35 px-1.5 py-px font-mono text-[9.5px] text-warning">
              truncated
            </span>
          )}
          {/* An empty auditKeyId means no age recipient was configured when this
              session was recorded, so the cast was spooled and stored as READABLE
              terminal transcript. That is a materially different artifact from an
              encrypted one and the operator has no other way to notice. */}
          {!rec.auditKeyId && (
            <span
              className="shrink-0 rounded border border-destructive/40 px-1.5 py-px font-mono text-[9.5px] text-destructive"
              title="Recorded without an audit recipient: stored as readable plaintext, not encrypted at rest."
            >
              plaintext
            </span>
          )}
        </div>
        <div className="truncate font-mono text-[11px] text-muted-foreground">
          {rec.principal || "—"} → {rec.nodeId}
        </div>
        <div className="mt-1.5 truncate font-mono text-2xs text-faint">
          {relativeTime(rec.startedUnix)} ·{" "}
          {formatDuration(rec.startedUnix, rec.endedUnix)} ·{" "}
          {formatBytes(rec.sizeBytes)}
        </div>
      </div>
      <span className="shrink-0 rounded-[5px] border border-brand-line px-2 py-0.5 font-mono text-[11px] text-brand">
        {rec.action || "shell"}
      </span>
    </Card>
  )
}

// RecordingsPage lists the workspace's session recordings (audit/replay-gated on
// the controller) and lets an auditor play one back. The cast itself is fetched and
// decrypted client-side by the player; this view only enumerates the index.
export function RecordingsPage() {
  const [page, setPage] = useState(1)
  const [query, setQuery] = useState("")
  // The server filters by principal with an EXACT match, which is a different
  // (and much sharper) tool than the free-text box below — that one only ever
  // searched the rows already on screen. Both exist now: pick a principal to
  // scope the whole result set, type to narrow the visible page.
  const [principal, setPrincipal] = useState("")
  const [principalTerm, setPrincipalTerm] = useState("")
  const [target, setTarget] = useState<RecordingInfo | null>(null)

  const { data, error, initialLoading, loading, refresh } =
    usePolling<RecordingsResponse>(
      (s) =>
        api.getRecordings(
          {
            principal: principal || undefined,
            limit: PAGE_SIZE,
            offset: (page - 1) * PAGE_SIZE,
          },
          s
        ),
      15000,
      [principal, page]
    )

  const total = data?.total ?? 0
  const forbidden = error?.toLowerCase().includes("capability")

  const filtered = useMemo(() => {
    const recordings = data?.recordings ?? []
    const q = query.trim().toLowerCase()
    if (!q) return recordings
    return recordings.filter((r) =>
      `${r.sessionId} ${r.principal} ${r.nodeId} ${r.action}`
        .toLowerCase()
        .includes(q)
    )
  }, [data, query])

  if (error && !data && forbidden) {
    return (
      <Card>
        <EmptyState
          icon={<Video className="size-8" />}
          title="Replay not permitted"
          message="Session replay is privileged. Ask a workspace admin for the auditor role to view recordings."
        />
      </Card>
    )
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2.5">
        <div className="flex min-w-60 flex-1 items-center gap-2.5 rounded-[9px] border bg-card px-3.5 py-[9px]">
          <Search className="size-[15px] shrink-0 text-faint" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search this page by user, node, or id…"
            className="w-full border-none bg-transparent font-mono text-[12.5px] text-foreground outline-none placeholder:text-faint"
          />
        </div>
        {/* Scopes the whole result set server-side, so paging and the total stay
            correct — unlike the box on the left, which only ever narrowed the rows
            already fetched. */}
        <form
          className="flex min-w-52 items-center gap-2.5 rounded-[9px] border bg-card px-3.5 py-[9px]"
          onSubmit={(e) => {
            e.preventDefault()
            setPrincipal(principalTerm.trim())
            setPage(1)
          }}
        >
          <User className="size-[15px] shrink-0 text-faint" />
          <input
            value={principalTerm}
            onChange={(e) => setPrincipalTerm(e.target.value)}
            placeholder="Filter by principal…"
            className="w-full border-none bg-transparent font-mono text-[12.5px] text-foreground outline-none placeholder:text-faint"
          />
          {principal && (
            <button
              type="button"
              onClick={() => {
                setPrincipal("")
                setPrincipalTerm("")
                setPage(1)
              }}
              className="shrink-0 text-faint hover:text-foreground"
              title="Clear principal filter"
            >
              <X className="size-3.5" />
            </button>
          )}
        </form>
      </div>

      {error && !data ? (
        <Card>
          <ErrorState message={error} onRetry={refresh} />
        </Card>
      ) : initialLoading ? (
        <div className="grid grid-cols-1 gap-3.5 lg:grid-cols-2">
          {Array.from({ length: 6 }).map((_, i) => (
            <Card key={i} className="flex items-center gap-4 p-4">
              <Skeleton className="size-[46px] rounded-[10px]" />
              <div className="flex-1 space-y-2">
                <Skeleton className="h-3.5 w-32" />
                <Skeleton className="h-3 w-48" />
              </div>
            </Card>
          ))}
        </div>
      ) : total === 0 ? (
        <Card>
          <EmptyState
            icon={<Video className="size-8" />}
            title="No recordings"
            message="No session recordings have been captured in this workspace yet."
          />
        </Card>
      ) : filtered.length === 0 ? (
        <Card>
          <div className="p-10 text-center font-mono text-[13px] text-faint">
            No recordings match your search.
          </div>
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-1 gap-3.5 lg:grid-cols-2">
            {filtered.map((r) => (
              <RecordingCard key={r.sessionId} rec={r} onPlay={() => setTarget(r)} />
            ))}
          </div>
          {total > PAGE_SIZE && (
            <Card className="p-0">
              <Pagination
                total={total}
                pageSize={PAGE_SIZE}
                page={page}
                onPage={setPage}
                loading={loading}
              />
            </Card>
          )}
        </>
      )}

      {target && (
        <RecordingPlayer recording={target} onClose={() => setTarget(null)} />
      )}
    </div>
  )
}
