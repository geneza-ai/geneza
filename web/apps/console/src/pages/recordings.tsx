import { useState } from "react"
import { PlayCircle, Video } from "lucide-react"

import { api } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import { Badge } from "@/components/ui/badge"
import { Button } from "@geneza/ui"
import { Card } from "@geneza/ui"
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
import { Pagination } from "@/components/data-pagination"
import { CopyId } from "@/components/copy-id"
import { ActionBadge } from "@/components/session-badges"
import { RecordingPlayer } from "@/components/recording-player"
import { formatBytes } from "@/lib/recording"
import { relativeTime } from "@/lib/format"
import type { RecordingInfo, RecordingsResponse } from "@/types"

const PAGE_SIZE = 25

// A recording is playable once the session has ended (it carries an end time) — a
// still-running session's cast is incomplete.
function isPlayable(r: RecordingInfo): boolean {
  return r.endedUnix > 0
}

// RecordingsPage lists the workspace's session recordings (audit/replay-gated on
// the controller) and lets an auditor play one back. The cast itself is fetched and
// decrypted client-side by the player; this view only enumerates the index.
export function RecordingsPage() {
  const [page, setPage] = useState(1)
  const [target, setTarget] = useState<RecordingInfo | null>(null)

  const { data, error, initialLoading, loading, refresh } =
    usePolling<RecordingsResponse>(
      (s) =>
        api.getRecordings(
          { limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE },
          s
        ),
      15000,
      [page]
    )

  const recordings = data?.recordings ?? []
  const total = data?.total ?? 0
  const forbidden = error?.toLowerCase().includes("capability")

  return (
    <div className="space-y-4">
      <PageToolbar
        description={`${total} recording${total === 1 ? "" : "s"}`}
        onRefresh={refresh}
        refreshing={loading}
      />

      <Card className="overflow-hidden p-0">
        {error && !data ? (
          forbidden ? (
            <EmptyState
              icon={<Video className="size-8" />}
              title="Replay not permitted"
              message="Session replay is privileged. Ask a workspace admin for the auditor role to view recordings."
            />
          ) : (
            <ErrorState message={error} onRetry={refresh} />
          )
        ) : initialLoading ? (
          <RowsSkeleton />
        ) : total === 0 ? (
          <EmptyState
            icon={<Video className="size-8" />}
            title="No recordings"
            message="No session recordings have been captured in this workspace yet."
          />
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Session ID</TableHead>
                  <TableHead>Node</TableHead>
                  <TableHead>Principal</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Started</TableHead>
                  <TableHead className="text-right">Size</TableHead>
                  <TableHead className="text-right">Play</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recordings.map((r) => (
                  <TableRow key={r.sessionId}>
                    <TableCell>
                      <CopyId value={r.sessionId} label="Session ID copied" />
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {r.nodeId}
                    </TableCell>
                    <TableCell className="text-sm">
                      {r.principal || "—"}
                    </TableCell>
                    <TableCell>
                      <ActionBadge action={r.action || "shell"} />
                      {r.truncated && (
                        <Badge variant="warning" className="ml-1.5">
                          truncated
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {relativeTime(r.startedUnix)}
                    </TableCell>
                    <TableCell className="text-right tabular-nums text-sm text-muted-foreground">
                      {formatBytes(r.sizeBytes)}
                    </TableCell>
                    <TableCell className="text-right">
                      {isPlayable(r) ? (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setTarget(r)}
                        >
                          <PlayCircle className="size-4" />
                          Play
                        </Button>
                      ) : (
                        <span className="text-xs text-muted-foreground">
                          in progress
                        </span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <Pagination
              total={total}
              pageSize={PAGE_SIZE}
              page={page}
              onPage={setPage}
              loading={loading}
            />
          </>
        )}
      </Card>

      {target && (
        <RecordingPlayer recording={target} onClose={() => setTarget(null)} />
      )}
    </div>
  )
}

function RowsSkeleton() {
  return (
    <div className="divide-y">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="flex items-center gap-4 px-3 py-3">
          <Skeleton className="h-4 w-36" />
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-5 w-14" />
          <Skeleton className="ml-auto h-4 w-16" />
        </div>
      ))}
    </div>
  )
}
