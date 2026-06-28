import { useState } from "react"
import { ShieldCheck } from "lucide-react"

import { usePolling } from "@/hooks/use-polling"
import { api } from "@/api"
import { Button } from "@geneza/ui"
import { Card } from "@geneza/ui"
import { EmptyState, ErrorState } from "@/components/states"
import { Pagination } from "@/components/data-pagination"
import { CVETable } from "@/components/cve-table"
import type { NodeCVEsResponse } from "@/types"

const PAGE_SIZE = 25

// NodeVulnerabilities is the by-node view: a node's CVE verdicts with an
// "affected only" toggle. Pagination is server-driven, like the other lists.
export function NodeVulnerabilities({ nodeId }: { nodeId: string }) {
  const [affectedOnly, setAffectedOnly] = useState(false)
  const [page, setPage] = useState(1)
  const offset = (page - 1) * PAGE_SIZE

  const { data, error, initialLoading, loading, refresh } =
    usePolling<NodeCVEsResponse>(
      (s) =>
        api.getNodeCVEs(
          nodeId,
          { affectedOnly, limit: PAGE_SIZE, offset },
          s
        ),
      30000,
      [nodeId, affectedOnly, offset]
    )

  const rows = data?.cves ?? []
  const total = data?.total ?? 0

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm text-muted-foreground">
          {total} {affectedOnly ? "affected " : ""}
          finding{total === 1 ? "" : "s"}
        </p>
        <Button
          variant={affectedOnly ? "default" : "outline"}
          size="sm"
          onClick={() => {
            setAffectedOnly((v) => !v)
            setPage(1)
          }}
        >
          Affected only
        </Button>
      </div>

      <Card className="overflow-hidden p-0">
        {error && !data ? (
          <ErrorState message={error} onRetry={refresh} />
        ) : initialLoading ? (
          <div className="px-4 py-10 text-center text-sm text-muted-foreground">
            Loading…
          </div>
        ) : total === 0 ? (
          <EmptyState
            icon={<ShieldCheck className="size-8" />}
            title={affectedOnly ? "No affected findings" : "No findings"}
            message={
              affectedOnly
                ? "Nothing on this node is currently affected."
                : "No vulnerabilities have been matched against this node's inventory yet."
            }
          />
        ) : (
          <>
            <CVETable rows={rows} />
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
    </div>
  )
}
