import {
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  ChevronsUpDown,
  ChevronUp,
} from "lucide-react"

import { Button } from "@geneza/ui"
import { TableHead } from "@/components/ui/table"
import { cn } from "@geneza/ui"

export interface SortState {
  sort: string
  order: "asc" | "desc"
}

/** Server-driven pagination footer: row range, page X of Y, and page nav. */
export function Pagination({
  total,
  pageSize,
  page,
  onPage,
  loading,
}: {
  total: number
  pageSize: number
  page: number // 1-based
  onPage: (page: number) => void
  loading?: boolean
}) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const cur = Math.min(Math.max(1, page), totalPages)
  const from = total === 0 ? 0 : (cur - 1) * pageSize + 1
  const to = Math.min(cur * pageSize, total)
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 border-t px-3 py-2 text-sm text-muted-foreground">
      <span>
        {total === 0 ? "No results" : `${from}–${to} of ${total}`}
        {loading ? " · refreshing…" : ""}
      </span>
      <div className="flex items-center gap-3">
        <span className="tabular-nums">
          Page {cur} of {totalPages}
        </span>
        <div className="flex items-center gap-1">
          <Button
            variant="outline"
            size="icon"
            className="size-8"
            disabled={cur <= 1}
            onClick={() => onPage(1)}
            aria-label="First page"
          >
            <ChevronsLeft className="size-4" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="size-8"
            disabled={cur <= 1}
            onClick={() => onPage(cur - 1)}
            aria-label="Previous page"
          >
            <ChevronLeft className="size-4" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="size-8"
            disabled={cur >= totalPages}
            onClick={() => onPage(cur + 1)}
            aria-label="Next page"
          >
            <ChevronRight className="size-4" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="size-8"
            disabled={cur >= totalPages}
            onClick={() => onPage(totalPages)}
            aria-label="Last page"
          >
            <ChevronsRight className="size-4" />
          </Button>
        </div>
      </div>
    </div>
  )
}

/** A column header that toggles server-side sort (asc → desc) on click. */
export function SortableHead({
  label,
  col,
  sort,
  className,
  onSort,
}: {
  label: string
  col: string
  sort: SortState
  className?: string
  onSort: (s: SortState) => void
}) {
  const active = sort.sort === col
  const next: SortState = active
    ? { sort: col, order: sort.order === "asc" ? "desc" : "asc" }
    : { sort: col, order: "asc" }
  const Icon = !active ? ChevronsUpDown : sort.order === "asc" ? ChevronUp : ChevronDown
  return (
    <TableHead className={className}>
      <button
        type="button"
        className="inline-flex items-center gap-1 hover:text-foreground"
        onClick={() => onSort(next)}
      >
        {label}
        <Icon
          className={cn(
            "size-3.5",
            active ? "text-foreground" : "text-muted-foreground/50"
          )}
        />
      </button>
    </TableHead>
  )
}
