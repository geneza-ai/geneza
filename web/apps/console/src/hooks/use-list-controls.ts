import { useCallback } from "react"
import { useSearchParams } from "react-router-dom"

export interface ListControls {
  /** free-text search */
  q: string
  /** state filter ("all" = no filter) */
  state: string
  /** sort column */
  sort: string
  /** sort direction */
  order: "asc" | "desc"
  /** 1-based page */
  page: number
  /** derived row offset for the API */
  offset: number
  setQ: (v: string) => void
  setState: (v: string) => void
  setSort: (sort: string, order: "asc" | "desc") => void
  setPage: (page: number) => void
}

/**
 * Mirrors a list view's filter / sort / page into the URL query string, so every
 * view is bookmarkable and shareable and survives refresh + back/forward. Values
 * equal to their defaults are dropped from the URL to keep it clean; changing a
 * filter, the search or the sort resets to page 1.
 */
export function useListControls(opts: {
  pageSize: number
  defaultSort: string
  defaultOrder?: "asc" | "desc"
}): ListControls {
  const defaultOrder = opts.defaultOrder ?? "desc"
  const [params, setParams] = useSearchParams()

  const q = params.get("q") ?? ""
  const state = params.get("state") ?? "all"
  const sort = params.get("sort") ?? opts.defaultSort
  const order = (params.get("order") === "asc" ? "asc" : params.get("order") === "desc" ? "desc" : defaultOrder)
  const page = Math.max(1, Number.parseInt(params.get("page") ?? "1", 10) || 1)
  const offset = (page - 1) * opts.pageSize

  const update = useCallback(
    (next: Record<string, string | undefined>) => {
      setParams(
        (prev) => {
          const p = new URLSearchParams(prev)
          for (const [k, v] of Object.entries(next)) {
            if (v === undefined || v === "") p.delete(k)
            else p.set(k, v)
          }
          return p
        },
        { replace: false } // each distinct view is a history entry (back/forward)
      )
    },
    [setParams]
  )

  return {
    q,
    state,
    sort,
    order,
    page,
    offset,
    setQ: (v) => update({ q: v || undefined, page: undefined }),
    setState: (v) => update({ state: v === "all" ? undefined : v, page: undefined }),
    setSort: (s, o) =>
      update({
        sort: s === opts.defaultSort && o === defaultOrder ? undefined : s,
        order: s === opts.defaultSort && o === defaultOrder ? undefined : o,
        page: undefined,
      }),
    setPage: (pg) => update({ page: pg <= 1 ? undefined : String(pg) }),
  }
}
