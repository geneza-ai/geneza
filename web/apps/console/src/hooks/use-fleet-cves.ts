import { useMemo } from "react"

import { api } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import type { VulnFeedStatus, WorkspaceCVE, WorkspaceCVEsResponse } from "@/types"

export interface SevCount {
  crit: number
  high: number
  med: number
}

export interface FleetCves {
  loaded: boolean
  /**
   * The feed's own state. Undefined while loading, and — critically — the thing
   * that decides whether an empty result means "clean" or "we have never looked".
   */
  feed: VulnFeedStatus | null
  /** True when the feed is configured AND has advisories to match against. */
  scanned: boolean
  /** Set when the rollup could not be read (no permission, or an error). */
  error?: string
  /** Open (status=affected) rollup rows. */
  open: WorkspaceCVE[]
  /** Fleet-wide open counts by severity. */
  counts: SevCount
  /** Open counts per node key (rows carry node ids/names). */
  perNode: Map<string, SevCount>
  /** Distinct nodes with an open critical or high CVE. */
  atRisk: number
}

// The workspace CVE rollup, shared by the dashboard and the nodes list: one
// slow poll, with per-node open counts derived from the rows' node lists so
// list views never need a per-node fetch. The 200-row window covers any
// realistic workspace; beyond it the counts degrade to a floor, not an error.
export function useFleetCves(intervalMs = 30000): FleetCves {
  const { data, error } = usePolling<WorkspaceCVEsResponse>(
    (s) => api.getWorkspaceCVEs({ limit: 200 }, s),
    intervalMs
  )
  // The feed changes on the order of hours; poll it far more slowly than the
  // rollup, but do poll it so a first sync completing flips the UI on its own.
  const { data: feed } = usePolling<VulnFeedStatus>(
    (s) => api.getVulnFeedStatus(s),
    Math.max(intervalMs * 10, 300000)
  )
  return useMemo(() => {
    const open = (data?.cves ?? []).filter((r) => r.status === "affected")
    const counts: SevCount = { crit: 0, high: 0, med: 0 }
    const perNode = new Map<string, SevCount>()
    const risky = new Set<string>()
    for (const r of open) {
      const s = r.severity.toLowerCase()
      const bump = (c: SevCount) => {
        if (s === "critical") c.crit++
        else if (s === "high") c.high++
        else if (s === "medium" || s === "moderate") c.med++
      }
      bump(counts)
      for (const n of r.nodes) {
        const c = perNode.get(n) ?? { crit: 0, high: 0, med: 0 }
        bump(c)
        perNode.set(n, c)
        if (s === "critical" || s === "high") risky.add(n)
      }
    }
    return {
      loaded: !!data,
      feed,
      scanned: !!feed?.enabled && feed.advisoryCount > 0,
      error: error ? String(error) : undefined,
      open,
      counts,
      perNode,
      atRisk: risky.size,
    }
  }, [data, feed, error])
}

/** The risk left-edge class for a node row, per its open CVE counts. */
export function riskEdgeClass(counts?: SevCount): string {
  if (counts && counts.crit > 0) return "border-l-sev-crit"
  if (counts && counts.high > 0) return "border-l-sev-high"
  return "border-l-transparent"
}
