import { useMemo } from "react"

import { api } from "@/api"
import { usePolling } from "@/hooks/use-polling"
import type { WorkspaceCVE, WorkspaceCVEsResponse } from "@/types"

export interface SevCount {
  crit: number
  high: number
  med: number
}

export interface FleetCves {
  loaded: boolean
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
  const { data } = usePolling<WorkspaceCVEsResponse>(
    (s) => api.getWorkspaceCVEs({ limit: 200 }, s),
    intervalMs
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
    return { loaded: !!data, open, counts, perNode, atRisk: risky.size }
  }, [data])
}

/** The risk left-edge class for a node row, per its open CVE counts. */
export function riskEdgeClass(counts?: SevCount): string {
  if (counts && counts.crit > 0) return "border-l-sev-crit"
  if (counts && counts.high > 0) return "border-l-sev-high"
  return "border-l-transparent"
}
