import { useCallbackRef } from "@/hooks/use-callback-ref"
import { useEffect, useMemo, useRef, useState } from "react"

import { api } from "@/api"
import type { PromResponse, PromSeries } from "@/types"

// A point keyed by unix-second timestamp; one numeric column per series.
export type ChartRow = { t: number } & Record<string, number | null>

// matrixToRows merges a Prometheus matrix into a single time-indexed table that
// Recharts consumes directly. seriesName maps each series' labels to a column.
export function matrixToRows(
  series: PromSeries[],
  seriesName: (labels: Record<string, string>) => string
): { rows: ChartRow[]; keys: string[] } {
  const byT = new Map<number, ChartRow>()
  const keys = new Set<string>()
  for (const s of series) {
    const key = seriesName(s.metric)
    keys.add(key)
    for (const [t, v] of s.values ?? []) {
      let row = byT.get(t)
      if (!row) {
        row = { t }
        byT.set(t, row)
      }
      const num = Number(v)
      row[key] = Number.isFinite(num) ? num : null
    }
  }
  const rows = [...byT.values()].sort((a, b) => a.t - b.t)
  return { rows, keys: [...keys] }
}

// useMetricRange polls a PromQL range query over a trailing window and returns
// merged chart rows. instance is substituted into the query as the node label.
export function useMetricRange(
  query: string,
  windowSec: number,
  seriesName: (labels: Record<string, string>) => string,
  opts?: { stepSec?: number; refreshMs?: number; enabled?: boolean }
) {
  const stepSec = opts?.stepSec ?? Math.max(15, Math.round(windowSec / 240))
  const refreshMs = opts?.refreshMs ?? 15000
  const enabled = opts?.enabled ?? true

  const [data, setData] = useState<{ rows: ChartRow[]; keys: string[] }>({
    rows: [],
    keys: [],
  })
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const nameRef = useCallbackRef(seriesName)
  const firstRef = useRef(true)

  useEffect(() => {
    if (!enabled) return
    let active = true
    const ctrl = new AbortController()
    firstRef.current = true

    const run = async () => {
      const end = Math.floor(Date.now() / 1000)
      const start = end - windowSec
      try {
        const resp: PromResponse = await api.queryRange(
          query,
          start,
          end,
          stepSec,
          ctrl.signal
        )
        if (!active) return
        if (resp.status !== "success" || !resp.data) {
          setError(resp.error ?? "query failed")
        } else {
          setError(null)
          setData(matrixToRows(resp.data.result, nameRef))
        }
      } catch (e) {
        if (!active || (e as Error).name === "AbortError") return
        setError((e as Error).message)
      } finally {
        if (active) setLoading(false)
      }
    }

    run()
    const id = setInterval(run, refreshMs)
    return () => {
      active = false
      ctrl.abort()
      clearInterval(id)
    }
  }, [query, windowSec, stepSec, refreshMs, enabled, nameRef])

  return useMemo(() => ({ ...data, error, loading }), [data, error, loading])
}

// promInstance escapes a node name for safe interpolation into a label matcher.
export function promInstance(node: string): string {
  return node.replace(/[\\"]/g, "\\$&")
}
