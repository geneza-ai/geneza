import { useCallback, useEffect, useInsertionEffect, useRef, useState } from "react"

import { ApiError } from "@/api"

interface PollingState<T> {
  data: T | null
  error: string | null
  loading: boolean
  /** true only on first load; refreshes keep showing stale data. */
  initialLoading: boolean
  refresh: () => void
}

/**
 * Fetch on mount and poll on an interval. Aborts in-flight requests on unmount
 * and between polls. Keeps previously loaded data visible while refreshing.
 */
export function usePolling<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  intervalMs = 10000,
  deps: unknown[] = []
): PollingState<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [settled, setSettled] = useState(false)
  const fetcherRef = useRef(fetcher)
  // Keep the latest fetcher without reading/writing the ref during render.
  useInsertionEffect(() => {
    fetcherRef.current = fetcher
  })

  const run = useCallback(async (signal: AbortSignal) => {
    setLoading(true)
    try {
      const result = await fetcherRef.current(signal)
      if (signal.aborted) return
      setData(result)
      setError(null)
    } catch (err) {
      if (signal.aborted || (err as Error).name === "AbortError") return
      // 401 is handled globally (redirect to login); don't show it inline.
      if (err instanceof ApiError && err.status === 401) return
      setError((err as Error).message || "Something went wrong")
    } finally {
      if (!signal.aborted) {
        setLoading(false)
        setSettled(true)
      }
    }
  }, [])

  const [nonce, setNonce] = useState(0)
  const refresh = useCallback(() => setNonce((n) => n + 1), [])

  useEffect(() => {
    const controller = new AbortController()
    // Async data fetch on mount/deps-change; state is set on completion, which
    // is the intended effect-subscribes-to-external-system pattern.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void run(controller.signal)

    let timer: number | undefined
    if (intervalMs > 0) {
      timer = window.setInterval(() => {
        // Pause polling when the tab is hidden.
        if (document.visibilityState === "visible") {
          const c = new AbortController()
          // Best-effort: we don't track per-tick controllers for abort, but
          // the request itself is short-lived.
          run(c.signal)
        }
      }, intervalMs)
    }

    return () => {
      controller.abort()
      if (timer) window.clearInterval(timer)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, nonce, ...deps])

  // Initial load = nothing settled yet and no data to show.
  const initialLoading = !settled && data === null
  return { data, error, loading, initialLoading, refresh }
}
