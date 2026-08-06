import { useEffect, useState } from "react"

/**
 * Returns `value` after it has stopped changing for `delayMs`.
 *
 * Use it for any input that is a query dependency. On the audit view this is
 * load-bearing rather than cosmetic: every audit read takes the same mutex the
 * append path needs and scans the whole chain file, so an undebounced keystroke
 * stalled audit writes across the fleet.
 */
export function useDebounced<T>(value: T, delayMs = 300): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delayMs)
    return () => clearTimeout(t)
  }, [value, delayMs])
  return debounced
}
