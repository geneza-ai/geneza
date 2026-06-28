import { useCallback, useEffect, useRef } from "react"

/**
 * Returns a stable function identity that always invokes the latest `callback`.
 * Useful for callbacks passed to effects without re-subscribing.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function useCallbackRef<T extends (...args: any[]) => any>(
  callback: T | undefined
): T {
  const ref = useRef(callback)

  useEffect(() => {
    ref.current = callback
  })

  const stable = useCallback((...args: Parameters<T>): ReturnType<T> => {
    return ref.current?.(...args) as ReturnType<T>
  }, [])

  return stable as T
}
