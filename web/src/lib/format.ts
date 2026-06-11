import { toast } from "sonner"

const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" })

/** Relative time from a unix-seconds timestamp, e.g. "12s ago", "3m ago". */
export function relativeTime(unixSeconds?: number): string {
  if (!unixSeconds || unixSeconds <= 0) return "never"
  const diffMs = unixSeconds * 1000 - Date.now()
  const diffSec = Math.round(diffMs / 1000)
  const abs = Math.abs(diffSec)

  if (abs < 60) return rtf.format(Math.round(diffSec), "second")
  const diffMin = Math.round(diffSec / 60)
  if (Math.abs(diffMin) < 60) return rtf.format(diffMin, "minute")
  const diffHr = Math.round(diffMin / 60)
  if (Math.abs(diffHr) < 24) return rtf.format(diffHr, "hour")
  const diffDay = Math.round(diffHr / 24)
  if (Math.abs(diffDay) < 30) return rtf.format(diffDay, "day")
  const diffMon = Math.round(diffDay / 30)
  if (Math.abs(diffMon) < 12) return rtf.format(diffMon, "month")
  return rtf.format(Math.round(diffMon / 12), "year")
}

/** Absolute local datetime string from unix seconds. */
export function absoluteTime(unixSeconds?: number): string {
  if (!unixSeconds || unixSeconds <= 0) return "—"
  return new Date(unixSeconds * 1000).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  })
}

/** Truncate a long id/hash for display, keeping head and tail. */
export function truncateMiddle(value: string, head = 8, tail = 6): string {
  if (!value) return ""
  if (value.length <= head + tail + 1) return value
  return `${value.slice(0, head)}…${value.slice(-tail)}`
}

export async function copyToClipboard(value: string, label = "Copied to clipboard") {
  try {
    await navigator.clipboard.writeText(value)
    toast.success(label)
  } catch {
    // Fallback for non-secure contexts.
    try {
      const el = document.createElement("textarea")
      el.value = value
      el.style.position = "fixed"
      el.style.opacity = "0"
      document.body.appendChild(el)
      el.select()
      document.execCommand("copy")
      document.body.removeChild(el)
      toast.success(label)
    } catch {
      toast.error("Could not copy to clipboard")
    }
  }
}
