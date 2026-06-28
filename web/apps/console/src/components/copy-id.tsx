import { Check, Copy } from "lucide-react"
import { useState } from "react"

import { cn } from "@geneza/ui"
import { copyToClipboard, truncateMiddle } from "@/lib/format"

interface CopyIdProps {
  value: string
  /** Display the full value instead of a truncated middle. */
  full?: boolean
  head?: number
  tail?: number
  className?: string
  label?: string
}

/** Monospace id/hash with a click-to-copy affordance. */
export function CopyId({
  value,
  full = false,
  head = 8,
  tail = 6,
  className,
  label = "ID copied",
}: CopyIdProps) {
  const [copied, setCopied] = useState(false)

  if (!value) return <span className="text-muted-foreground">—</span>

  const display = full ? value : truncateMiddle(value, head, tail)

  const onCopy = async () => {
    await copyToClipboard(value, label)
    setCopied(true)
    setTimeout(() => setCopied(false), 1200)
  }

  return (
    <button
      type="button"
      onClick={onCopy}
      title={value}
      className={cn(
        "group inline-flex max-w-full items-center gap-1.5 rounded font-mono text-xs text-muted-foreground transition-colors hover:text-foreground",
        className
      )}
    >
      <span className="truncate">{display}</span>
      {copied ? (
        <Check className="size-3 shrink-0 text-success" />
      ) : (
        <Copy className="size-3 shrink-0 opacity-0 transition-opacity group-hover:opacity-100" />
      )}
    </button>
  )
}
