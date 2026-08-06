import { cn } from "@geneza/ui"

export function StatusDot({
  online,
  className,
}: {
  online: boolean
  className?: string
}) {
  return (
    <span
      className={cn(
        "inline-block size-2 shrink-0 rounded-full",
        online ? "bg-success status-glow" : "bg-offline",
        className
      )}
    />
  )
}
