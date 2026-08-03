import { cn } from "@geneza/ui"

export function StatusDot({
  online,
  pulse,
  className,
}: {
  online: boolean
  /** Throb the dot for a transitional state (connecting / updating). */
  pulse?: boolean
  className?: string
}) {
  return (
    <span
      className={cn(
        "inline-block size-2 shrink-0 rounded-full",
        online ? "bg-success status-glow" : "bg-offline",
        pulse && "animate-live-pulse",
        className
      )}
    />
  )
}
