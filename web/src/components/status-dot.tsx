import { cn } from "@/lib/utils"

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
        online
          ? "bg-[var(--success)] shadow-[0_0_0_3px_color-mix(in_oklch,var(--success)_18%,transparent)]"
          : "bg-muted-foreground/40",
        className
      )}
    />
  )
}
