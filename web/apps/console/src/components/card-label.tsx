import { cn } from "@geneza/ui"

/** Mono micro-caps section label used across the Console design's cards. */
export function CardLabel({
  children,
  className,
}: {
  children: React.ReactNode
  className?: string
}) {
  return (
    <div
      className={cn(
        "font-mono text-2xs uppercase tracking-[0.1em] text-faint",
        className
      )}
    >
      {children}
    </div>
  )
}
