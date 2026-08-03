import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@geneza/ui"

// Pills read as machine annotations: mono micro-caps, a tinted wash and a
// slightly stronger border in the same hue (the Console design's badge()).
const badgeVariants = cva(
  "inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-0.5 font-mono text-2xs font-semibold transition-colors focus:outline-none",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground",
        secondary: "border-border bg-secondary text-secondary-foreground",
        outline: "text-foreground",
        muted: "border-transparent bg-muted text-muted-foreground",
        destructive: "border-destructive/30 bg-destructive/13 text-destructive",
        success: "border-success/30 bg-success/13 text-success",
        warning: "border-warning/30 bg-warning/13 text-warning",
        "sev-crit": "border-sev-crit/30 bg-sev-crit/13 text-sev-crit",
        "sev-high": "border-sev-high/30 bg-sev-high/13 text-sev-high",
        "sev-med": "border-sev-med/30 bg-sev-med/13 text-sev-med",
        "sev-low": "border-sev-low/30 bg-sev-low/13 text-sev-low",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}

export { Badge, badgeVariants }
