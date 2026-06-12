import { Badge } from "@/components/ui/badge"
import type { SessionAction, SessionState } from "@/types"

export function ActionBadge({ action }: { action: SessionAction }) {
  return (
    <Badge variant="secondary" className="font-mono text-[11px]">
      {action}
    </Badge>
  )
}

const STATE_VARIANT: Record<
  string,
  "success" | "muted" | "warning" | "secondary" | "destructive"
> = {
  active: "success",
  detached: "warning",
  pending: "secondary",
  ended: "muted",
  revoked: "destructive",
}

export function StateBadge({ state }: { state: SessionState }) {
  const variant = STATE_VARIANT[state] ?? "secondary"
  return (
    <Badge variant={variant} className="capitalize">
      {state}
    </Badge>
  )
}
