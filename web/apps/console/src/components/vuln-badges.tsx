import { ShieldAlert } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import type { CVEStatus } from "@/types"

const STATUS_VARIANT: Record<
  string,
  "success" | "muted" | "warning" | "secondary" | "destructive"
> = {
  affected: "destructive",
  fixed: "success",
  not_affected: "muted",
  under_investigation: "warning",
}

const STATUS_LABEL: Record<string, string> = {
  affected: "Affected",
  fixed: "Fixed",
  not_affected: "Not affected",
  under_investigation: "Investigating",
}

export function StatusBadge({ status }: { status: CVEStatus }) {
  const variant = STATUS_VARIANT[status] ?? "secondary"
  return <Badge variant={variant}>{STATUS_LABEL[status] ?? status}</Badge>
}

// Severity is a free-text label from the advisory feed; colour the well-known
// ratings and fall back to a neutral badge for anything unrecognized.
const SEVERITY_VARIANT: Record<string, "destructive" | "warning" | "muted"> = {
  critical: "destructive",
  high: "destructive",
  medium: "warning",
  moderate: "warning",
  low: "muted",
  negligible: "muted",
}

export function SeverityBadge({ severity }: { severity: string }) {
  if (!severity) return <span className="text-muted-foreground">—</span>
  const variant = SEVERITY_VARIANT[severity.toLowerCase()] ?? "secondary"
  return (
    <Badge variant={variant} className="capitalize">
      {severity}
    </Badge>
  )
}

// KEV — the package is in CISA's Known-Exploited-Vulnerabilities catalog. This is
// the loudest triage signal, so it gets a prominent destructive badge with an icon.
export function KevBadge({ kev }: { kev: boolean }) {
  if (!kev) return <span className="text-muted-foreground">—</span>
  return (
    <Badge variant="destructive" className="gap-1">
      <ShieldAlert className="size-3" />
      KEV
    </Badge>
  )
}

// EPSS is the exploit-prediction probability (0..1); render it as a percentage,
// emphasising the higher-risk scores for triage.
export function EpssScore({ epss }: { epss: number }) {
  if (!epss || epss <= 0) {
    return <span className="text-muted-foreground">—</span>
  }
  const pct = epss * 100
  const cls =
    pct >= 50
      ? "text-destructive font-medium"
      : pct >= 10
        ? "text-warning"
        : "text-muted-foreground"
  return <span className={cls}>{pct.toFixed(pct < 1 ? 2 : 1)}%</span>
}
