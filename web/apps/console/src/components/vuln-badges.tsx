import { ShieldAlert } from "lucide-react"

import { cn } from "@geneza/ui"
import { Badge } from "@/components/ui/badge"
import { severityKey, type SevKey } from "@/lib/severity"
import type { CVEStatus } from "@/types"

// The CVE state pill is deliberately quiet — colored text and a faint border,
// no fill. The severity dot next to it carries the alarm.
const STATUS_CLASS: Record<string, string> = {
  affected: "border-faint/40 text-faint",
  fixed: "border-success/35 text-success",
  not_affected: "border-muted-foreground/35 text-muted-foreground",
  under_investigation: "border-warning/35 text-warning",
}

const STATUS_LABEL: Record<string, string> = {
  affected: "open",
  fixed: "fixed",
  not_affected: "not affected",
  under_investigation: "investigating",
}

export function StatusBadge({ status }: { status: CVEStatus }) {
  return (
    <span
      className={cn(
        "inline-flex items-center whitespace-nowrap rounded-[5px] border px-2 py-0.5 font-mono text-[11px]",
        STATUS_CLASS[status] ?? "border-border text-muted-foreground"
      )}
    >
      {STATUS_LABEL[status] ?? status}
    </span>
  )
}

export function SeverityBadge({ severity }: { severity: string }) {
  if (!severity) return <span className="text-muted-foreground">—</span>
  const key = severityKey(severity)
  return (
    <Badge variant={key ?? "secondary"} className="lowercase">
      {severity}
    </Badge>
  )
}

// The 8px severity dot that anchors a CVE row.
const SEV_DOT: Record<SevKey, string> = {
  "sev-crit": "bg-sev-crit",
  "sev-high": "bg-sev-high",
  "sev-med": "bg-sev-med",
  "sev-low": "bg-sev-low",
}

export function SeverityDot({
  severity,
  className,
}: {
  severity: string
  className?: string
}) {
  const key = severityKey(severity)
  return (
    <span
      className={cn(
        "inline-block size-2 shrink-0 rounded-full",
        key ? SEV_DOT[key] : "bg-faint",
        className
      )}
    />
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
