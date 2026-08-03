import {
  FileText,
  KeyRound,
  LogIn,
  RefreshCw,
  ShieldCheck,
  TerminalSquare,
  UserPlus,
} from "lucide-react"

import { cn } from "@geneza/ui"

const ICONS: Record<string, React.ElementType> = {
  login_success: LogIn,
  login: LogIn,
  session_request: TerminalSquare,
  session_event: TerminalSquare,
  session_start: TerminalSquare,
  session_end: TerminalSquare,
  enroll: UserPlus,
  token_create: KeyRound,
  cert_renew: RefreshCw,
  policy_eval: ShieldCheck,
}

export function AuditTypeIcon({ type, className }: { type: string; className?: string }) {
  const Icon = ICONS[type] ?? (type.startsWith("session") ? TerminalSquare : FileText)
  return <Icon className={cn("size-4", className)} />
}

// Maps an audit record type onto the design's activity-tag tones: outcomes
// that deny or break something read as danger, transitions as warning,
// grants/arrivals as success, and bookkeeping stays quiet.
function auditTone(type: string): string {
  const t = type.toLowerCase()
  if (/fail|deny|denied|revoke|quarantine|broken/.test(t))
    return "border-destructive/35 text-destructive"
  if (/policy|rollout|canary|pending/.test(t)) return "border-warning/35 text-warning"
  if (/login|enroll|approve|token|grant|session_start|session_request/.test(t))
    return "border-success/35 text-success"
  return "border-faint/40 text-faint"
}

/** The mono event-kind tag that opens an activity/audit row. */
export function AuditTag({ type }: { type: string }) {
  return (
    <span
      className={cn(
        "inline-flex min-w-[58px] items-center justify-center whitespace-nowrap rounded-[5px] border px-2 py-0.5 font-mono text-[11px]",
        auditTone(type)
      )}
    >
      {type}
    </span>
  )
}
