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
