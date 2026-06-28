import { Badge } from "@/components/ui/badge"

// Maps a node's worst CVE severity to a coloured badge. An empty severity (no
// findings) renders as a muted dash so a clean node reads as clean, not unknown.
export function SeverityBadge({ severity }: { severity: string }) {
  const s = severity.toUpperCase()
  if (!s) return <span className="text-muted-foreground">—</span>
  switch (s) {
    case "CRITICAL":
      return <Badge variant="destructive">Critical</Badge>
    case "HIGH":
      return <Badge variant="warning">High</Badge>
    case "MEDIUM":
      return <Badge variant="secondary">Medium</Badge>
    case "LOW":
      return <Badge variant="muted">Low</Badge>
    default:
      return <Badge variant="outline">{severity}</Badge>
  }
}

export function OutdatedBadge({ outdated }: { outdated: boolean }) {
  return outdated ? (
    <Badge variant="warning">Outdated</Badge>
  ) : (
    <Badge variant="success">Current</Badge>
  )
}

export function OnlineBadge({ online }: { online: boolean }) {
  return online ? (
    <Badge variant="success">Online</Badge>
  ) : (
    <Badge variant="muted">Offline</Badge>
  )
}
