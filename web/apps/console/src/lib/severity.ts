// Severity is a free-text label from the advisory feed; map the well-known
// ratings onto the design's severity scale.
export type SevKey = "sev-crit" | "sev-high" | "sev-med" | "sev-low"

const SEVERITY_KEY: Record<string, SevKey> = {
  critical: "sev-crit",
  high: "sev-high",
  medium: "sev-med",
  moderate: "sev-med",
  low: "sev-low",
  negligible: "sev-low",
}

export function severityKey(severity: string): SevKey | null {
  return SEVERITY_KEY[severity.toLowerCase()] ?? null
}
