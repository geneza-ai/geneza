import { Badge } from "@/components/ui/badge"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import type { SevCount } from "@/hooks/use-fleet-cves"

/**
 * A node's open-CVE pills — "N crit / N high / N med", or a verdict for the
 * no-findings case.
 *
 * `scanned` is not optional decoration. Zero findings means one of three very
 * different things: the node really is clean, no CVE feed was ever configured (so
 * nothing was ever matched), or a feed is configured but has not finished its first
 * sync. Rendering a green "clean" for all three is the worst option available,
 * because nobody investigates a green badge.
 */
export function NodeCvePills({
  counts,
  scanned,
}: {
  counts?: SevCount
  /** True only when a feed is configured AND has advisories to match against. */
  scanned?: boolean
}) {
  const none =
    !counts || (counts.crit === 0 && counts.high === 0 && counts.med === 0)
  if (none) {
    if (!scanned) {
      return (
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge variant="outline" className="text-muted-foreground">
              not scanned
            </Badge>
          </TooltipTrigger>
          <TooltipContent>
            No CVE feed has produced advisories yet, so nothing has been matched
            against this node. Set vuln_feed.source in the controller config.
          </TooltipContent>
        </Tooltip>
      )
    }
    return <Badge variant="success">clean</Badge>
  }
  return (
    <div className="flex flex-wrap gap-1.5">
      {counts.crit > 0 && <Badge variant="sev-crit">{counts.crit} crit</Badge>}
      {counts.high > 0 && <Badge variant="sev-high">{counts.high} high</Badge>}
      {counts.med > 0 && <Badge variant="sev-med">{counts.med} med</Badge>}
    </div>
  )
}
