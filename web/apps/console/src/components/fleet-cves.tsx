import { Badge } from "@/components/ui/badge"
import type { SevCount } from "@/hooks/use-fleet-cves"

/** A node's open-CVE pills — "N crit / N high / N med", or a clean tick. */
export function NodeCvePills({ counts }: { counts?: SevCount }) {
  if (!counts || (counts.crit === 0 && counts.high === 0 && counts.med === 0)) {
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
