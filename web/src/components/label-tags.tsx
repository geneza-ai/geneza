import { Badge } from "@/components/ui/badge"

export function LabelTags({
  labels,
  max,
}: {
  labels: Record<string, string>
  max?: number
}) {
  const entries = Object.entries(labels ?? {})
  if (entries.length === 0)
    return <span className="text-xs text-muted-foreground">—</span>

  const shown = max ? entries.slice(0, max) : entries
  const overflow = max ? entries.length - shown.length : 0

  return (
    <div className="flex flex-wrap gap-1">
      {shown.map(([k, v]) => (
        <Badge
          key={k}
          variant="muted"
          className="max-w-[160px] truncate font-mono text-[10px]"
          title={`${k}=${v}`}
        >
          {k}
          <span className="opacity-50">=</span>
          {v}
        </Badge>
      ))}
      {overflow > 0 && (
        <Badge variant="muted" className="text-[10px]">
          +{overflow}
        </Badge>
      )}
    </div>
  )
}
