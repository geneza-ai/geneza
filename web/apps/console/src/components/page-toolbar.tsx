import { RefreshCw } from "lucide-react"

import { Button } from "@geneza/ui"
import { cn } from "@geneza/ui"

export function PageToolbar({
  description,
  children,
  onRefresh,
  refreshing,
}: {
  description?: string
  children?: React.ReactNode
  onRefresh?: () => void
  refreshing?: boolean
}) {
  return (
    <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
      <div className="min-w-0">
        {description && (
          <p className="text-sm text-muted-foreground">{description}</p>
        )}
      </div>
      <div className="flex items-center gap-2">
        {children}
        {onRefresh && (
          <Button
            variant="outline"
            size="icon-sm"
            onClick={onRefresh}
            title="Refresh"
          >
            <RefreshCw
              className={cn("size-3.5", refreshing && "animate-spin")}
            />
          </Button>
        )}
      </div>
    </div>
  )
}
