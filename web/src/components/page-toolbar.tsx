import { RefreshCw } from "lucide-react"

import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

export function PageToolbar({
  title,
  description,
  children,
  onRefresh,
  refreshing,
}: {
  title?: string
  description?: string
  children?: React.ReactNode
  onRefresh?: () => void
  refreshing?: boolean
}) {
  return (
    <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
      <div className="min-w-0">
        {title && (
          <h2 className="text-sm font-semibold tracking-tight">{title}</h2>
        )}
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
