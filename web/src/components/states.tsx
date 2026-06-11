import { AlertTriangle, Inbox, RefreshCw } from "lucide-react"

import { Button } from "@/components/ui/button"

export function EmptyState({
  title = "Nothing here yet",
  message,
  icon,
}: {
  title?: string
  message?: string
  icon?: React.ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-16 text-center">
      <div className="mb-1 text-muted-foreground/60">
        {icon ?? <Inbox className="size-8" />}
      </div>
      <p className="text-sm font-medium">{title}</p>
      {message && (
        <p className="max-w-sm text-sm text-muted-foreground">{message}</p>
      )}
    </div>
  )
}

export function ErrorState({
  message,
  onRetry,
}: {
  message?: string
  onRetry?: () => void
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-16 text-center">
      <AlertTriangle className="size-8 text-destructive" />
      <div>
        <p className="text-sm font-medium">Couldn’t load data</p>
        {message && (
          <p className="mt-1 max-w-md text-sm text-muted-foreground">
            {message}
          </p>
        )}
      </div>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RefreshCw className="size-3.5" />
          Retry
        </Button>
      )}
    </div>
  )
}
