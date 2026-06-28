import { Link } from "react-router-dom"

import { Button } from "@geneza/ui"

export function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-24 text-center">
      <p className="font-mono text-5xl font-semibold text-muted-foreground/40">
        404
      </p>
      <div>
        <p className="text-sm font-medium">Page not found</p>
        <p className="mt-1 text-sm text-muted-foreground">
          The page you’re looking for doesn’t exist.
        </p>
      </div>
      <Button asChild variant="outline" size="sm">
        <Link to="/">Back to dashboard</Link>
      </Button>
    </div>
  )
}
