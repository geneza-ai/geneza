import { useLocation } from "react-router-dom"

import { useSession } from "@/components/session-context"

const TITLES: Record<string, string> = {
  "/": "Dashboard",
  "/machines": "Machines",
  "/sessions": "Sessions",
  "/policy": "Policy",
  "/audit": "Audit log",
  "/tokens": "Access tokens",
}

function titleFor(pathname: string): string {
  if (TITLES[pathname]) return TITLES[pathname]
  // Match longest prefix for nested routes.
  const match = Object.keys(TITLES)
    .filter((p) => p !== "/" && pathname.startsWith(p))
    .sort((a, b) => b.length - a.length)[0]
  return match ? TITLES[match] : "Geneza"
}

export function Header() {
  const { pathname } = useLocation()
  const { config } = useSession()
  const title = titleFor(pathname)

  return (
    <header className="sticky top-0 z-20 flex h-14 shrink-0 items-center justify-between gap-4 border-b bg-background/80 px-5 backdrop-blur">
      <h1 className="text-base font-semibold tracking-tight">{title}</h1>
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <span className="hidden sm:inline">Cluster</span>
        <span className="rounded-md border bg-muted/40 px-2 py-0.5 font-mono text-xs text-foreground">
          {config.clusterName}
        </span>
      </div>
    </header>
  )
}
