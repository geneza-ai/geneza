import { useEffect } from "react"
import { useLocation, useNavigate } from "react-router-dom"
import { Search } from "lucide-react"

import { useTheme } from "@/components/theme-provider"
import { useHeaderOverride } from "@/components/layout/page-header-context"
import { MobileNav } from "@/components/layout/mobile-nav"

const TITLES: Record<string, string> = {
  "/": "Dashboard",
  "/nodes": "Nodes",
  "/sessions": "Sessions",
  "/metrics": "Metrics",
  "/recordings": "Recordings",
  "/vulnerabilities": "Vulnerabilities",
  "/policy": "Policy",
  "/audit": "Audit log",
  "/tokens": "Node enrollment",
  "/members": "Members",
  "/activate": "Approve device login",
  "/404": "Not found",
}

function titleFor(pathname: string): string {
  if (TITLES[pathname]) return TITLES[pathname]
  // Match longest prefix for nested routes.
  const match = Object.keys(TITLES)
    .filter((p) => p !== "/" && pathname.startsWith(p))
    .sort((a, b) => b.length - a.length)[0]
  return match ? TITLES[match] : "Geneza"
}

// The fleet-search affordance: not an input itself, it jumps to the nodes list
// (whose toolbar owns the real search) — same target as the ⌘K shortcut.
function SearchAffordance({ onGo }: { onGo: () => void }) {
  return (
    <button
      onClick={onGo}
      className="hidden h-9 w-64 items-center gap-2 rounded-[9px] border bg-card px-3 text-faint transition-colors hover:border-input hover:text-muted-foreground lg:flex"
    >
      <Search className="size-[15px] shrink-0" />
      <span className="font-mono text-xs">Search fleet…</span>
      <kbd className="ml-auto rounded border px-1.5 py-px font-mono text-[10.5px]">
        ⌘K
      </kbd>
    </button>
  )
}

// Light/dark toggle, worn on the sleeve like the mock: a forest dot plus the
// current mode in machine text. The "system" preference stays in the user menu.
function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme()
  return (
    <button
      onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
      className="flex h-9 items-center gap-2 rounded-[9px] border bg-card px-3 font-mono text-[11.5px] text-foreground transition-colors hover:bg-accent"
      aria-label="Toggle color theme"
    >
      <span className="size-2 rounded-full bg-brand" />
      {resolvedTheme === "dark" ? "Dark" : "Light"}
    </button>
  )
}

export function Header() {
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const { override } = useHeaderOverride()

  const title = override?.title ?? titleFor(pathname)
  const crumb = override?.crumb

  const goSearch = () => navigate("/nodes", { state: { focusSearch: true } })

  // ⌘K / Ctrl-K jumps to the fleet search from anywhere.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault()
        navigate("/nodes", { state: { focusSearch: true } })
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [navigate])

  return (
    <header className="sticky top-0 z-20 flex h-[60px] shrink-0 items-center gap-4 border-b bg-background px-6">
      <div className="flex min-w-0 flex-1 items-center gap-2">
        <MobileNav />
        <div className="min-w-0">
          {crumb && (
            <p className="truncate font-mono text-[11px] leading-tight text-faint">
              {crumb}
            </p>
          )}
          <h1 className="truncate font-serif text-[21px] font-medium leading-tight tracking-tight">
            {title}
          </h1>
        </div>
      </div>
      <SearchAffordance onGo={goSearch} />
      <ThemeToggle />
    </header>
  )
}
