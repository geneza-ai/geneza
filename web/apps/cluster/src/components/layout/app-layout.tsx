import { NavLink, Outlet } from "react-router-dom"
import { Boxes, LogOut, Moon, Network, ShieldAlert, Sun } from "lucide-react"

import { cn } from "@geneza/ui"
import { useTheme } from "@/components/theme-provider"
import { useSession } from "@/components/session-context"
import { Button } from "@geneza/ui"

interface NavItem {
  to: string
  label: string
  icon: React.ElementType
  end?: boolean
}

const NAV: NavItem[] = [
  { to: "/", label: "Cluster", icon: Network, end: true },
  { to: "/agents", label: "Agents", icon: Boxes },
  { to: "/risk", label: "Risk", icon: ShieldAlert },
]

function Brand() {
  return (
    <div className="flex h-14 items-center gap-2 px-5">
      <div className="flex size-7 items-center justify-center rounded-md bg-primary text-primary-foreground">
        <Network className="size-4" />
      </div>
      <div className="flex flex-col leading-none">
        <span className="text-sm font-semibold tracking-tight">Geneza</span>
        <span className="text-[11px] text-muted-foreground">Cluster operator</span>
      </div>
    </div>
  )
}

function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme()
  return (
    <Button
      variant="ghost"
      size="icon-sm"
      aria-label="Toggle theme"
      onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
    >
      {resolvedTheme === "dark" ? <Sun /> : <Moon />}
    </Button>
  )
}

function Sidebar() {
  return (
    <aside className="hidden w-60 shrink-0 flex-col border-r bg-sidebar md:flex">
      <Brand />
      <nav className="flex-1 space-y-0.5 px-3 py-2">
        {NAV.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-sidebar-accent text-sidebar-accent-foreground"
                  : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground"
              )
            }
          >
            <item.icon className="size-4 shrink-0" />
            {item.label}
          </NavLink>
        ))}
      </nav>
      <div className="border-t px-3 py-3 text-[11px] text-muted-foreground">
        Break-glass cluster console
      </div>
    </aside>
  )
}

function SessionMenu() {
  const session = useSession()
  if (!session) return null
  const { me, signOut } = session
  return (
    <div className="flex items-center gap-2">
      <div className="hidden flex-col items-end leading-none sm:flex">
        <span className="text-sm font-medium">{me.user}</span>
        <span className="text-[11px] text-muted-foreground">
          {me.auth === "cert" ? "break-glass cert" : "SSO"}
        </span>
      </div>
      {me.auth === "oidc" && (
        <Button
          variant="ghost"
          size="icon-sm"
          aria-label="Sign out"
          title="Sign out"
          onClick={signOut}
        >
          <LogOut />
        </Button>
      )}
    </div>
  )
}

export function AppLayout() {
  return (
    <div className="flex min-h-screen bg-background text-foreground">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 items-center justify-between gap-3 border-b px-5">
          <span className="text-sm font-semibold tracking-tight md:hidden">
            Geneza Cluster
          </span>
          <div className="ml-auto flex items-center gap-3">
            <SessionMenu />
            <ThemeToggle />
          </div>
        </header>
        {/* Top nav for narrow screens. */}
        <nav className="flex gap-1 border-b px-3 py-2 md:hidden">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
                  isActive
                    ? "bg-sidebar-accent text-sidebar-accent-foreground"
                    : "text-muted-foreground hover:bg-sidebar-accent/60"
                )
              }
            >
              <item.icon className="size-4" />
              {item.label}
            </NavLink>
          ))}
        </nav>
        <main className="min-w-0 flex-1 p-5 lg:p-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
