import { NavLink } from "react-router-dom"
import {
  Activity,
  KeyRound,
  LayoutDashboard,
  ScrollText,
  Server,
  Shield,
  TerminalSquare,
} from "lucide-react"

import { cn } from "@/lib/utils"
import { useSession } from "@/components/session-context"
import { UserMenu } from "@/components/layout/user-menu"

interface NavItem {
  to: string
  label: string
  icon: React.ElementType
  end?: boolean
  adminOnly?: boolean
}

const NAV: NavItem[] = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/machines", label: "Machines", icon: Server },
  { to: "/sessions", label: "Sessions", icon: TerminalSquare },
  { to: "/policy", label: "Policy", icon: Shield },
  { to: "/audit", label: "Audit log", icon: ScrollText },
  { to: "/tokens", label: "Access tokens", icon: KeyRound, adminOnly: true },
]

export function Sidebar() {
  const { me } = useSession()
  const items = NAV.filter((i) => !i.adminOnly || me.admin)

  return (
    <aside className="hidden w-60 shrink-0 flex-col border-r bg-sidebar text-sidebar-foreground md:flex">
      <div className="flex h-14 items-center gap-2 px-5">
        <div className="flex size-7 items-center justify-center rounded-md bg-primary text-primary-foreground">
          <Activity className="size-4" />
        </div>
        <span className="text-sm font-semibold tracking-tight">Geneza</span>
      </div>

      <nav className="flex-1 space-y-0.5 px-3 py-2">
        {items.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-sidebar-accent text-sidebar-accent-foreground"
                  : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground"
              )
            }
          >
            <item.icon className="size-4 shrink-0" />
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="border-t p-3">
        <UserMenu />
      </div>
    </aside>
  )
}
