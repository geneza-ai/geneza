import { NavLink } from "react-router-dom"
import {
  Activity,
  KeyRound,
  LayoutDashboard,
  ScrollText,
  Server,
  Shield,
  ShieldX,
  TerminalSquare,
  Video,
} from "lucide-react"

import { cn } from "@geneza/ui"
import { useSession } from "@/components/session-context"

interface NavItem {
  to: string
  label: string
  icon: React.ElementType
  end?: boolean
  adminOnly?: boolean
  // Replaying a shell is privileged; the recordings entry is shown only to the
  // workspace audit/replay roles (admins implicitly hold the capability too).
  auditorOnly?: boolean
  // Shown only when the workspace actually records sessions (recordingEnabled),
  // so a recording-disabled workspace doesn't surface an empty Recordings page.
  requiresRecording?: boolean
}

interface NavGroup {
  label: string
  items: NavItem[]
}

// The roles that may list/replay recordings, mirroring the controller's
// consoleCanReplayRecordings gate. ws-admin is covered by me.admin.
const REPLAY_ROLES = new Set(["ws-auditor", "ws-admin", "admin", "platform-admin"])

// Navigation is grouped so the rail reads as sections rather than one long list,
// and so low-traffic entries fold under a heading instead of competing with the
// daily-driver views.
const GROUPS: NavGroup[] = [
  {
    label: "Fleet",
    items: [
      { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
      { to: "/nodes", label: "Nodes", icon: Server },
      { to: "/sessions", label: "Sessions", icon: TerminalSquare },
      { to: "/metrics", label: "Metrics", icon: Activity },
    ],
  },
  {
    label: "Security",
    items: [
      { to: "/recordings", label: "Recordings", icon: Video, auditorOnly: true, requiresRecording: true },
      { to: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldX },
      { to: "/policy", label: "Policy", icon: Shield },
      { to: "/audit", label: "Audit log", icon: ScrollText },
    ],
  },
  {
    label: "Admin",
    items: [
      { to: "/tokens", label: "Access tokens", icon: KeyRound, adminOnly: true },
    ],
  },
]

// Resolves the nav groups the current user is permitted to see, dropping any
// group left empty after role filtering.
function useNavGroups(): NavGroup[] {
  const { me } = useSession()
  const canReplay = me.admin || me.roles.some((r) => REPLAY_ROLES.has(r))
  return GROUPS.map((g) => ({
    ...g,
    items: g.items.filter(
      (i) =>
        (!i.adminOnly || me.admin) &&
        (!i.auditorOnly || canReplay) &&
        (!i.requiresRecording || !!me.recordingEnabled)
    ),
  })).filter((g) => g.items.length > 0)
}

// The Geneza wordmark shown at the top of the sidebar / mobile drawer.
function Brand() {
  return (
    <div className="flex h-14 items-center gap-2 px-3.5">
      <div className="flex size-7 shrink-0 items-center justify-center rounded-md bg-primary text-primary-foreground">
        <Activity className="size-4" />
      </div>
      <span className="text-sm font-semibold tracking-tight">Geneza</span>
    </div>
  )
}

// The grouped navigation links, shared by the persistent sidebar and the mobile
// drawer. onNavigate fires after a link is tapped so the drawer can close itself.
function SidebarNav({ onNavigate }: { onNavigate?: () => void }) {
  const groups = useNavGroups()

  return (
    <nav className="flex-1 space-y-0.5 overflow-y-auto px-2 py-2">
      {groups.map((group) => (
        <div key={group.label}>
          <p className="px-2.5 pb-1 pt-3 text-2xs font-semibold uppercase tracking-wider text-muted-foreground/70">
            {group.label}
          </p>
          <div className="space-y-0.5">
            {group.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                onClick={onNavigate}
                className={({ isActive }) =>
                  cn(
                    "flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm font-medium transition-colors",
                    isActive
                      ? "bg-primary/10 text-primary"
                      : "text-muted-foreground hover:bg-muted hover:text-foreground"
                  )
                }
              >
                <item.icon className="size-4 shrink-0" />
                <span className="truncate">{item.label}</span>
              </NavLink>
            ))}
          </div>
        </div>
      ))}
    </nav>
  )
}

// Shared inner column (brand + grouped nav) reused for both the persistent
// sidebar and the mobile drawer.
function SidebarBody({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <>
      <Brand />
      <SidebarNav onNavigate={onNavigate} />
    </>
  )
}

// Persistent left sidebar, shown from the md breakpoint up. On narrow viewports
// it is hidden and the same navigation is reached through MobileNav's drawer.
export function Sidebar() {
  return (
    <aside className="hidden w-60 shrink-0 flex-col border-r bg-sidebar text-sidebar-foreground md:flex">
      <SidebarBody />
    </aside>
  )
}

export { SidebarBody }
