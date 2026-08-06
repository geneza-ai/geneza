import { ChevronsUpDown, LogOut, Monitor, Moon, Sun } from "lucide-react"

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { useTheme } from "@/components/theme-provider"
import { useSession } from "@/components/session-context"

function initial(name: string): string {
  return (name.trim()[0] ?? "?").toUpperCase()
}

// The user row pinned to the sidebar foot: forest avatar, identity, and the
// role in machine text. The dropdown carries the rest (roles, theme, sign out).
export function UserMenu() {
  const { me, signOut } = useSession()
  const { theme, setTheme } = useTheme()
  // Never print the bare "admin" — that is the reserved cluster role a console
  // session cannot hold, and showing it here implies authority the user lacks.
  const role = me.roles[0] ?? (me.admin ? "ws-admin" : me.workspace)

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button className="flex w-full items-center gap-2.5 rounded-lg px-2 py-1.5 text-left transition-colors hover:bg-sidebar-accent">
          <div className="flex size-7 shrink-0 items-center justify-center rounded-full bg-brand text-xs font-semibold text-brand-foreground">
            {initial(me.user)}
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-[12.5px] font-medium leading-tight">
              {me.user}
            </p>
            <p className="truncate font-mono text-2xs leading-tight text-faint">
              {role}
            </p>
          </div>
          <ChevronsUpDown className="size-3.5 shrink-0 text-faint" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" side="top" className="w-56">
        <DropdownMenuLabel className="font-normal">
          <p className="text-sm font-medium">{me.user}</p>
          <p className="mt-0.5 truncate text-xs text-muted-foreground">
            {me.roles.length ? me.roles.join(", ") : "no roles"}
          </p>
          {me.groups.length > 0 && (
            <p className="truncate text-xs text-muted-foreground/70">
              {me.groups.join(", ")}
            </p>
          )}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuLabel className="px-2 py-1 text-xs font-normal text-muted-foreground">
          Theme
        </DropdownMenuLabel>
        <DropdownMenuItem onSelect={() => setTheme("light")}>
          <Sun className="size-4" /> Light
          {theme === "light" && <span className="ml-auto text-xs">•</span>}
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => setTheme("dark")}>
          <Moon className="size-4" /> Dark
          {theme === "dark" && <span className="ml-auto text-xs">•</span>}
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => setTheme("system")}>
          <Monitor className="size-4" /> System
          {theme === "system" && <span className="ml-auto text-xs">•</span>}
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onSelect={signOut}
          className="text-destructive focus:text-destructive"
        >
          <LogOut className="size-4" /> Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
