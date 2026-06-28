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
import { Badge } from "@/components/ui/badge"

function initials(name: string): string {
  const clean = name.split("@")[0]
  const parts = clean.split(/[.\-_ ]+/).filter(Boolean)
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase()
  return clean.slice(0, 2).toUpperCase()
}

export function UserMenu() {
  const { me, signOut } = useSession()
  const { theme, setTheme } = useTheme()

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button className="flex max-w-[16rem] items-center gap-2 rounded-md py-1 pl-1 pr-1.5 text-left transition-colors hover:bg-muted sm:pr-2">
          <div className="flex size-7 shrink-0 items-center justify-center rounded-full bg-primary/10 text-xs font-medium text-primary">
            {initials(me.user)}
          </div>
          <div className="hidden min-w-0 sm:block">
            <div className="flex items-center gap-1.5">
              <p className="truncate text-sm font-medium leading-tight">
                {me.user}
              </p>
              {me.admin && (
                <Badge variant="muted" className="px-1 py-0 text-2xs">
                  admin
                </Badge>
              )}
            </div>
            <p className="truncate text-xs leading-tight text-muted-foreground">
              {me.workspace}
            </p>
          </div>
          <ChevronsUpDown className="hidden size-4 shrink-0 text-muted-foreground sm:block" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" side="bottom" className="w-56">
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
