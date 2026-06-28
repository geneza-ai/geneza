import { useState } from "react"
import { Menu } from "lucide-react"

import { Button } from "@geneza/ui"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet"
import { SidebarBody } from "@/components/layout/sidebar"

// Hamburger button plus slide-in navigation drawer, shown only below the md
// breakpoint where the persistent sidebar is hidden. Tapping a nav link closes
// the drawer (and navigates) via the onNavigate callback passed to SidebarBody.
export function MobileNav() {
  const [open, setOpen] = useState(false)

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="md:hidden"
          aria-label="Open navigation menu"
        >
          <Menu className="size-5" />
        </Button>
      </SheetTrigger>
      <SheetContent
        side="left"
        className="w-64 bg-sidebar p-0 text-sidebar-foreground"
      >
        {/* The drawer is purely navigational; the title/description satisfy the
            dialog's accessible-name requirement without cluttering the UI. */}
        <SheetTitle className="sr-only">Navigation</SheetTitle>
        <SheetDescription className="sr-only">
          Primary site navigation
        </SheetDescription>
        <SidebarBody onNavigate={() => setOpen(false)} />
      </SheetContent>
    </Sheet>
  )
}
