import { Outlet } from "react-router-dom"

import { Header } from "@/components/layout/header"
import { Sidebar } from "@/components/layout/sidebar"

export function AppLayout() {
  return (
    <div className="flex h-screen w-full overflow-hidden bg-background">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Header />
        <main className="flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-7xl px-5 py-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  )
}
