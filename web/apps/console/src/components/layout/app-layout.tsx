import { Outlet } from "react-router-dom"

import { Header } from "@/components/layout/header"
import { PageHeaderProvider } from "@/components/layout/page-header"
import { Sidebar } from "@/components/layout/sidebar"

export function AppLayout() {
  return (
    <PageHeaderProvider>
      <div className="flex h-screen w-full overflow-hidden bg-background">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <Header />
          <main className="flex-1 overflow-y-auto">
            <div className="mx-auto w-full max-w-[1172px] px-6 pb-14 pt-7">
              <Outlet />
            </div>
          </main>
        </div>
      </div>
    </PageHeaderProvider>
  )
}
