import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom"

import { ThemeProvider } from "@/components/theme-provider"
import { TooltipProvider } from "@/components/ui/tooltip"
import { Toaster } from "@/components/ui/sonner"
import { AuthGate } from "@/components/auth-gate"
import { AppLayout } from "@/components/layout/app-layout"
import { RequireAdmin } from "@/components/require-admin"
import { DashboardPage } from "@/pages/dashboard"
import { MachinesPage } from "@/pages/machines"
import { SessionsPage } from "@/pages/sessions"
import { PolicyPage } from "@/pages/policy"
import { AuditPage } from "@/pages/audit"
import { TokensPage } from "@/pages/tokens"
import { NotFound } from "@/pages/not-found"

function App() {
  return (
    <ThemeProvider>
      <TooltipProvider delayDuration={200}>
        <BrowserRouter>
          <AuthGate>
            <Routes>
              <Route element={<AppLayout />}>
                <Route index element={<DashboardPage />} />
                <Route path="machines" element={<MachinesPage />} />
                <Route path="sessions" element={<SessionsPage />} />
                <Route path="policy" element={<PolicyPage />} />
                <Route path="audit" element={<AuditPage />} />
                <Route
                  path="tokens"
                  element={
                    <RequireAdmin>
                      <TokensPage />
                    </RequireAdmin>
                  }
                />
                <Route path="404" element={<NotFound />} />
                <Route path="*" element={<Navigate to="/404" replace />} />
              </Route>
            </Routes>
          </AuthGate>
        </BrowserRouter>
        <Toaster />
      </TooltipProvider>
    </ThemeProvider>
  )
}

export default App
