import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom"

import { ThemeProvider } from "@/components/theme-provider"
import { TooltipProvider } from "@/components/ui/tooltip"
import { Toaster } from "@/components/ui/sonner"
import { AuthGate } from "@/components/auth-gate"
import { AppLayout } from "@/components/layout/app-layout"
import { RequireAdmin } from "@/components/require-admin"
import { DashboardPage } from "@/pages/dashboard"
import { NodesPage } from "@/pages/nodes"
import { NodeDetailPage } from "@/pages/node-detail"
import { MetricsPage } from "@/pages/metrics"
import { SessionsPage } from "@/pages/sessions"
import { RecordingsPage } from "@/pages/recordings"
import { VulnerabilitiesPage } from "@/pages/vulnerabilities"
import { PolicyPage } from "@/pages/policy"
import { AuditPage } from "@/pages/audit"
import { TokensPage } from "@/pages/tokens"
import { ActivatePage } from "@/pages/activate"
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
                <Route path="nodes" element={<NodesPage />} />
                <Route path="nodes/:id" element={<NodeDetailPage />} />
                <Route path="metrics" element={<MetricsPage />} />
                <Route path="sessions" element={<SessionsPage />} />
                <Route path="recordings" element={<RecordingsPage />} />
                <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
                <Route path="activate" element={<ActivatePage />} />
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
