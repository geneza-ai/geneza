import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom"

import { ThemeProvider } from "@/components/theme-provider"
import { AuthGate } from "@/components/auth-gate"
import { AppLayout } from "@/components/layout/app-layout"
import { TopologyPage } from "@/pages/topology"
import { AgentsPage } from "@/pages/agents"
import { RiskPage } from "@/pages/risk"

function App() {
  return (
    <ThemeProvider>
      <AuthGate>
        <BrowserRouter>
          <Routes>
            <Route element={<AppLayout />}>
              <Route index element={<TopologyPage />} />
              <Route path="agents" element={<AgentsPage />} />
              <Route path="risk" element={<RiskPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </AuthGate>
    </ThemeProvider>
  )
}

export default App
