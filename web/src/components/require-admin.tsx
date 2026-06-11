import { Navigate } from "react-router-dom"

import { useSession } from "@/components/session-context"

export function RequireAdmin({ children }: { children: React.ReactNode }) {
  const { me } = useSession()
  if (!me.admin) return <Navigate to="/" replace />
  return <>{children}</>
}
