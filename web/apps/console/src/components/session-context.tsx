import { createContext, useContext } from "react"

import type { AppConfig, Me } from "@/types"

interface SessionContextValue {
  config: AppConfig
  me: Me
  signOut: () => void
}

export const SessionContext = createContext<SessionContextValue | undefined>(
  undefined
)

export function useSession() {
  const ctx = useContext(SessionContext)
  if (!ctx) throw new Error("useSession must be used within SessionContext")
  return ctx
}
