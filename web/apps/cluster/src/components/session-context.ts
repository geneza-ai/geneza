import { createContext, useContext } from "react"

import type { Me } from "@/auth"

export interface SessionValue {
  me: Me
  signOut: () => void
}

export const SessionContext = createContext<SessionValue | null>(null)

export function useSession(): SessionValue | null {
  return useContext(SessionContext)
}
