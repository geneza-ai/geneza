import { useMemo, useState } from "react"

import {
  PageHeaderContext,
  type HeaderOverride,
} from "@/components/layout/page-header-context"

export function PageHeaderProvider({ children }: { children: React.ReactNode }) {
  const [override, setOverride] = useState<HeaderOverride | null>(null)
  const value = useMemo(() => ({ override, setOverride }), [override])
  return (
    <PageHeaderContext.Provider value={value}>
      {children}
    </PageHeaderContext.Provider>
  )
}
