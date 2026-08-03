import { createContext, useContext, useEffect } from "react"

// Detail pages (node detail, recording playback) promote their entity into the
// topbar: a mono breadcrumb over the serif title. List pages leave it unset and
// the header falls back to its static section title.
export interface HeaderOverride {
  title: string
  crumb?: string
}

export interface PageHeaderState {
  override: HeaderOverride | null
  setOverride: (o: HeaderOverride | null) => void
}

export const PageHeaderContext = createContext<PageHeaderState | undefined>(
  undefined
)

export function useHeaderOverride(): PageHeaderState {
  const ctx = useContext(PageHeaderContext)
  if (!ctx)
    throw new Error("useHeaderOverride must be used within PageHeaderProvider")
  return ctx
}

/** Sets the topbar title/crumb for the lifetime of the calling page. */
export function usePageHeader(title: string | null, crumb?: string) {
  const { setOverride } = useHeaderOverride()
  useEffect(() => {
    setOverride(title ? { title, crumb } : null)
    return () => setOverride(null)
  }, [title, crumb, setOverride])
}
