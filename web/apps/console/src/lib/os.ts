// Operating-system helpers shared by the OS/distro icon and any view that needs
// to reason about a node's platform from its labels.

/** Lowercase and strip to alphanumerics, for forgiving id matching. */
export function normalizeId(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]/g, "")
}

// Label keys (normalised) that commonly carry a Linux distribution id.
const DISTRO_KEYS = new Set([
  "distro",
  "distribution",
  "osdistro",
  "osrelease",
  "osid",
  "id",
])

/**
 * Best-effort distro hint from a node's labels — e.g. a `distro=ubuntu` or
 * `os-release=debian` label. Returns undefined when nothing distro-shaped is
 * present, so callers fall back to the generic Linux glyph.
 */
export function distroFromLabels(
  labels: Record<string, string> | undefined
): string | undefined {
  if (!labels) return undefined
  for (const [k, v] of Object.entries(labels)) {
    if (v && DISTRO_KEYS.has(normalizeId(k))) return v
  }
  return undefined
}
