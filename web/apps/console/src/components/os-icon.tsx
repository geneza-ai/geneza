import {
  siAlmalinux,
  siAlpinelinux,
  siApple,
  siArchlinux,
  siCentos,
  siDebian,
  siFedora,
  siFreebsd,
  siGentoo,
  siLinux,
  siLinuxmint,
  siManjaro,
  siNixos,
  siOpenbsd,
  siOpensuse,
  siProxmox,
  siRaspberrypi,
  siRedhat,
  siRockylinux,
  siSuse,
  siUbuntu,
} from "simple-icons"
import { HardDrive } from "lucide-react"

import { cn } from "@geneza/ui"
import { normalizeId as norm } from "@/lib/os"

// A subset of a simple-icons record — just what we render.
interface Glyph {
  title: string
  hex: string
  path: string
}

// Windows is trademark-removed from simple-icons, so we carry the classic
// four-pane mark ourselves (brand blue, recognisable at 16px).
const WINDOWS: Glyph = {
  title: "Windows",
  hex: "0078D4",
  path: "M0 0h11.4v11.4H0zM12.6 0H24v11.4H12.6zM0 12.6h11.4V24H0zM12.6 12.6H24V24H12.6z",
}

// Distro id (normalised: lowercased, alphanumerics only) → logo. Ordered by
// specificity so e.g. "linuxmint" wins before a bare "linux" fallback. Each
// entry is matched as a substring of the normalised hint.
const DISTROS: [string, Glyph][] = [
  ["ubuntu", siUbuntu],
  ["debian", siDebian],
  ["raspbian", siRaspberrypi],
  ["raspberrypi", siRaspberrypi],
  ["raspberry", siRaspberrypi],
  ["linuxmint", siLinuxmint],
  ["mint", siLinuxmint],
  ["fedora", siFedora],
  ["archlinux", siArchlinux],
  ["arch", siArchlinux],
  ["manjaro", siManjaro],
  ["alpine", siAlpinelinux],
  ["almalinux", siAlmalinux],
  ["alma", siAlmalinux],
  ["rockylinux", siRockylinux],
  ["rocky", siRockylinux],
  ["centos", siCentos],
  ["rhel", siRedhat],
  ["redhat", siRedhat],
  ["opensuse", siOpensuse],
  ["sles", siSuse],
  ["sled", siSuse],
  ["suse", siSuse],
  ["gentoo", siGentoo],
  ["nixos", siNixos],
  ["nix", siNixos],
  ["proxmox", siProxmox],
  ["pve", siProxmox],
]

/** Resolve the best-matching logo for an (os, distro) pair, or null to fall back. */
function resolveGlyph(os: string, distro?: string): Glyph | null {
  const o = norm(os)
  if (o.includes("darwin") || o.includes("mac") || o.includes("apple"))
    return siApple
  if (o.includes("windows") || o === "win") return WINDOWS
  if (o.includes("openbsd")) return siOpenbsd
  if (o.includes("freebsd") || o.includes("bsd")) return siFreebsd

  if (o.includes("linux")) {
    // A distro hint (from a label) refines the generic penguin into the
    // real distribution logo when we recognise it.
    if (distro) {
      const d = norm(distro)
      for (const [key, glyph] of DISTROS) if (d.includes(key)) return glyph
    }
    return siLinux
  }
  return null
}

// Brand hexes that are pure black/white can't be drawn literally (invisible on
// one theme), so those inherit currentColor and adapt instead.
const ADAPTIVE = new Set(["000000", "ffffff"])

/**
 * Renders the operating-system (and, for Linux, the distribution) logo for a
 * node. `distro` is an optional hint, usually pulled from a node label via
 * {@link distroFromLabels}. Falls back to a neutral drive glyph when the OS is
 * unknown. Size comes from `className` (default `size-4`); set `colored` false
 * to force the icon to inherit the surrounding text colour.
 */
export function OsIcon({
  os,
  distro,
  colored = true,
  className,
}: {
  os: string
  distro?: string
  colored?: boolean
  className?: string
}) {
  const glyph = resolveGlyph(os, distro)
  if (!glyph) {
    return (
      <HardDrive
        className={cn("size-4 text-muted-foreground", className)}
        aria-label={os || "unknown OS"}
      />
    )
  }

  const useBrandHex = colored && !ADAPTIVE.has(glyph.hex.toLowerCase())
  return (
    <svg
      role="img"
      viewBox="0 0 24 24"
      aria-label={glyph.title}
      className={cn("size-4 shrink-0", !useBrandHex && "text-muted-foreground", className)}
      style={useBrandHex ? { color: `#${glyph.hex}` } : undefined}
      fill="currentColor"
    >
      <title>{glyph.title}</title>
      <path d={glyph.path} />
    </svg>
  )
}
