import * as React from "react"

/**
 * Geneza — the "Growth Node" mark.
 *
 * A single root that branches into a verified mesh: network + forest + genesis
 * in one glyph. Five nodes (one root, one hub, three reaches); only the apex
 * node carries the accent = the one live / verified endpoint. The branches are
 * never colored, there are never more than three reaches, and the root stays
 * anchored at the foot.
 */
export function GenezaMark({
  size = 24,
  stroke = "currentColor",
  accent = "var(--brand)",
  ...props
}: React.SVGProps<SVGSVGElement> & { size?: number; accent?: string }) {
  // Step the stroke up slightly at small sizes for optical evenness.
  const sw = size <= 20 ? 2.8 : size <= 32 ? 2.5 : 2.3
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" fill="none" {...props}>
      <path
        d="M24 38 L24 25 M24 25 L12 14 M24 25 L24 9.5 M24 25 L36 14"
        stroke={stroke}
        strokeWidth={sw}
        strokeLinecap="round"
      />
      <circle cx="24" cy="38" r="2.8" fill={stroke} />
      <circle cx="24" cy="25" r="2.6" fill={stroke} />
      <circle cx="12" cy="14" r="2.2" fill={stroke} />
      <circle cx="36" cy="14" r="2.2" fill={stroke} />
      <circle cx="24" cy="9.5" r="3.2" fill={accent} />
    </svg>
  )
}

/**
 * The full logo lockup: the mark plus the "Geneza" wordmark set in the brand
 * serif (Source Serif 4, weight 500, tightened tracking).
 */
export function GenezaLogo({
  size = 22,
  className,
}: {
  size?: number
  className?: string
}) {
  return (
    <span
      className={className}
      style={{ display: "inline-flex", alignItems: "center", gap: size * 0.5 }}
    >
      <GenezaMark size={size} stroke="var(--foreground)" accent="var(--brand)" />
      <span
        style={{
          fontFamily: "var(--font-serif)",
          fontWeight: 500,
          fontSize: size * 0.86,
          letterSpacing: "-0.02em",
        }}
      >
        Geneza
      </span>
    </span>
  )
}
