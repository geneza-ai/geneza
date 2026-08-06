package affected

import "strings"

// OSV ecosystem strings are not one shape, and the difference is the whole reason
// OS-package matching produced nothing for a long time. An agent's dpkg extractor
// emits the OS id and version it read from os-release — "Ubuntu:22.04" — while the
// advisories Canonical actually publishes are filed under "Ubuntu:22.04:LTS", plus
// a family of paid/hardened variants: "Ubuntu:Pro:22.04:LTS",
// "Ubuntu:Pro:FIPS-updates:22.04:LTS". Debian and Alpine happen to agree on both
// sides ("Debian:12", "Alpine:v3.19"); Red Hat disagrees a third way, carrying the
// product and the repo around the release ("Red Hat:enterprise_linux:9::baseos",
// and the same CVE again under ::appstream, ::crb, ::nfv, ::realtime).
//
// So an exact string compare — which is what every store lookup used to do —
// silently matches nothing for Ubuntu and only the one repo the host's CPE names
// for Red Hat. Two operations fix it, and they are deliberately different:
//
//   - Key() is the coarse INDEX key, family:release. It deliberately collapses
//     the variants together so one indexed lookup fetches every candidate.
//   - Applies() is the precise SELECTION test run afterwards, in Go, over that
//     small candidate set. It is what keeps a Pro-only or FIPS-only advisory from
//     landing on a host running neither — collapsing to family alone and stopping
//     there would trade silent false negatives for silent false positives, and a
//     false "affected" is the more expensive mistake to ship.

// EcosystemParts is an OSV ecosystem string split into the three things that
// decide applicability. Trailing tokens after the release ("LTS", the Red Hat repo)
// are deliberately dropped: they qualify the advisory's provenance, not the host.
type EcosystemParts struct {
	// Family is the ecosystem proper: "Ubuntu", "Debian", "Alpine", "Red Hat",
	// "npm", "PyPI", "Go".
	Family string
	// Variants are the qualifier tokens that appear BEFORE the release and narrow
	// which hosts the entry applies to: "Pro", "FIPS-updates", "enterprise_linux".
	Variants []string
	// Release is the distro release the entry is scoped to ("22.04", "12",
	// "v3.19", "9"), empty for a language ecosystem or an unscoped entry.
	Release string
}

// ParseEcosystem splits an OSV ecosystem string. The release is the first
// colon-separated token that starts a version (an optional "v" then a digit);
// tokens before it qualify the host, tokens after it qualify the advisory.
func ParseEcosystem(eco string) EcosystemParts {
	parts := strings.Split(eco, ":")
	p := EcosystemParts{Family: parts[0]}
	for i := 1; i < len(parts); i++ {
		if looksLikeRelease(parts[i]) {
			p.Release = parts[i]
			return p
		}
		if parts[i] != "" {
			p.Variants = append(p.Variants, parts[i])
		}
	}
	return p
}

// looksLikeRelease reports whether a token is a distro release number: "22.04",
// "12", "v3.19", "9". Everything else in that position is a qualifier.
func looksLikeRelease(tok string) bool {
	s := strings.TrimPrefix(tok, "v")
	return s != "" && s[0] >= '0' && s[0] <= '9'
}

// Key is the coarse lookup key: family, plus the release when the entry has one.
// Every variant of one release collapses to the same key on purpose, so a single
// indexed read returns all of them and Applies picks the ones that really apply.
func (p EcosystemParts) Key() string {
	if p.Release == "" {
		return p.Family
	}
	return p.Family + ":" + p.Release
}

// EcosystemKey is the store index key for an ecosystem string. Both sides of the
// join must be keyed through it: "Ubuntu:22.04:LTS" (advisory) and "Ubuntu:22.04"
// (component) both key to "Ubuntu:22.04", and "Red Hat:enterprise_linux:9::baseos"
// and "Red Hat:enterprise_linux:9::appstream" both key to "Red Hat:9".
func EcosystemKey(eco string) string { return ParseEcosystem(eco).Key() }

// EcosystemApplies reports whether an advisory entry's ecosystem applies to a
// component's. Family and release must agree, and every variant the advisory
// narrows itself to must be one the component actually carries — so
// "Ubuntu:Pro:FIPS-updates:22.04:LTS" does not apply to a plain "Ubuntu:22.04"
// host, while "Red Hat:enterprise_linux:9::appstream" does apply to a
// "Red Hat:enterprise_linux:9::baseos" host (same product, same release; the repo
// the advisory was filed under says nothing about which repos the host installs
// from).
//
// An empty advisory ecosystem means the entry inherits the component's, which is
// how OSV records that omit it are read elsewhere in the matcher.
func EcosystemApplies(advisoryEco, componentEco string) bool {
	if advisoryEco == "" {
		return true
	}
	a, c := ParseEcosystem(advisoryEco), ParseEcosystem(componentEco)
	if !strings.EqualFold(a.Family, c.Family) {
		return false
	}
	// An unscoped entry on either side applies across releases: that is what an
	// ecosystem with no release means, and language ecosystems never have one.
	if a.Release != "" && c.Release != "" && !strings.EqualFold(a.Release, c.Release) {
		return false
	}
	for _, v := range a.Variants {
		if !hasVariant(c.Variants, v) {
			return false
		}
	}
	return true
}

func hasVariant(have []string, want string) bool {
	for _, h := range have {
		if strings.EqualFold(h, want) {
			return true
		}
	}
	return false
}
