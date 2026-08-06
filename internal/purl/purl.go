// Package purl parses a Package URL into the fields the affectedness matcher keys
// on: the OSV ecosystem, the package name and version, and (for an OS package) the
// distro. It is a thin, dependency-free reader of the parts of the PURL spec this
// system uses — the type, namespace, name, version, and the `distro` qualifier —
// not a full PURL implementation, so a malformed or exotic PURL degrades to "no
// ecosystem" rather than failing the whole inventory.
//
// The distro mapping is load-bearing: the matcher needs the distro-scoped OSV
// ecosystem (e.g. "Ubuntu:22.04", "Debian:12", "Alpine:v3.19") to select the
// backport-aware advisory, because the advisory's fixed version is the distro's own
// patched version. A bare PURL type ("deb") does not encode the distro release, so
// when the producer recorded the ecosystem on the component that value wins; this
// derivation is the fallback for a PURL alone.
package purl

import (
	"net/url"
	"strings"
)

// Parsed is the subset of a PURL the matcher consumes.
type Parsed struct {
	Type      string
	Namespace string
	Name      string
	Version   string
	// Ecosystem is the OSV ecosystem string, distro-scoped for an OS package
	// ("Ubuntu:22.04") and the language ecosystem otherwise ("npm", "PyPI").
	Ecosystem string
	// Distro is the OS package's distro identifier ("ubuntu:22.04"), empty for a
	// language dependency.
	Distro string
	// SourceName is the source package a binary OS package was built from, read
	// from whichever qualifier the producing tool used: "source" (deb), "origin"
	// (apk) or "upstream" (rpm). Distro advisories are filed against the source
	// package, so this is what an OS-package advisory lookup keys on.
	SourceName string
}

// Parse reads a PURL ("pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.16?distro=ubuntu-22.04")
// into its parts and derives the OSV ecosystem and distro. It returns an error only
// for a string that is not a PURL at all; an unknown type still yields the type,
// name, and version with a best-effort ecosystem.
func Parse(s string) (Parsed, error) {
	var p Parsed
	rest, ok := strings.CutPrefix(s, "pkg:")
	if !ok {
		return p, errNotPurl
	}
	// Split off qualifiers and subpath before walking the path so a '@' or '/' in a
	// qualifier value cannot be mistaken for a version or namespace boundary.
	var qualifiers string
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		qualifiers = rest[i+1:]
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	// type is the first segment.
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return p, errNotPurl
	}
	p.Type = strings.ToLower(rest[:slash])
	rest = rest[slash+1:]
	// version is everything after the last '@'.
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		p.Version = unescape(rest[at+1:])
		rest = rest[:at]
	}
	// the remaining path is namespace.../name; the last segment is the name.
	if ls := strings.LastIndexByte(rest, '/'); ls >= 0 {
		p.Namespace = unescape(rest[:ls])
		p.Name = unescape(rest[ls+1:])
	} else {
		p.Name = unescape(rest)
	}

	distroQual := qualifier(qualifiers, "distro")
	p.Ecosystem, p.Distro = ecosystem(p.Type, p.Namespace, distroQual)
	p.SourceName = sourceQualifier(qualifiers)
	return p, nil
}

// sourceQualifier reads the source-package name from whichever qualifier the
// producing tool used. The three OS extractors each spell it differently, and a
// foreign SBOM may use any of them, so all three are accepted. A value carrying a
// version ("openssl@3.0.7", as some tools emit) is trimmed back to the name.
func sourceQualifier(qualifiers string) string {
	for _, k := range []string{"source", "origin", "upstream"} {
		if v := qualifier(qualifiers, k); v != "" {
			if at := strings.IndexByte(v, '@'); at > 0 {
				return v[:at]
			}
			return v
		}
	}
	return ""
}

var errNotPurl = parseError("not a package url")

type parseError string

func (e parseError) Error() string { return string(e) }

// ecosystem maps a PURL (type, namespace, distro-qualifier) to the OSV ecosystem
// and a distro identifier. For an OS package type it consults the distro qualifier
// (the release, e.g. "ubuntu-22.04") and the namespace (the vendor) to build the
// distro-scoped ecosystem; for a language type it returns the OSV ecosystem for
// that type and no distro.
func ecosystem(typ, namespace, distro string) (osvEcosystem, distroID string) {
	switch typ {
	case "deb", "rpm", "apk":
		return osEcosystem(typ, namespace, distro)
	}
	return langEcosystem(typ), ""
}

// osEcosystem builds the distro-scoped OSV ecosystem ("Ubuntu:22.04") and the
// distro identifier ("ubuntu:22.04") from an OS package's type, namespace vendor,
// and distro qualifier. The qualifier carries the release; when it is absent the
// ecosystem is left distro-less (the matcher then falls back to the base family).
func osEcosystem(typ, namespace, distro string) (string, string) {
	vendor, release := distroVendorRelease(typ, namespace, distro)
	if vendor == "" {
		return "", ""
	}
	osvFamily := distroOSVFamily[vendor]
	if osvFamily == "" {
		return "", ""
	}
	if release == "" {
		return osvFamily, vendor
	}
	return osvFamily + ":" + release, vendor + ":" + release
}

// distroVendorRelease resolves the lowercase vendor and release from the PURL.
// The distro qualifier is the PREFERRED authority on both ("ubuntu-22.04" -> vendor
// "ubuntu", release "22.04"), but it is not the only spelling in the wild and it must
// never be the last word: a qualifier that does not resolve to a known vendor falls
// through to the namespace, so supplying MORE information cannot make a component
// fare worse. It used to short-circuit here, which silently dropped every OS package
// from a foreign CycloneDX document — scalibr's dpkg extractor writes the release
// CODENAME ("bookworm", "jammy") and apk writes a bare version ("3.18.0"), neither of
// which is a vendor, so the component ended up with no ecosystem and was discarded.
func distroVendorRelease(typ, namespace, distro string) (vendor, release string) {
	ns := distroVendorAlias(strings.ToLower(namespace))
	if distro != "" {
		d := strings.ToLower(distro)
		if i := strings.IndexByte(d, '-'); i >= 0 {
			if v := distroVendorAlias(d[:i]); distroOSVFamily[v] != "" {
				return v, d[i+1:]
			}
		}
		// A bare qualifier is either the vendor ("debian"), a release codename
		// ("bookworm") or a bare release ("3.18.0"). Only the first names a vendor.
		if v := distroVendorAlias(d); distroOSVFamily[v] != "" {
			return v, ""
		}
		if r, v := releaseFromCodename(d); r != "" && (ns == "" || ns == v) {
			return v, r
		}
		// A bare release with no vendor of its own: take the vendor from the
		// namespace (deb/rpm) or the type (apk), and keep the release.
		if ns != "" && distroOSVFamily[ns] != "" {
			return ns, d
		}
		if typ == "apk" {
			return "alpine", d
		}
	}
	if ns != "" {
		return ns, ""
	}
	if typ == "apk" {
		return "alpine", ""
	}
	return "", ""
}

// releaseFromCodename maps a Debian/Ubuntu release codename to its vendor and
// numeric release. Codenames are what dpkg's own metadata carries (VERSION_CODENAME
// in os-release), so any SBOM built from it spells the distro this way.
func releaseFromCodename(name string) (release, vendor string) {
	if r, ok := debianCodenames[name]; ok {
		return r, "debian"
	}
	if r, ok := ubuntuCodenames[name]; ok {
		return r, "ubuntu"
	}
	return "", ""
}

var debianCodenames = map[string]string{
	"jessie": "8", "stretch": "9", "buster": "10",
	"bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14",
}

var ubuntuCodenames = map[string]string{
	"xenial": "16.04", "bionic": "18.04", "focal": "20.04",
	"jammy": "22.04", "noble": "24.04", "questing": "25.10",
}

// distroVendorAlias normalizes a vendor token to the canonical lowercase id the
// OSV-family map is keyed by (e.g. "redhat"/"rhel" -> "redhat").
func distroVendorAlias(v string) string {
	switch v {
	case "rhel", "redhat", "red-hat":
		return "redhat"
	case "alpine", "alpinelinux":
		return "alpine"
	}
	return v
}

// distroOSVFamily maps a canonical distro vendor to its OSV ecosystem family.
var distroOSVFamily = map[string]string{
	"ubuntu":   "Ubuntu",
	"debian":   "Debian",
	"redhat":   "Red Hat",
	"rocky":    "Rocky Linux",
	"alma":     "AlmaLinux",
	"fedora":   "Fedora",
	"alpine":   "Alpine",
	"suse":     "SUSE",
	"opensuse": "openSUSE",
}

// langEcosystem maps a language PURL type to its OSV ecosystem string.
func langEcosystem(typ string) string {
	switch typ {
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "golang":
		return "Go"
	case "cargo":
		return "crates.io"
	case "maven":
		return "Maven"
	case "gem":
		return "RubyGems"
	case "nuget":
		return "NuGet"
	case "composer":
		return "Packagist"
	case "hex":
		return "Hex"
	case "pub":
		return "Pub"
	case "conan":
		return "ConanCenter"
	}
	return ""
}

// qualifier returns the value of a PURL qualifier key, or "".
func qualifier(qualifiers, key string) string {
	if qualifiers == "" {
		return ""
	}
	for _, kv := range strings.Split(qualifiers, "&") {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return unescape(v)
		}
	}
	return ""
}

func unescape(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}
