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
	return p, nil
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
// The distro qualifier is the authority on both ("ubuntu-22.04" -> vendor "ubuntu",
// release "22.04"); the namespace is the fallback vendor for a deb/rpm with no
// qualifier. Alpine carries no namespace vendor, so apk defaults to alpine.
func distroVendorRelease(typ, namespace, distro string) (vendor, release string) {
	if distro != "" {
		d := strings.ToLower(distro)
		if i := strings.IndexByte(d, '-'); i >= 0 {
			return distroVendorAlias(d[:i]), d[i+1:]
		}
		return distroVendorAlias(d), ""
	}
	if namespace != "" {
		return distroVendorAlias(strings.ToLower(namespace)), ""
	}
	if typ == "apk" {
		return "alpine", ""
	}
	return "", ""
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
