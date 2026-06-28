// Package vulnfeed is the seam between the affectedness matcher and a source of
// vulnerability data. A Feed refreshes advisories into the store and answers the
// matcher's by-package and per-CVE enrichment lookups; the matcher only ever talks
// to this interface, so an open feed (public OSV/NVD) and a curated paid feed are
// interchangeable and composable behind it. The data shapes mirror the OSV schema
// so a feed that reads OSV bulk data maps onto them without translation, but they
// are defined here (not imported) to keep the seam free of a pre-1.0 dependency
// until a concrete feed needs one.
package vulnfeed

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"time"
)

// Feed is one source of vulnerability data. Implementations compose: a paid feed
// can wrap an open one, overriding or augmenting per-package and per-CVE answers.
// Sync is the only method that writes to the store; the reads are pure lookups the
// matcher drives.
type Feed interface {
	// Name is the stable identifier the config selects a feed by (e.g. "osv-public",
	// "nvd-public", "geneza-vulnfeed").
	Name() string

	// Sync refreshes advisories modified since the given watermark into the store,
	// returning how many it wrote. A zero `since` is a full refresh. It is the
	// caller's chore loop, not the feed, that schedules and shards the sync.
	Sync(ctx context.Context, since time.Time) (n int, err error)

	// Advisories returns the vulnerabilities filed against a package in an
	// ecosystem — the matcher's inner resolve. The feed answers from whatever it
	// synced; an unknown package is an empty slice, not an error.
	Advisories(ecosystem, name string) ([]Vulnerability, error)

	// Enrich returns prioritization signal (KEV/EPSS/severity) for a CVE. An open
	// feed answers best-effort and may return a zero Enrichment for a CVE it has no
	// signal for; a paid feed is the curated, low-latency source.
	Enrich(ctx context.Context, cve string) (Enrichment, error)
}

// Enrichment is the prioritization signal for one CVE, sourced from KEV/EPSS and
// any feed-specific risk scoring. Zero values mean "no signal", not "absent risk".
type Enrichment struct {
	// Severity is a human label (e.g. "critical"); empty when the feed has none.
	Severity string
	// KEV reports whether the CVE is on CISA's Known-Exploited-Vulnerabilities list.
	KEV bool
	// EPSS is the FIRST exploit-prediction probability in [0,1].
	EPSS float64
}

// Vulnerability is the subset of the OSV advisory schema the matcher consumes: the
// identifiers, the affected-package ranges, and the raw source document (which
// carries the advisory's own upstream license, surfaced per-record rather than
// asserting one blanket license for the feed).
type Vulnerability struct {
	ID       string     `json:"id"`
	Aliases  []string   `json:"aliases,omitempty"`
	Modified time.Time  `json:"modified,omitempty"`
	Affected []Affected `json:"affected,omitempty"`
	// Severity is the advisory's own human label (e.g. "CRITICAL", "HIGH"), derived
	// from the OSV record's database_specific.severity or, failing that, the CVSS
	// vector in its severity[] scores. It is the offline default the matcher records
	// on a verdict so a CVE shows a severity even when no KEV/EPSS feed is reachable;
	// an enrichment feed's curated severity still overrides it. Empty when the
	// advisory carries none.
	Severity string `json:"-"`
	// Raw is the verbatim source advisory, retained so a feed never loses fields the
	// minimal struct does not model — including the per-source license/attribution.
	Raw []byte `json:"-"`
}

// UnmarshalJSON reads an OSV advisory into the Vulnerability and additionally
// derives the human Severity label the matcher records as the offline default. The
// promoted fields (id/aliases/modified/affected) unmarshal as usual; Severity is
// taken from the record's database_specific.severity when present, else from the
// CVSS vector in its severity[] scores, neither of which the promoted fields model.
func (v *Vulnerability) UnmarshalJSON(b []byte) error {
	type alias Vulnerability // avoid recursing into this method
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*v = Vulnerability(a)
	v.Severity = severityFromOSV(b)
	return nil
}

// severityFromOSV pulls a qualitative severity band out of an OSV document. The
// advisory's database_specific.severity ("CRITICAL"/"HIGH"/...) is the curated
// label and wins; failing that, the CVSS base score in severity[].score is parsed
// to a band. An advisory carrying neither yields "".
func severityFromOSV(doc []byte) string {
	var rec struct {
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
	}
	if err := json.Unmarshal(doc, &rec); err != nil {
		return ""
	}
	if s := strings.TrimSpace(rec.DatabaseSpecific.Severity); s != "" {
		return strings.ToUpper(s)
	}
	for _, sev := range rec.Severity {
		if band := cvssBand(sev.Score); band != "" {
			return band
		}
	}
	return ""
}

// cvssBand derives the qualitative CVSS band ("CRITICAL"/"HIGH"/"MEDIUM"/"LOW")
// from a CVSS v3/v4 vector string by reading its base score. The base score is not
// carried as a number in the OSV vector, so it is computed from the vector's metrics
// — but the common case the advisories use is a fully specified v3.1/v4.0 vector, so
// the band is read from the standard qualitative cutoffs once the score is known.
// A vector this reader cannot score yields "".
func cvssBand(vector string) string {
	score, ok := cvssBaseScore(vector)
	if !ok {
		return ""
	}
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0.0:
		return "LOW"
	default:
		return ""
	}
}

// cvssBaseScore computes the CVSS v3.x base score from a vector string. It models
// the v3.0/v3.1 base-metric formula (the metrics an advisory's vector always carries)
// so a band can be derived offline without a CVSS library. A v4.0 vector reuses the
// same exploitability/impact metric letters for its base group, so the same reading
// gives a usable band. ok is false when the vector is not a recognizable CVSS v3/v4
// base vector.
func cvssBaseScore(vector string) (float64, bool) {
	if !strings.HasPrefix(vector, "CVSS:3") && !strings.HasPrefix(vector, "CVSS:4") {
		return 0, false
	}
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		if k, val, ok := strings.Cut(part, ":"); ok {
			m[k] = val
		}
	}
	av, ok1 := cvssAttackVector[m["AV"]]
	ac, ok2 := cvssAttackComplexity[m["AC"]]
	pr, ok3 := cvssPrivilegesRequired(m["PR"], m["S"])
	ui, ok4 := cvssUserInteraction[m["UI"]]
	c, ok5 := cvssImpact[m["C"]]
	in, ok6 := cvssImpact[m["I"]]
	av6 := m["A"]
	a, ok7 := cvssImpact[av6]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, false
	}
	scopeChanged := m["S"] == "C"

	iscBase := 1 - (1-c)*(1-in)*(1-a)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iscBase-0.029) - 3.25*pow15(iscBase-0.02)
	} else {
		impact = 6.42 * iscBase
	}
	if impact <= 0 {
		return 0, true
	}
	exploitability := 8.22 * av * ac * pr * ui
	var base float64
	if scopeChanged {
		base = roundUp(min1(1.08*(impact+exploitability), 10))
	} else {
		base = roundUp(min1(impact+exploitability, 10))
	}
	return base, true
}

var (
	cvssAttackVector     = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	cvssAttackComplexity = map[string]float64{"L": 0.77, "H": 0.44}
	cvssUserInteraction  = map[string]float64{"N": 0.85, "R": 0.62}
	cvssImpact           = map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
)

// cvssPrivilegesRequired returns the PR weight, which differs when the scope is
// changed (a higher weight for Low/High privileges), matching the v3 spec.
func cvssPrivilegesRequired(pr, scope string) (float64, bool) {
	changed := scope == "C"
	switch pr {
	case "N":
		return 0.85, true
	case "L":
		if changed {
			return 0.68, true
		}
		return 0.62, true
	case "H":
		if changed {
			return 0.5, true
		}
		return 0.27, true
	}
	return 0, false
}

func pow15(x float64) float64 { return math.Pow(x, 15) }

func min1(a, b float64) float64 { return math.Min(a, b) }

// roundUp rounds to one decimal place, away from zero, as the CVSS v3.1 spec's
// Roundup defines (a score of 6.001 becomes 6.1, never 6.0).
func roundUp(x float64) float64 {
	scaled := int(math.Round(x * 100000))
	if scaled%10000 == 0 {
		return float64(scaled) / 100000
	}
	return float64(scaled/10000+1) / 10
}

// Affected ties a vulnerability to one package and the version ranges it applies
// to, in OSV's package/ranges shape.
type Affected struct {
	Package  Package  `json:"package"`
	Ranges   []Range  `json:"ranges,omitempty"`
	Versions []string `json:"versions,omitempty"`
}

// Package names an affected package in OSV terms: the ecosystem (which selects the
// version-comparison rules), the package name, and the PURL when present.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Purl      string `json:"purl,omitempty"`
}

// Range is one OSV affected range: a type ("ECOSYSTEM" | "SEMVER" | "GIT") and the
// ordered introduced/fixed events. For a distro the fixed value is the distro's
// OWN backported version, the version the matcher compares the installed one
// against.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events,omitempty"`
}

// Event is one boundary in a Range: exactly one of its fields is set ("introduced"
// at which the vulnerability begins, "fixed" at which it ends).
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// AdvisoryRecord is one advisory as a feed hands it to the store: the promoted
// fields back the by-package index and Doc is the verbatim source document (which
// carries the advisory's own upstream license). It mirrors the controller store's
// record but lives here so a feed never imports the store, keeping the seam's
// dependency direction one-way.
type AdvisoryRecord struct {
	ID           string
	Source       string
	Ecosystem    string
	PackageName  string
	Doc          []byte
	ModifiedUnix int64
}

// AdvisoryStore is the narrow persistence surface a feed's Sync writes to and its
// Advisories read serves from. The controller store satisfies it through a thin
// adapter, so a feed depends only on this interface, never on the store package.
type AdvisoryStore interface {
	PutAdvisories(recs []AdvisoryRecord) error
	AdvisoriesForPackage(ecosystem, name string) ([]AdvisoryRecord, error)
}

// ImageAdvisoryProvider is a registry-side scan-by-digest lookup: given a container
// image's content digest, it returns the vulnerabilities a feed already knows that
// image carries — so a known image needs no local SBOM scan. It is the image-level
// twin of the per-package Advisories lookup, and it composes with the open-vs-paid
// split exactly like Feed: an open provider can answer best-effort (or nothing) for a
// digest it has not scanned, while a paid provider is the curated upstream that has
// pre-scanned the registry. The returned vulnerabilities carry the same package/range
// shape as a normal advisory, so the matcher folds them in without a special path; a
// digest the provider has no data for is an empty slice, never an error.
type ImageAdvisoryProvider interface {
	// Name identifies the provider for logs/diagnostics.
	Name() string
	// AdvisoriesForDigest returns the vulnerabilities the provider attributes to the
	// image identified by digest ("sha256:<hex>"). An unknown digest is an empty
	// slice (not an error): the caller then falls back to the locally-scanned SBOM.
	AdvisoriesForDigest(ctx context.Context, digest string) ([]Vulnerability, error)
}

// NoImageAdvisories is the default ImageAdvisoryProvider: it answers nothing for
// every digest, so a deployment with no registry-scan upstream wired keeps relying on
// the locally-scanned SBOM. It is a real seam, not a stub the match path skips — the
// match path always consults the configured provider, and this default simply
// contributes no extra advisories. A paid build swaps in a provider backed by the
// vendor's pre-scanned registry feed.
type NoImageAdvisories struct{}

func (NoImageAdvisories) Name() string { return "none" }

func (NoImageAdvisories) AdvisoriesForDigest(context.Context, string) ([]Vulnerability, error) {
	return nil, nil
}
