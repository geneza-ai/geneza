// Package engine is the concrete affectedness matcher: given a component and the
// advisories filed against its package, it decides whether the installed version
// falls inside a vulnerable range. The version math is delegated entirely to
// osv-scalibr/semantic so each ecosystem (Debian epoch/revision, RPM rpmvercmp,
// PEP440, apk, semver) is compared by its own native rules — hand-rolling that
// comparison is exactly the bug this system exists to avoid, because distros
// backport fixes and keep an upstream-looking version.
//
// The headline correctness is distro-backport awareness: a distro advisory's
// fixed version is the DISTRO's own patched version, so the matcher compares the
// installed version against THAT, never against an upstream fix. An Ubuntu package
// at 1.1.1f-1ubuntu2.16 is fixed if the Ubuntu advisory's fixed event is
// 1.1.1f-1ubuntu2.16, even though that string looks "older" than upstream 1.1.1g.
package engine

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/google/osv-scalibr/semantic"

	"geneza.io/internal/affected"
	"geneza.io/internal/affected/vulnfeed"
)

// VEXSource answers whether a workspace/vendor VEX statement clears a given
// (cve, purl). A nil source suppresses nothing. The minimal contract keeps full
// OpenVEX ingestion a later increment while the suppression path is wired today.
type VEXSource interface {
	// Suppressed reports a not_affected VEX statement for (workspace, cve, purl):
	// ok is true when a statement exists, with justification the recorded reason.
	Suppressed(ws, cve, purl string) (justification string, ok bool)
}

// Engine is the concrete affected.Engine. It holds an optional VEX source and a
// clock for the match timestamp; everything else it needs arrives per call.
type Engine struct {
	WS  string
	VEX VEXSource
	Now func() time.Time
}

// New builds an engine for one workspace. vex may be nil (no suppression).
func New(ws string, vex VEXSource) *Engine {
	return &Engine{WS: ws, VEX: vex, Now: time.Now}
}

var _ affected.Engine = (*Engine)(nil)

// MatchAdvisory evaluates the supplied candidate components against one advisory
// and returns a verdict per component the advisory's package applies to. The
// caller supplies the candidates (the small set the component index selected for
// the advisory's ecosystem+name), so the engine never scans the fleet.
func (e *Engine) MatchAdvisory(ctx context.Context, adv vulnfeed.Vulnerability, candidates []affected.Component) ([]affected.Match, error) {
	var out []affected.Match
	for i := range candidates {
		c := candidates[i]
		if m, ok := e.matchOne(c, adv); ok {
			out = append(out, m)
		}
	}
	return out, nil
}

// MatchNode resolves the advisories for each of a node's components through the
// feed and returns the verdicts for that node.
func (e *Engine) MatchNode(ctx context.Context, feed vulnfeed.Feed, nodeID string, comps []affected.Component) ([]affected.Match, error) {
	var out []affected.Match
	for i := range comps {
		c := comps[i]
		advs, err := feed.Advisories(c.Ecosystem, c.Name)
		if err != nil {
			return nil, err
		}
		for j := range advs {
			if m, ok := e.matchOne(c, advs[j]); ok {
				out = append(out, m)
			}
		}
	}
	return out, nil
}

// matchOne is the per-(component, advisory) verdict. It returns ok=false when the
// advisory does not apply to the component at all (different package), so the
// caller emits no row.
func (e *Engine) matchOne(c affected.Component, adv vulnfeed.Vulnerability) (affected.Match, bool) {
	cve := primaryID(adv)
	m := affected.Match{Component: c, CVE: cve, AdvisoryID: adv.ID}

	// An advisory commonly files the same package as several affected entries — one
	// per major-version line, each carrying its own range. The component is
	// vulnerable if ANY applicable entry places its version in an open window, so
	// evaluate every entry that applies and combine them: affected outranks fixed
	// outranks under_investigation outranks not_affected.
	entries := selectAffected(c, adv)
	if len(entries) == 0 {
		return affected.Match{}, false
	}

	status := affected.StatusNotAffected
	var fixedAtOrPast string // the fix the installed version is already at/past (Fixed)
	var fixesWindow string   // the fix that would close the open window (Affected)
	uncertain := false
	for _, aff := range entries {
		st, fx := evalAffected(c, aff)
		switch st {
		case affected.StatusAffected:
			status = affected.StatusAffected
			// The first applicable entry that places the version in an open window
			// names the version to upgrade to; keep it for the verdict.
			if fixesWindow == "" {
				fixesWindow = fx
			}
		case affected.StatusFixed:
			if status != affected.StatusAffected {
				status = affected.StatusFixed
				fixedAtOrPast = fx
			}
		case affected.StatusUnderInvestigation:
			uncertain = true
		}
	}
	if status == affected.StatusNotAffected && uncertain {
		status = affected.StatusUnderInvestigation
	}
	m.Status = status
	m.Severity = adv.Severity
	switch status {
	case affected.StatusFixed:
		m.FixedVersion = fixedAtOrPast
	case affected.StatusAffected:
		// The fixing version is the upper bound of the window the version sits in; it
		// is empty for an open-ended window (a `fixed` event the advisory omits).
		m.FixedVersion = fixesWindow
	}

	// VEX suppression downgrades an otherwise-affected verdict and records the
	// justification. It never upgrades fixed/under_investigation.
	if status == affected.StatusAffected && e.VEX != nil {
		if just, supp := e.VEX.Suppressed(e.WS, cve, c.Purl); supp {
			m.Status = affected.StatusNotAffected
			m.VEXJustification = just
		}
	}
	return m, true
}

// selectAffected returns the advisory's affected entries that apply to the
// component, matching on ecosystem family and package name. When the component is
// distro-qualified and the advisory carries distro entries for the same base
// ecosystem, only those are returned so the backported fixed version is the one
// evaluated; otherwise every matching entry is returned and the caller combines
// them, because a package routinely spans several version-line entries.
func selectAffected(c affected.Component, adv vulnfeed.Vulnerability) []vulnfeed.Affected {
	var all, distro []vulnfeed.Affected
	for i := range adv.Affected {
		a := adv.Affected[i]
		if !strings.EqualFold(a.Package.Name, c.Name) {
			continue
		}
		if baseEcosystem(a.Package.Ecosystem) != baseEcosystem(c.Ecosystem) {
			continue
		}
		all = append(all, a)
		if hasDistroSuffix(a.Package.Ecosystem) {
			distro = append(distro, a)
		}
	}
	if hasDistroSuffix(c.Ecosystem) && len(distro) > 0 {
		return distro
	}
	return all
}

// evalAffected decides the status for one component against one affected entry by
// walking its ranges with the ecosystem's native comparator. The version compared
// against a distro range's fixed event is the distro's OWN patched version — the
// backport awareness — because the entry came from the distro ecosystem.
func evalAffected(c affected.Component, aff vulnfeed.Affected) (affected.Status, string) {
	eco := aff.Package.Ecosystem
	if eco == "" {
		eco = c.Ecosystem
	}

	// An explicit version enumeration (OSV `versions`) is an exact-membership test.
	// An enumeration carries no upper bound, so an affected verdict names no fix.
	if len(aff.Ranges) == 0 && len(aff.Versions) > 0 {
		for _, v := range aff.Versions {
			if cmp(eco, c.Version, v) == 0 {
				return affected.StatusAffected, ""
			}
		}
		return affected.StatusNotAffected, ""
	}

	affectedAny := false
	var openWindowFix string // the fix that closes the window the version is inside
	var fixedVersion string
	uncertain := false

	for _, r := range aff.Ranges {
		// GIT ranges carry commit hashes, not versions the comparator can order;
		// without a usable bound the verdict is left to other ranges/entries.
		if strings.EqualFold(r.Type, "GIT") {
			continue
		}
		st, fixedAt, unk := evalRange(eco, c.Version, r)
		switch st {
		case inVulnWindow:
			affectedAny = true
			if openWindowFix == "" {
				openWindowFix = fixedAt
			}
		case pastFix:
			fixedVersion = fixedAt
		}
		if unk {
			uncertain = true
		}
	}

	if affectedAny {
		// The fix is the open window's `fixed` event; "" for an open-ended window.
		return affected.StatusAffected, openWindowFix
	}
	if fixedVersion != "" {
		return affected.StatusFixed, fixedVersion
	}
	if uncertain {
		return affected.StatusUnderInvestigation, ""
	}
	// The package matched but no range placed the version inside it.
	return affected.StatusNotAffected, ""
}

// rangeState is where a version sits relative to one OSV range's windows.
type rangeState int

const (
	beforeVuln   rangeState = iota // before every vulnerable window in this range
	inVulnWindow                   // inside an open vulnerable window
	pastFix                        // at or past the fixed event that closed its window
)

// evalRange walks one OSV range's ordered events as a sweep: each "introduced"
// opens a vulnerable window and each "fixed" closes it (a range may carry several
// such windows). It reports where the installed version lands. fixedAt is the
// version that resolves the finding: for an inVulnWindow result it is the `fixed`
// event of the open window the installed version sits in (the version to upgrade
// to), and for a pastFix result it is the fixed event the version was already
// patched out of (the distro's own version for a distro range). unknown is set when
// a bound could not be parsed in the ecosystem, so the caller treats the verdict as
// undecided rather than guessing.
func evalRange(eco, installed string, r vulnfeed.Range) (state rangeState, fixedAt string, unknown bool) {
	state = beforeVuln
	open := false // currently inside a vulnerable window
	for _, ev := range r.Events {
		switch {
		case ev.Introduced != "":
			// "introduced: 0" is "from the beginning": every version is at/after it.
			ge := true
			if ev.Introduced != "0" {
				ci := cmp(eco, installed, ev.Introduced)
				if ci == cmpErr {
					unknown = true
					continue
				}
				ge = ci >= 0
			}
			if ge {
				open = true
				state = inVulnWindow
			}
		case ev.Fixed != "":
			if !open {
				continue
			}
			cf := cmp(eco, installed, ev.Fixed)
			if cf == cmpErr {
				unknown = true
				continue
			}
			if cf >= 0 {
				// At or past this window's fix: patched out of it.
				open = false
				state = pastFix
				fixedAt = ev.Fixed
			} else {
				// Below the fix while a window is open: in the vulnerable window, and
				// this `fixed` event is the version that closes it.
				state = inVulnWindow
				return state, ev.Fixed, unknown
			}
		}
	}
	return state, fixedAt, unknown
}

// cmpErr is a sentinel the comparator returns when a version cannot be parsed in
// the ecosystem, so the caller treats the range as undecidable rather than guessing.
const cmpErr = -2

// cmp compares two versions under an ecosystem's native rules via
// osv-scalibr/semantic, which strips a distro suffix (Debian:12 -> Debian) and
// applies epoch/revision/rpmvercmp/PEP440/apk/semver as appropriate. It returns
// cmpErr if either side is unparseable.
func cmp(ecosystem, a, b string) int {
	v, err := semantic.Parse(a, ecosystem)
	if err != nil {
		return cmpErr
	}
	r, err := v.CompareStr(b)
	if err != nil {
		return cmpErr
	}
	return r
}

// baseEcosystem strips a distro suffix so "Ubuntu:22.04" and "Ubuntu" compare as
// the same family. It mirrors the suffix handling semantic.Parse applies.
func baseEcosystem(eco string) string {
	if i := strings.IndexByte(eco, ':'); i >= 0 {
		return eco[:i]
	}
	return eco
}

// hasDistroSuffix reports whether an OSV ecosystem string is distro-scoped (e.g.
// "Ubuntu:22.04", "Debian:12"), which is the marker that its fixed events carry
// backported versions.
func hasDistroSuffix(eco string) bool {
	return strings.IndexByte(eco, ':') >= 0
}

// primaryID returns the CVE identifier for an advisory: a CVE alias if present
// (the stable cross-source key), else the advisory's own ID.
func primaryID(adv vulnfeed.Vulnerability) string {
	ids := append([]string{}, adv.Aliases...)
	sort.Strings(ids)
	for _, id := range ids {
		if strings.HasPrefix(id, "CVE-") {
			return id
		}
	}
	return adv.ID
}
