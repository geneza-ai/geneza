// Package affected is the controller-side matcher that answers "is machine M affected
// by CVE-X?". It matches a feed's advisories against the components a node already
// reported — never by re-touching the node — and produces a verdict per (node,
// component, cve). It talks only to a vulnfeed.Feed for vulnerability data, so the
// open and paid feeds are interchangeable beneath it. This file is the seam: the
// types the matcher produces and the interface it implements; the concrete
// version-range and VEX logic land on top of it.
package affected

import (
	"context"

	"geneza.io/internal/affected/vulnfeed"
)

// Status is the verdict for one (node, component, cve). The values are the strings
// persisted in the node_cve table.
type Status string

const (
	// StatusAffected: the component's version falls in the advisory's vulnerable
	// range and no VEX suppresses it.
	StatusAffected Status = "affected"
	// StatusNotAffected: a VEX statement (or the data) clears this component.
	StatusNotAffected Status = "not_affected"
	// StatusFixed: the installed version is at or past the distro's fixed version.
	StatusFixed Status = "fixed"
	// StatusUnderInvestigation: the advisory applies but the verdict is not yet
	// decided (e.g. the distro's fixed version is unknown).
	StatusUnderInvestigation Status = "under_investigation"
)

// Component is one installed component the matcher evaluates: the granularity a
// node's SBOM expands into. Distro qualifies the version so a backported fix is
// compared against the distro's own patched version, never an upstream one.
type Component struct {
	NodeID    string
	Purl      string
	Source    string
	Ecosystem string
	Name      string
	Version   string
	Distro    string
}

// Match is one computed verdict: a component, the CVE it was matched against, the
// status, and the supporting detail (the matched advisory, the distro's fixed
// version, and any VEX justification) the answer table records.
type Match struct {
	Component  Component
	CVE        string
	Status     Status
	AdvisoryID string
	// FixedVersion is the version that resolves the finding: for a StatusFixed
	// verdict it is the distro's patched version the installed one is already at or
	// past; for a StatusAffected verdict it is the upper bound (the `fixed` event) of
	// the open vulnerable window the installed version currently sits in — the
	// version to upgrade to. Empty when the advisory names no fixing version.
	FixedVersion string
	// Severity is the advisory's own qualitative label ("CRITICAL"/"HIGH"/...), the
	// offline default carried so a verdict shows a severity even with no KEV/EPSS feed.
	Severity string
	// VEXJustification is the recorded reason a StatusNotAffected verdict was
	// reached by VEX suppression; empty when the status was not VEX-driven.
	VEXJustification string
}

// Engine computes affectedness against stored inventory using a vulnfeed.Feed. The
// two methods are the two triggers: a feed sync changed an advisory (match it
// against the nodes carrying that package), or a node's inventory changed (re-match
// that one node). Neither contacts the node — both are joins over already-stored
// data.
type Engine interface {
	// MatchAdvisory evaluates every component (across the workspace's nodes) for the
	// given advisory's package and returns the verdicts. The caller supplies the
	// candidate components — the small set the component index selected for the
	// advisory's (ecosystem, name) — so the engine never scans the fleet itself.
	MatchAdvisory(ctx context.Context, adv vulnfeed.Vulnerability, candidates []Component) ([]Match, error)

	// MatchNode evaluates one node's components against the feed and returns the
	// verdicts for that node, resolving advisories per component through the feed.
	MatchNode(ctx context.Context, feed vulnfeed.Feed, nodeID string, comps []Component) ([]Match, error)
}
