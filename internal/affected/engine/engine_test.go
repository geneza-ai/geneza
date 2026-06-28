package engine

import (
	"context"
	"encoding/json"
	"testing"

	"geneza.io/internal/affected"
	"geneza.io/internal/affected/vulnfeed"
)

// vuln builds a Vulnerability from a JSON literal so the tests read like the OSV
// records they model and exercise the same unmarshal path the feed uses.
func vuln(t *testing.T, raw string) vulnfeed.Vulnerability {
	t.Helper()
	var v vulnfeed.Vulnerability
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("bad vuln literal: %v", err)
	}
	return v
}

func matchOne(t *testing.T, e *Engine, c affected.Component, v vulnfeed.Vulnerability) affected.Match {
	t.Helper()
	ms, err := e.MatchAdvisory(context.Background(), v, []affected.Component{c})
	if err != nil {
		t.Fatalf("MatchAdvisory: %v", err)
	}
	if len(ms) != 1 {
		t.Fatalf("want exactly one match, got %d", len(ms))
	}
	return ms[0]
}

// TestUbuntuBackportNotAffected is the headline: an Ubuntu package at the distro's
// own backported-and-patched version is NOT affected, even though that version
// string looks "older" than the upstream fix a naive comparator would use. An
// older distro version of the same package IS affected.
func TestUbuntuBackportNotAffected(t *testing.T) {
	e := New("ws", nil)
	// Ubuntu USN-style advisory: the fixed event is the DISTRO's backported version.
	adv := vuln(t, `{
		"id": "USN-OSV-1",
		"aliases": ["CVE-2022-0778"],
		"affected": [{
			"package": {"ecosystem": "Ubuntu:22.04", "name": "openssl"},
			"ranges": [{"type": "ECOSYSTEM", "events": [
				{"introduced": "0"},
				{"fixed": "1.1.1f-1ubuntu2.16"}
			]}]
		}]
	}`)

	patched := affected.Component{
		NodeID: "n1", Purl: "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.16",
		Ecosystem: "Ubuntu:22.04", Name: "openssl",
		Version: "1.1.1f-1ubuntu2.16", Distro: "ubuntu:22.04",
	}
	got := matchOne(t, e, patched, adv)
	if got.Status != affected.StatusFixed {
		t.Fatalf("backported-patched openssl: want fixed, got %q (fixed=%q)", got.Status, got.FixedVersion)
	}
	if got.CVE != "CVE-2022-0778" {
		t.Errorf("want CVE alias as id, got %q", got.CVE)
	}
	if got.FixedVersion != "1.1.1f-1ubuntu2.16" {
		t.Errorf("want distro fixed version recorded, got %q", got.FixedVersion)
	}

	// An OLDER distro build of the same package is affected.
	older := patched
	older.Version = "1.1.1f-1ubuntu2.10"
	older.Purl = "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.10"
	if g := matchOne(t, e, older, adv); g.Status != affected.StatusAffected {
		t.Fatalf("older distro openssl: want affected, got %q", g.Status)
	}

	// Proof the naive comparator would be WRONG: the patched distro version
	// 1.1.1f-1ubuntu2.16 sorts BELOW the upstream fix 1.1.1g, so an upstream
	// compare would call the patched box vulnerable. The distro-fixed value is the
	// correct one and yields fixed above.
	if c := cmp("Ubuntu:22.04", "1.1.1f-1ubuntu2.16", "1.1.1g"); c >= 0 {
		t.Fatalf("expected backported version to sort below upstream fix (naive FP), got cmp=%d", c)
	}
}

// TestDebianRangeFixedVsAffected exercises a Debian ECOSYSTEM range with epoch and
// revision handling on both sides of the fix.
func TestDebianRangeFixedVsAffected(t *testing.T) {
	e := New("ws", nil)
	adv := vuln(t, `{
		"id": "DSA-OSV-1",
		"aliases": ["CVE-2023-1111"],
		"affected": [{
			"package": {"ecosystem": "Debian:12", "name": "curl"},
			"ranges": [{"type": "ECOSYSTEM", "events": [
				{"introduced": "0"},
				{"fixed": "7.88.1-10+deb12u5"}
			]}]
		}]
	}`)
	base := affected.Component{NodeID: "n1", Ecosystem: "Debian:12", Name: "curl", Distro: "debian:12"}

	vulnerable := base
	vulnerable.Version = "7.88.1-10+deb12u3"
	if g := matchOne(t, e, vulnerable, adv); g.Status != affected.StatusAffected {
		t.Fatalf("debian curl below fix: want affected, got %q", g.Status)
	}
	patched := base
	patched.Version = "7.88.1-10+deb12u5"
	if g := matchOne(t, e, patched, adv); g.Status != affected.StatusFixed {
		t.Fatalf("debian curl at fix: want fixed, got %q", g.Status)
	}
	newer := base
	newer.Version = "7.88.1-10+deb12u7"
	if g := matchOne(t, e, newer, adv); g.Status != affected.StatusFixed {
		t.Fatalf("debian curl past fix: want fixed, got %q", g.Status)
	}
}

// TestEcosystemRangesNpmPyPI proves the matcher is version-correct across two
// non-distro ecosystems with their own comparators, including an introduced floor
// and multiple ranges.
func TestEcosystemRangesNpmPyPI(t *testing.T) {
	e := New("ws", nil)

	npm := vuln(t, `{
		"id": "GHSA-npm-1",
		"aliases": ["CVE-2021-3807"],
		"affected": [{
			"package": {"ecosystem": "npm", "name": "ansi-regex"},
			"ranges": [{"type": "ECOSYSTEM", "events": [
				{"introduced": "0"},
				{"fixed": "5.0.1"},
				{"introduced": "6.0.0"},
				{"fixed": "6.0.1"}
			]}]
		}]
	}`)
	npmComp := affected.Component{NodeID: "n1", Ecosystem: "npm", Name: "ansi-regex"}
	// In the first vulnerable window.
	c1 := npmComp
	c1.Version = "5.0.0"
	if g := matchOne(t, e, c1, npm); g.Status != affected.StatusAffected {
		t.Fatalf("npm 5.0.0: want affected, got %q", g.Status)
	}
	// Between the two windows (>=5.0.1, <6.0.0): fixed by the first range, below the
	// second's introduced floor -> not in a vulnerable window.
	c2 := npmComp
	c2.Version = "5.5.0"
	if g := matchOne(t, e, c2, npm); g.Status != affected.StatusFixed {
		t.Fatalf("npm 5.5.0 (between windows): want fixed, got %q", g.Status)
	}
	// In the second window.
	c3 := npmComp
	c3.Version = "6.0.0"
	if g := matchOne(t, e, c3, npm); g.Status != affected.StatusAffected {
		t.Fatalf("npm 6.0.0: want affected, got %q", g.Status)
	}

	pypi := vuln(t, `{
		"id": "PYSEC-1",
		"aliases": ["CVE-2023-32681"],
		"affected": [{
			"package": {"ecosystem": "PyPI", "name": "requests"},
			"ranges": [{"type": "ECOSYSTEM", "events": [
				{"introduced": "2.3.0"},
				{"fixed": "2.31.0"}
			]}]
		}]
	}`)
	py := affected.Component{NodeID: "n1", Ecosystem: "PyPI", Name: "requests"}
	below := py
	below.Version = "2.2.0" // below the introduced floor
	if g := matchOne(t, e, below, pypi); g.Status != affected.StatusNotAffected {
		t.Fatalf("requests below introduced floor: want not_affected, got %q", g.Status)
	}
	vulnv := py
	vulnv.Version = "2.30.0"
	if g := matchOne(t, e, vulnv, pypi); g.Status != affected.StatusAffected {
		t.Fatalf("requests 2.30.0: want affected, got %q", g.Status)
	}
	fixedv := py
	fixedv.Version = "2.31.0"
	if g := matchOne(t, e, fixedv, pypi); g.Status != affected.StatusFixed {
		t.Fatalf("requests 2.31.0: want fixed, got %q", g.Status)
	}
}

// TestVEXSuppression flips an otherwise-affected verdict to not_affected and
// records the justification, and proves it does not fabricate a verdict for a
// fixed component.
func TestVEXSuppression(t *testing.T) {
	vex := NewMemVEX()
	purl := "pkg:pypi/requests@2.30.0"
	vex.Set("ws", "CVE-2023-32681", purl, "vulnerable_code_not_present")
	e := New("ws", vex)

	adv := vuln(t, `{
		"id": "PYSEC-1",
		"aliases": ["CVE-2023-32681"],
		"affected": [{
			"package": {"ecosystem": "PyPI", "name": "requests"},
			"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}]
		}]
	}`)
	c := affected.Component{NodeID: "n1", Purl: purl, Ecosystem: "PyPI", Name: "requests", Version: "2.30.0"}
	got := matchOne(t, e, c, adv)
	if got.Status != affected.StatusNotAffected {
		t.Fatalf("VEX-suppressed: want not_affected, got %q", got.Status)
	}
	if got.VEXJustification != "vulnerable_code_not_present" {
		t.Errorf("want justification recorded, got %q", got.VEXJustification)
	}

	// Same engine, a different purl with no VEX statement stays affected.
	other := c
	other.Purl = "pkg:pypi/requests@2.29.0"
	if g := matchOne(t, e, other, adv); g.Status != affected.StatusAffected {
		t.Fatalf("non-suppressed purl: want affected, got %q", g.Status)
	}
}

// TestPackageMismatchNoVerdict: an advisory for a different package yields no row
// for the component, so the caller emits nothing.
func TestPackageMismatchNoVerdict(t *testing.T) {
	e := New("ws", nil)
	adv := vuln(t, `{
		"id": "X-1", "aliases": ["CVE-2020-0001"],
		"affected": [{"package": {"ecosystem": "npm", "name": "left-pad"},
			"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]}]
	}`)
	c := affected.Component{NodeID: "n1", Ecosystem: "npm", Name: "ansi-regex", Version: "0.1.0"}
	ms, err := e.MatchAdvisory(context.Background(), adv, []affected.Component{c})
	if err != nil {
		t.Fatalf("MatchAdvisory: %v", err)
	}
	if len(ms) != 0 {
		t.Fatalf("want no verdict for unrelated package, got %d", len(ms))
	}
}

// TestMultiRangeAffectedAcrossEntries models an advisory that files the same
// package as several affected entries, one per major-version line — the shape
// CVE-2025-29927 uses for next. A version inside any one entry's window is
// affected even though every other entry reports it as past their fix, so the
// entries must be OR'd rather than a single one chosen.
func TestMultiRangeAffectedAcrossEntries(t *testing.T) {
	e := New("ws", nil)
	adv := vuln(t, `{
		"id": "GHSA-multi", "aliases": ["CVE-2025-29927"],
		"affected": [
			{"package": {"ecosystem": "npm", "name": "next"},
			 "ranges": [{"type": "SEMVER", "events": [{"introduced": "13.0.0"}, {"fixed": "13.5.9"}]}]},
			{"package": {"ecosystem": "npm", "name": "next"},
			 "ranges": [{"type": "SEMVER", "events": [{"introduced": "14.0.0"}, {"fixed": "14.2.25"}]}]},
			{"package": {"ecosystem": "npm", "name": "next"},
			 "ranges": [{"type": "SEMVER", "events": [{"introduced": "15.0.0"}, {"fixed": "15.2.3"}]}]}
		]
	}`)
	comp := func(v string) affected.Component {
		return affected.Component{NodeID: "n1", Purl: "pkg:npm/next@" + v, Ecosystem: "npm", Name: "next", Version: v}
	}

	// Inside the 14.x window: affected, even though the 13.x entry alone would
	// report 14.1.0 as already past its fix.
	if got := matchOne(t, e, comp("14.1.0"), adv); got.Status != affected.StatusAffected {
		t.Fatalf("next@14.1.0: want affected, got %q (fixed=%q)", got.Status, got.FixedVersion)
	}
	// Inside the 13.x window.
	if got := matchOne(t, e, comp("13.2.0"), adv); got.Status != affected.StatusAffected {
		t.Fatalf("next@13.2.0: want affected, got %q", got.Status)
	}
	// Past the 14.x fix and below the 15.x introduce: not in any window.
	if got := matchOne(t, e, comp("14.2.25"), adv); got.Status == affected.StatusAffected {
		t.Fatalf("next@14.2.25: want not affected, got %q", got.Status)
	}
	// An affected finding names the version that fixes the window it sits in: 14.1.0
	// is in the 14.x window whose fix is 14.2.25, so that is the upgrade target.
	if got := matchOne(t, e, comp("14.1.0"), adv); got.FixedVersion != "14.2.25" {
		t.Fatalf("next@14.1.0 affected: want fix 14.2.25, got %q", got.FixedVersion)
	}
	if got := matchOne(t, e, comp("13.2.0"), adv); got.FixedVersion != "13.5.9" {
		t.Fatalf("next@13.2.0 affected: want fix 13.5.9, got %q", got.FixedVersion)
	}
}

// TestSeverityAndFixOnVerdict proves the advisory's own severity rides the verdict
// (the offline default, no enrichment) and that an affected finding reports the
// fixing version of its open window.
func TestSeverityAndFixOnVerdict(t *testing.T) {
	e := New("ws", nil)
	adv := vuln(t, `{
		"id": "GHSA-sev", "aliases": ["CVE-2025-77"],
		"database_specific": {"severity": "CRITICAL"},
		"affected": [
			{"package": {"ecosystem": "npm", "name": "left-pad"},
			 "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.3.0"}]}]}
		]
	}`)
	c := affected.Component{NodeID: "n1", Purl: "pkg:npm/left-pad@1.1.0", Ecosystem: "npm", Name: "left-pad", Version: "1.1.0"}
	got := matchOne(t, e, c, adv)
	if got.Status != affected.StatusAffected {
		t.Fatalf("left-pad@1.1.0: want affected, got %q", got.Status)
	}
	if got.Severity != "CRITICAL" {
		t.Fatalf("severity not carried onto verdict: got %q", got.Severity)
	}
	if got.FixedVersion != "1.3.0" {
		t.Fatalf("affected fixing version: want 1.3.0, got %q", got.FixedVersion)
	}
}
