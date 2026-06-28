package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"geneza.io/internal/affected/engine"
	"geneza.io/internal/affected/vulnfeed/osv"
)

// fakeEnricher is a fixed per-CVE prioritization lookup for the match-time
// enrichment path: a CVE in the map returns its signal, any other returns none.
type fakeEnricher map[string]struct {
	kev  bool
	epss float64
}

func (f fakeEnricher) Lookup(cve string) (bool, float64) {
	e := f[cve]
	return e.kev, e.epss
}

// writeOSVFixtures drops a set of OSV JSON records into a temp dir the feed reads.
func writeOSVFixtures(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}
	return dir
}

// affectedMatchSuite seeds inventory + advisories (the advisories via the OSV dir
// feed's Sync, so the feed's parse/store path is exercised), runs the controller
// matching pass, and asserts the node_cve answer table. It runs against any Store
// so bbolt and both SQL engines share the assertions.
func affectedMatchSuite(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	const wsA, wsB = "wsA", "wsB"

	if err := s.PutWorkspace(&WorkspaceRecord{ID: wsA, Name: "A"}); err != nil {
		t.Fatalf("PutWorkspace A: %v", err)
	}
	if err := s.PutWorkspace(&WorkspaceRecord{ID: wsB, Name: "B"}); err != nil {
		t.Fatalf("PutWorkspace B: %v", err)
	}

	// --- seed inventory ---
	// wsA/n1: an Ubuntu openssl at the BACKPORTED-and-patched version -> must be
	// fixed; wsA/n2: an OLDER Ubuntu openssl -> must be affected; wsA/n1 also a
	// vulnerable npm dep. wsB/nB has the same backported openssl: it must NEVER
	// surface under wsA, and a wsA-scoped advisory match must not touch it.
	if err := s.UpsertNodeComponents(wsA, "n1", []ComponentRecord{
		{Purl: "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.16", Source: "os", Ecosystem: "Ubuntu:22.04", Name: "openssl", Version: "1.1.1f-1ubuntu2.16", Distro: "ubuntu:22.04"},
		{Purl: "pkg:npm/ansi-regex@5.0.0", Source: "lang", Ecosystem: "npm", Name: "ansi-regex", Version: "5.0.0"},
	}); err != nil {
		t.Fatalf("seed n1: %v", err)
	}
	if err := s.UpsertNodeComponents(wsA, "n2", []ComponentRecord{
		{Purl: "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.10", Source: "os", Ecosystem: "Ubuntu:22.04", Name: "openssl", Version: "1.1.1f-1ubuntu2.10", Distro: "ubuntu:22.04"},
	}); err != nil {
		t.Fatalf("seed n2: %v", err)
	}
	if err := s.UpsertNodeComponents(wsB, "nB", []ComponentRecord{
		{Purl: "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.16", Source: "os", Ecosystem: "Ubuntu:22.04", Name: "openssl", Version: "1.1.1f-1ubuntu2.16", Distro: "ubuntu:22.04"},
	}); err != nil {
		t.Fatalf("seed nB: %v", err)
	}

	// --- sync advisories through the OSV dir feed ---
	dir := writeOSVFixtures(t, map[string]string{
		"openssl.json": `{
			"id": "USN-1", "modified": "2024-01-01T00:00:00Z", "aliases": ["CVE-2022-0778"],
			"affected": [{"package": {"ecosystem": "Ubuntu:22.04", "name": "openssl"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.1f-1ubuntu2.16"}]}]}],
			"license": "CC-BY-4.0"
		}`,
		"ansi.json": `{
			"id": "GHSA-1", "modified": "2024-01-01T00:00:00Z", "aliases": ["CVE-2021-3807"],
			"affected": [{"package": {"ecosystem": "npm", "name": "ansi-regex"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.0.1"}]}]}]
		}`,
	})
	feed := osv.New(dir, FeedStore(s))
	n, err := feed.Sync(ctx, time.Time{})
	if err != nil {
		t.Fatalf("feed.Sync: %v", err)
	}
	if n != 2 {
		t.Fatalf("feed.Sync wrote %d advisories, want 2", n)
	}

	// --- run the new-CVE matching pass for each changed advisory ---
	// A fixed enricher marks one CVE KEV+EPSS so the match-time enrichment path is
	// exercised: the verdicts it writes carry the prioritization signal.
	m := newAffectedMatcher(s, nil, fakeEnricher{
		"CVE-2022-0778": {kev: true, epss: 0.91},
	})
	osslAdv, err := feed.Advisories("Ubuntu:22.04", "openssl")
	if err != nil || len(osslAdv) != 1 {
		t.Fatalf("Advisories openssl: err=%v len=%d", err, len(osslAdv))
	}
	if _, err := m.MatchAdvisoryAllWorkspaces(ctx, osslAdv[0]); err != nil {
		t.Fatalf("match openssl advisory: %v", err)
	}
	ansiAdv, _ := feed.Advisories("npm", "ansi-regex")
	if len(ansiAdv) != 1 {
		t.Fatalf("Advisories ansi-regex: len=%d", len(ansiAdv))
	}
	if _, err := m.MatchAdvisoryAllWorkspaces(ctx, ansiAdv[0]); err != nil {
		t.Fatalf("match ansi advisory: %v", err)
	}

	// --- assert node_cve ---
	// The backported-patched openssl on wsA/n1 is FIXED (the headline), the older
	// one on wsA/n2 is AFFECTED. NodesAffectedByCVE returns both rows for the CVE;
	// status distinguishes them.
	rows, err := s.NodesAffectedByCVE(wsA, "CVE-2022-0778")
	if err != nil {
		t.Fatalf("NodesAffectedByCVE: %v", err)
	}
	byNode := map[string]NodeCVERecord{}
	for _, r := range rows {
		byNode[r.NodeID] = r
	}
	if len(byNode) != 2 {
		t.Fatalf("openssl CVE: want rows for n1 and n2, got %d (%v)", len(byNode), byNode)
	}
	if got := byNode["n1"].Status; got != "fixed" {
		t.Errorf("n1 backported-patched openssl: want fixed, got %q", got)
	}
	if byNode["n1"].FixedVersion != "1.1.1f-1ubuntu2.16" {
		t.Errorf("n1 fixed version: want distro version, got %q", byNode["n1"].FixedVersion)
	}
	if got := byNode["n2"].Status; got != "affected" {
		t.Errorf("n2 older openssl: want affected, got %q", got)
	}
	// Match-time enrichment: the openssl CVE the fake enricher marked carries the
	// KEV/EPSS signal on the verdict rows it wrote, while the npm CVE (no signal)
	// does not.
	if !byNode["n1"].KEV || byNode["n1"].EPSS != 0.91 {
		t.Errorf("n1 openssl verdict not enriched at match time: kev=%v epss=%v", byNode["n1"].KEV, byNode["n1"].EPSS)
	}
	if !byNode["n2"].KEV || byNode["n2"].EPSS != 0.91 {
		t.Errorf("n2 openssl verdict not enriched at match time: kev=%v epss=%v", byNode["n2"].KEV, byNode["n2"].EPSS)
	}

	// CVEsForNode: n1 carries the openssl (fixed) and the npm (affected) verdicts.
	n1cves, err := s.CVEsForNode(wsA, "n1")
	if err != nil {
		t.Fatalf("CVEsForNode n1: %v", err)
	}
	gotCVEs := map[string]string{}
	for _, r := range n1cves {
		gotCVEs[r.CVE] = r.Status
	}
	if gotCVEs["CVE-2022-0778"] != "fixed" || gotCVEs["CVE-2021-3807"] != "affected" {
		t.Errorf("n1 cve set wrong: %v", gotCVEs)
	}

	// --- tenant isolation: the fleet-wide pass DID evaluate wsB's nB (it carries
	// the package), but the verdict is written UNDER wsB and is backport-aware on
	// its own — it never appears in wsA's answer set, and wsA's answer set never
	// gained an nB row. ---
	wsArows, _ := s.NodesAffectedByCVE(wsA, "CVE-2022-0778")
	for _, r := range wsArows {
		if r.NodeID == "nB" {
			t.Fatalf("wsB node nB leaked into wsA answer set: %v", r)
		}
	}
	wsBrows, err := s.NodesAffectedByCVE(wsB, "CVE-2022-0778")
	if err != nil {
		t.Fatalf("NodesAffectedByCVE wsB: %v", err)
	}
	if len(wsBrows) != 1 || wsBrows[0].NodeID != "nB" || wsBrows[0].Status != "fixed" {
		t.Fatalf("wsB nB backported openssl: want one fixed row, got %v", wsBrows)
	}

	// --- new advisory re-matches WITHOUT touching unrelated nodes ---
	// A brand-new CVE for npm ansi-regex (a second advisory) selects only the nodes
	// carrying ansi-regex (wsA/n1), never the openssl-only n2 or wsB/nB.
	dir2 := writeOSVFixtures(t, map[string]string{
		"ansi2.json": `{
			"id": "GHSA-2", "modified": "2024-06-01T00:00:00Z", "aliases": ["CVE-2024-9999"],
			"affected": [{"package": {"ecosystem": "npm", "name": "ansi-regex"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "6.0.0"}]}]}]
		}`,
	})
	feed2 := osv.New(dir2, FeedStore(s))
	if _, err := feed2.Sync(ctx, time.Time{}); err != nil {
		t.Fatalf("feed2.Sync: %v", err)
	}
	beforeN2, _ := s.CVEsForNode(wsA, "n2")
	beforeNB, _ := s.CVEsForNode(wsB, "nB")
	// The store-backed feed now resolves both ansi-regex advisories; match only the
	// newly-synced one, exactly as a post-sync pass would for the changed record.
	all, _ := feed2.Advisories("npm", "ansi-regex")
	matchedNew := false
	for _, adv := range all {
		if adv.ID != "GHSA-2" { // the parsed OSV id (Doc-level), the new advisory
			continue
		}
		matchedNew = true
		if _, err := m.MatchAdvisoryAllWorkspaces(ctx, adv); err != nil {
			t.Fatalf("match new ansi advisory: %v", err)
		}
	}
	if !matchedNew {
		t.Fatalf("new advisory GHSA-2 not resolvable after sync")
	}
	// n1 now also carries the new CVE.
	if rows, _ := s.NodesAffectedByCVE(wsA, "CVE-2024-9999"); len(rows) != 1 || rows[0].NodeID != "n1" {
		t.Fatalf("new CVE: want only n1, got %v", rows)
	}
	// The unrelated nodes were untouched (same cve-set counts as before).
	if afterN2, _ := s.CVEsForNode(wsA, "n2"); len(afterN2) != len(beforeN2) {
		t.Errorf("new ansi advisory touched unrelated n2: before=%d after=%d", len(beforeN2), len(afterN2))
	}
	if afterNB, _ := s.CVEsForNode(wsB, "nB"); len(afterNB) != len(beforeNB) {
		t.Errorf("new ansi advisory touched foreign-ws nB: before=%d after=%d", len(beforeNB), len(afterNB))
	}

	// --- node-change direction + VEX suppression ---
	vex := engine.NewMemVEX()
	vex.Set(wsA, "CVE-2021-3807", "pkg:npm/ansi-regex@5.0.0", "vulnerable_code_not_present")
	mv := newAffectedMatcher(s, vex, nil)
	if _, err := mv.MatchNode(ctx, feed, wsA, "n1"); err != nil {
		t.Fatalf("MatchNode n1: %v", err)
	}
	n1cves, _ = s.CVEsForNode(wsA, "n1")
	for _, r := range n1cves {
		if r.CVE == "CVE-2021-3807" && r.Purl == "pkg:npm/ansi-regex@5.0.0" {
			if r.Status != "not_affected" || r.VEXJustification != "vulnerable_code_not_present" {
				t.Errorf("VEX did not suppress ansi-regex on re-match: %+v", r)
			}
		}
	}
}

func TestAffectedMatchBbolt(t *testing.T) {
	affectedMatchSuite(t, testStore(t))
}

func TestAffectedMatchSQL(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		affectedMatchSuite(t, s)
	})
}
