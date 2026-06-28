package controller

import (
	"context"
	"testing"
	"time"

	"geneza.io/internal/affected/vulnfeed"
	"geneza.io/internal/affected/vulnfeed/osv"
)

// imageDedupMatchSuite proves the fleet-wide image-digest dedup end to end: two nodes
// on one digest store the image SBOM once but both surface as affected, a feed change
// re-matches the digest once and updates both, removing one node leaves the other's
// verdict, and the digest-less (host) path is unchanged. It runs against any Store so
// bbolt and both SQL engines share the assertions.
func imageDedupMatchSuite(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	const ws = "wsA"
	const dig = "sha256:cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"
	src := "image:repo@" + dig

	if err := s.PutWorkspace(&WorkspaceRecord{ID: ws, Name: "A"}); err != nil {
		t.Fatalf("PutWorkspace: %v", err)
	}
	// Two nodes both running the SAME image digest (an older Ubuntu openssl), plus one
	// host openssl on n1 so the host path is exercised in the same suite.
	if err := s.PutNode(ws, &NodeRecord{ID: "n1", Name: "n1"}); err != nil {
		t.Fatalf("PutNode n1: %v", err)
	}
	if err := s.PutNode(ws, &NodeRecord{ID: "n2", Name: "n2"}); err != nil {
		t.Fatalf("PutNode n2: %v", err)
	}

	imgComp := ImageComponentRecord{
		Digest: dig, Purl: "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.10", Source: src,
		Ecosystem: "Ubuntu:22.04", Name: "openssl", Version: "1.1.1f-1ubuntu2.10", Distro: "ubuntu:22.04",
	}
	// Store the image SBOM ONCE keyed by digest, and associate both nodes with it.
	if err := s.PutImageComponents(dig, []ImageComponentRecord{imgComp}); err != nil {
		t.Fatalf("PutImageComponents: %v", err)
	}
	if err := s.SetNodeImages(ws, "n1", []string{dig}); err != nil {
		t.Fatalf("SetNodeImages n1: %v", err)
	}
	if err := s.SetNodeImages(ws, "n2", []string{dig}); err != nil {
		t.Fatalf("SetNodeImages n2: %v", err)
	}
	// A host openssl on n1 (per-node path) at the patched version -> must be fixed.
	if err := s.UpsertNodeComponents(ws, "n1", []ComponentRecord{
		{Purl: "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.16", Source: "os", Ecosystem: "Ubuntu:22.04", Name: "openssl", Version: "1.1.1f-1ubuntu2.16", Distro: "ubuntu:22.04"},
	}); err != nil {
		t.Fatalf("UpsertNodeComponents n1 host: %v", err)
	}

	// (a) The image SBOM is stored ONCE: there is no per-node image_components copy.
	if list, _ := s.ListImageComponents(dig); len(list) != 1 {
		t.Fatalf("image SBOM not stored once: len=%d", len(list))
	}

	// --- sync the advisory through the OSV dir feed and match the digest ONCE ---
	dir := writeOSVFixtures(t, map[string]string{
		"openssl.json": `{
			"id": "USN-1", "modified": "2024-01-01T00:00:00Z", "aliases": ["CVE-2022-0778"],
			"affected": [{"package": {"ecosystem": "Ubuntu:22.04", "name": "openssl"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.1f-1ubuntu2.16"}]}]}],
			"license": "CC-BY-4.0"
		}`,
	})
	feed := osv.New(dir, FeedStore(s))
	if _, err := feed.Sync(ctx, time.Time{}); err != nil {
		t.Fatalf("feed.Sync: %v", err)
	}

	m := newAffectedMatcher(s, nil, nil)
	// Match the digest once (the first-seen trigger).
	if w, err := m.MatchImageDigest(ctx, feed, dig); err != nil || w != 1 {
		t.Fatalf("MatchImageDigest: w=%d err=%v", w, err)
	}
	// Match the host node too.
	if _, err := m.MatchNode(ctx, feed, ws, "n1"); err != nil {
		t.Fatalf("MatchNode n1: %v", err)
	}

	// (b/a) ListNodesAffectedByCVE fans the single digest verdict to BOTH nodes.
	affected, err := nodesAffectedByCVEFanned(s, ws, "CVE-2022-0778")
	if err != nil {
		t.Fatalf("nodesAffectedByCVEFanned: %v", err)
	}
	gotNodes := affectedNodeSet(affected)
	if !gotNodes["n1"] || !gotNodes["n2"] {
		t.Fatalf("digest verdict did not fan to both nodes: %v", gotNodes)
	}
	// The per-node read returns the node's image-sourced finding.
	n2rows, _ := cvesForNodeFanned(s, ws, "n2")
	if len(n2rows) != 1 || n2rows[0].CVE != "CVE-2022-0778" || n2rows[0].Status != "affected" {
		t.Fatalf("n2 image finding missing/wrong: %+v", n2rows)
	}
	// n1 carries BOTH the image (affected) and host (fixed) openssl: distinct purls.
	n1rows, _ := cvesForNodeFanned(s, ws, "n1")
	if len(n1rows) != 2 {
		t.Fatalf("n1 should have image+host openssl rows: %+v", n1rows)
	}

	// --- (b) feed change re-matches the digest once; both nodes' verdicts update ---
	// Re-issue the advisory with a HIGHER fixed version so the image's older openssl
	// stays affected but the host's now-older-than-fixed flips appropriately; assert the
	// re-match touches the shared digest and both nodes still reflect it.
	dir2 := writeOSVFixtures(t, map[string]string{
		"openssl.json": `{
			"id": "USN-1", "modified": "2024-06-01T00:00:00Z", "aliases": ["CVE-2022-0778"],
			"affected": [{"package": {"ecosystem": "Ubuntu:22.04", "name": "openssl"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.1f-1ubuntu2.20"}]}]}],
			"license": "CC-BY-4.0"
		}`,
	})
	feed2 := osv.New(dir2, FeedStore(s))
	if _, err := feed2.Sync(ctx, time.Time{}); err != nil {
		t.Fatalf("feed2.Sync: %v", err)
	}
	changed := feed2.Changed()
	if len(changed) != 1 {
		t.Fatalf("feed2 changed: want 1 got %d", len(changed))
	}
	// The advisory-change image direction re-matches every digest carrying the package
	// ONCE (dedup by digest), not per node.
	m2 := newAffectedMatcher(s, nil, nil)
	if _, err := m2.MatchAdvisoryImages(ctx, feed2, changed[0]); err != nil {
		t.Fatalf("MatchAdvisoryImages: %v", err)
	}
	// Both nodes still affected (image openssl is below the new fixed version too).
	affected2, _ := nodesAffectedByCVEFanned(s, ws, "CVE-2022-0778")
	got2 := affectedNodeSet(affected2)
	if !got2["n1"] || !got2["n2"] {
		t.Fatalf("after feed change, digest verdict not fanned to both: %v", got2)
	}

	// --- (c) removing one node leaves the other's verdict intact ---
	if err := s.DeleteNode(ws, "n2"); err != nil {
		t.Fatalf("DeleteNode n2: %v", err)
	}
	affected3, _ := nodesAffectedByCVEFanned(s, ws, "CVE-2022-0778")
	got3 := affectedNodeSet(affected3)
	if got3["n2"] {
		t.Fatalf("deleted node n2 still surfaced: %v", got3)
	}
	if !got3["n1"] {
		t.Fatalf("surviving node n1 lost its verdict: %v", got3)
	}
	// The global image verdict survives (n1 still runs the digest).
	if list, _ := s.ImageCVEsForDigest(dig); len(list) == 0 {
		t.Fatalf("image verdict wrongly cleared after one node removed")
	}

	// --- (d) backward-compat: a digest-less node uses the per-node path unchanged ---
	if err := s.PutNode(ws, &NodeRecord{ID: "n3", Name: "n3"}); err != nil {
		t.Fatalf("PutNode n3: %v", err)
	}
	if err := s.UpsertNodeComponents(ws, "n3", []ComponentRecord{
		{Purl: "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.10", Source: "os", Ecosystem: "Ubuntu:22.04", Name: "openssl", Version: "1.1.1f-1ubuntu2.10", Distro: "ubuntu:22.04"},
	}); err != nil {
		t.Fatalf("UpsertNodeComponents n3: %v", err)
	}
	if _, err := m2.MatchNode(ctx, feed2, ws, "n3"); err != nil {
		t.Fatalf("MatchNode n3: %v", err)
	}
	n3rows, _ := cvesForNodeFanned(s, ws, "n3")
	if len(n3rows) != 1 || n3rows[0].Status != "affected" {
		t.Fatalf("backward-compat host-only node wrong: %+v", n3rows)
	}
	// n3 has no image association, so it never touches the image tables.
	if d, _ := s.NodeImageDigests(ws, "n3"); len(d) != 0 {
		t.Fatalf("host-only node gained image association: %v", d)
	}
}

func affectedNodeSet(rows []NodeCVERecord) map[string]bool {
	out := map[string]bool{}
	for _, r := range rows {
		if r.Status == "affected" {
			out[r.NodeID] = true
		}
	}
	return out
}

func TestImageDedupMatchBbolt(t *testing.T) {
	imageDedupMatchSuite(t, testStore(t))
}

func TestImageDedupMatchSQL(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		imageDedupMatchSuite(t, s)
	})
}

// stubImageAdvisor is a registry scan-by-digest provider that returns a fixed
// advisory for one known digest, proving the feed-side seam is real and callable.
type stubImageAdvisor struct {
	digest string
	advs   []vulnfeed.Vulnerability
}

func (s stubImageAdvisor) Name() string { return "stub" }

func (s stubImageAdvisor) AdvisoriesForDigest(_ context.Context, digest string) ([]vulnfeed.Vulnerability, error) {
	if digest == s.digest {
		return s.advs, nil
	}
	return nil, nil
}

// imageAdvisorSuite proves the registry scan-by-digest provider is folded into the
// digest match: an advisory the provider attributes to the digest produces a verdict
// even though it was never synced into the local feed.
func imageAdvisorSuite(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	const dig = "sha256:0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"

	if err := s.PutImageComponents(dig, []ImageComponentRecord{
		{Digest: dig, Purl: "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.10", Source: "image:repo@" + dig,
			Ecosystem: "Ubuntu:22.04", Name: "openssl", Version: "1.1.1f-1ubuntu2.10", Distro: "ubuntu:22.04"},
	}); err != nil {
		t.Fatalf("PutImageComponents: %v", err)
	}

	// An empty local feed (no advisories synced); the provider supplies the advisory.
	dir := writeOSVFixtures(t, map[string]string{})
	feed := osv.New(dir, FeedStore(s))

	m := newAffectedMatcher(s, nil, nil)
	m.imageAdvisor = stubImageAdvisor{
		digest: dig,
		advs: []vulnfeed.Vulnerability{{
			ID: "CVE-2022-0778",
			Affected: []vulnfeed.Affected{{
				Package: vulnfeed.Package{Ecosystem: "Ubuntu:22.04", Name: "openssl"},
				Ranges:  []vulnfeed.Range{{Type: "ECOSYSTEM", Events: []vulnfeed.Event{{Introduced: "0"}, {Fixed: "1.1.1f-1ubuntu2.16"}}}},
			}},
		}},
	}
	w, err := m.MatchImageDigest(ctx, feed, dig)
	if err != nil {
		t.Fatalf("MatchImageDigest with provider: %v", err)
	}
	if w != 1 {
		t.Fatalf("provider advisory did not produce a verdict: w=%d", w)
	}
	list, _ := s.ImageCVEsForDigest(dig)
	if len(list) != 1 || list[0].CVE != "CVE-2022-0778" || list[0].Status != "affected" {
		t.Fatalf("provider verdict wrong: %+v", list)
	}

	// The no-op default contributes nothing: clearing and re-matching with it yields
	// zero verdicts from the (empty) feed alone.
	m.imageAdvisor = vulnfeed.NoImageAdvisories{}
	if w, _ := m.MatchImageDigest(ctx, feed, dig); w != 0 {
		t.Fatalf("no-op provider should contribute nothing: w=%d", w)
	}
}

func TestImageAdvisorBbolt(t *testing.T) {
	imageAdvisorSuite(t, testStore(t))
}

func TestImageAdvisorSQL(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		imageAdvisorSuite(t, s)
	})
}
