package controller

import (
	"errors"
	"sort"
	"sync"
	"testing"
)

// imageDedupStoreSuite exercises the image-digest dedup tables (image_components,
// node_images, image_cve) across any Store impl, so bbolt and both SQL engines run
// the identical assertions.
func imageDedupStoreSuite(t *testing.T, s Store) {
	t.Helper()
	const wsA, wsB = "wsA", "wsB"
	const dig1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	const dig2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

	// --- image_components: store-once, has, list, by-package ---
	if has, err := s.HasImageComponents(dig1); err != nil || has {
		t.Fatalf("HasImageComponents empty: has=%v err=%v", has, err)
	}
	comps := []ImageComponentRecord{
		{Purl: "pkg:deb/debian/openssl@1.1.1f", Source: "image:repo@" + dig1, Ecosystem: "Debian", Name: "openssl", Version: "1.1.1f-1", Distro: "debian:11"},
		{Purl: "pkg:deb/debian/curl@7.74.0", Source: "image:repo@" + dig1, Ecosystem: "Debian", Name: "curl", Version: "7.74.0-1", Distro: "debian:11"},
	}
	if err := s.PutImageComponents(dig1, comps); err != nil {
		t.Fatalf("PutImageComponents: %v", err)
	}
	if has, err := s.HasImageComponents(dig1); err != nil || !has {
		t.Fatalf("HasImageComponents after put: has=%v err=%v", has, err)
	}
	if list, err := s.ListImageComponents(dig1); err != nil || len(list) != 2 {
		t.Fatalf("ListImageComponents: err=%v len=%d", err, len(list))
	}
	// Re-store is idempotent and replace-set: a smaller set drops the stale rows.
	if err := s.PutImageComponents(dig1, comps[:1]); err != nil {
		t.Fatalf("PutImageComponents replace: %v", err)
	}
	if list, _ := s.ListImageComponents(dig1); len(list) != 1 {
		t.Fatalf("image replace-set did not drop stale rows: len=%d", len(list))
	}
	if err := s.PutImageComponents(dig1, comps); err != nil {
		t.Fatalf("PutImageComponents restore: %v", err)
	}
	byPkg, err := s.ImageDigestsForPackage("Debian", "openssl")
	if err != nil || len(byPkg) != 1 || byPkg[0] != dig1 {
		t.Fatalf("ImageDigestsForPackage openssl: err=%v got=%v", err, byPkg)
	}

	// --- node_images association: replace-set per node, both directions ---
	if err := s.SetNodeImages(wsA, "n1", []string{dig1, dig2}); err != nil {
		t.Fatalf("SetNodeImages n1: %v", err)
	}
	if err := s.SetNodeImages(wsA, "n2", []string{dig1}); err != nil {
		t.Fatalf("SetNodeImages n2: %v", err)
	}
	if d, _ := s.NodeImageDigests(wsA, "n1"); len(d) != 2 {
		t.Fatalf("NodeImageDigests n1: got %v", d)
	}
	runs, err := s.NodesRunningDigest(wsA, dig1)
	if err != nil {
		t.Fatalf("NodesRunningDigest dig1: %v", err)
	}
	sort.Strings(runs)
	if len(runs) != 2 || runs[0] != "n1" || runs[1] != "n2" {
		t.Fatalf("NodesRunningDigest dig1: got %v, want [n1 n2]", runs)
	}
	// Replace-set: n1 stops running dig2 -> only dig1 fans to it.
	if err := s.SetNodeImages(wsA, "n1", []string{dig1}); err != nil {
		t.Fatalf("SetNodeImages n1 shrink: %v", err)
	}
	if d, _ := s.NodeImageDigests(wsA, "n1"); len(d) != 1 || d[0] != dig1 {
		t.Fatalf("NodeImageDigests n1 after shrink: got %v", d)
	}
	if runs, _ := s.NodesRunningDigest(wsA, dig2); len(runs) != 0 {
		t.Fatalf("dig2 still associated after shrink: %v", runs)
	}

	// --- workspace scoping: wsB sees none of wsA's associations ---
	if err := s.SetNodeImages(wsB, "nB", []string{dig1}); err != nil {
		t.Fatalf("SetNodeImages wsB: %v", err)
	}
	if runs, _ := s.NodesRunningDigest(wsA, dig1); len(runs) != 2 {
		t.Fatalf("wsB association leaked into wsA: %v", runs)
	}
	if runs, _ := s.NodesRunningDigest(wsB, dig1); len(runs) != 1 || runs[0] != "nB" {
		t.Fatalf("wsB NodesRunningDigest: got %v", runs)
	}

	// --- image_cve: upsert, list, replace-set clear ---
	iv := &ImageCVERecord{Digest: dig1, CVE: "CVE-2022-0778", Purl: "pkg:deb/debian/openssl@1.1.1f", Status: "affected", Severity: "high", FixedVersion: "1.1.1f-1+deb11u1", MatchedUnix: 5}
	if err := s.PutImageCVE(iv); err != nil {
		t.Fatalf("PutImageCVE: %v", err)
	}
	// Upsert in place.
	iv.Status = "fixed"
	if err := s.PutImageCVE(iv); err != nil {
		t.Fatalf("PutImageCVE update: %v", err)
	}
	if list, err := s.ImageCVEsForDigest(dig1); err != nil || len(list) != 1 || list[0].Status != "fixed" {
		t.Fatalf("ImageCVEsForDigest: err=%v list=%+v", err, list)
	}
	if distinct, _ := s.DistinctImageCVEs(); len(distinct) != 1 || distinct[0] != "CVE-2022-0778" {
		t.Fatalf("DistinctImageCVEs: %v", distinct)
	}
	// Enrich overlays KEV/EPSS by CVE and is idempotent.
	n, err := s.EnrichImageCVEs(map[string]CVEEnrichment{"CVE-2022-0778": {KEV: true, EPSS: 0.9}})
	if err != nil || n != 1 {
		t.Fatalf("EnrichImageCVEs: n=%d err=%v", n, err)
	}
	if n, _ := s.EnrichImageCVEs(map[string]CVEEnrichment{"CVE-2022-0778": {KEV: true, EPSS: 0.9}}); n != 0 {
		t.Fatalf("EnrichImageCVEs not idempotent: n=%d", n)
	}
	if list, _ := s.ImageCVEsForDigest(dig1); !list[0].KEV || list[0].EPSS != 0.9 {
		t.Fatalf("image enrichment not applied: %+v", list[0])
	}
	// Replace-set clear.
	if err := s.ClearImageCVEs(dig1); err != nil {
		t.Fatalf("ClearImageCVEs: %v", err)
	}
	if list, _ := s.ImageCVEsForDigest(dig1); len(list) != 0 {
		t.Fatalf("ClearImageCVEs left rows: %d", len(list))
	}

	// --- DeleteNode cascades the association but leaves the global image rows ---
	if err := s.PutNode(wsA, &NodeRecord{ID: "n2", Name: "n2"}); err != nil {
		t.Fatalf("PutNode for cascade: %v", err)
	}
	if err := s.DeleteNode(wsA, "n2"); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	// n2 no longer runs dig1; n1 still does.
	runs, _ = s.NodesRunningDigest(wsA, dig1)
	if len(runs) != 1 || runs[0] != "n1" {
		t.Fatalf("DeleteNode did not cascade node_images: %v", runs)
	}
	// The global image component set survives (n1 still references the digest).
	if has, _ := s.HasImageComponents(dig1); !has {
		t.Fatalf("DeleteNode wrongly dropped global image components")
	}
}

func TestImageDedupStoreBbolt(t *testing.T) {
	imageDedupStoreSuite(t, testStore(t))
}

func TestImageDedupStoreSQL(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		imageDedupStoreSuite(t, s)
	})
}

// TestImageDigestFromSource pins the source-string classifier the split rule depends
// on: a digest-pinned image source yields its digest; everything else (host sources,
// a bare image ref with no digest) falls through to the per-node path.
func TestImageDigestFromSource(t *testing.T) {
	cases := []struct {
		source string
		digest string
		ok     bool
	}{
		{"image:repo@sha256:abc123", "sha256:abc123", true},
		{"image:registry.example.com:5000/repo:tag@sha256:deadbeef", "sha256:deadbeef", true},
		{"image:repo", "", false},   // no digest resolved
		{"image:repo@sha256:", "", false}, // empty hex is unresolvable
		{"os", "", false},
		{"lang", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := imageDigestFromSource(c.source)
		if ok != c.ok || got != c.digest {
			t.Errorf("imageDigestFromSource(%q) = (%q,%v), want (%q,%v)", c.source, got, ok, c.digest, c.ok)
		}
	}
}

// TestSplitInventoryRouting proves the host/image partition: host and digest-less
// image components stay per-node, digest-pinned ones group by digest, and the digest
// order is first-seen.
func TestSplitInventoryRouting(t *testing.T) {
	const d1 = "sha256:aaaa"
	const d2 = "sha256:bbbb"
	comps := []ComponentRecord{
		{Purl: "a", Source: "os"},
		{Purl: "b", Source: "image:repo@" + d1},
		{Purl: "c", Source: "image:repo2@" + d2},
		{Purl: "d", Source: "image:nodigest"}, // digest-less -> host path
		{Purl: "e", Source: "image:repo@" + d1},
		{Purl: "f", Source: "lang"},
	}
	host, byDigest, digests := splitInventory(comps)
	if len(host) != 3 { // a, d, f
		t.Fatalf("host set: got %d want 3 (%+v)", len(host), host)
	}
	if len(byDigest[d1]) != 2 || len(byDigest[d2]) != 1 {
		t.Fatalf("byDigest grouping wrong: %+v", byDigest)
	}
	if len(digests) != 2 || digests[0] != d1 || digests[1] != d2 {
		t.Fatalf("digest first-seen order wrong: %v", digests)
	}
}

// errStore wraps a Store to fail one named method, so the fan-out error paths are
// exercised. Only the methods the fan-out helpers call are overridden.
type errImageStore struct {
	Store
	failDigests bool
}

func (e errImageStore) NodeImageDigests(ws, nodeID string) ([]string, error) {
	if e.failDigests {
		return nil, errors.New("boom")
	}
	return e.Store.NodeImageDigests(ws, nodeID)
}

// imageDigestWriteOnceRaceSuite hammers the digest store/associate path the way two
// nodes reporting the same brand-new digest concurrently would: many goroutines store
// the same digest's (content-addressable) component set and associate distinct nodes.
// The store is content-addressed, so the converged state is deterministic regardless
// of interleaving — exactly one component set for the digest, and every node
// associated. Run under -race this also proves no data race in the write path.
func imageDigestWriteOnceRaceSuite(t *testing.T, s Store) {
	t.Helper()
	const ws = "wsRace"
	const dig = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
	comps := []ImageComponentRecord{
		{Digest: dig, Purl: "pkg:deb/debian/openssl@1.1.1f", Source: "image:repo@" + dig, Ecosystem: "Debian", Name: "openssl", Version: "1.1.1f-1"},
	}
	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each "node" stores the identical content-addressed set (idempotent) and
			// associates its own id — the concurrent first-sight scenario.
			if err := s.PutImageComponents(dig, comps); err != nil {
				errs[i] = err
				return
			}
			errs[i] = s.SetNodeImages(ws, nodeName(i), []string{dig})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent writer %d: %v", i, err)
		}
	}
	// Converged: exactly one component set for the digest.
	if list, _ := s.ListImageComponents(dig); len(list) != 1 {
		t.Fatalf("write-once race produced %d component rows, want 1", len(list))
	}
	// Every node ended associated with the digest.
	runs, _ := s.NodesRunningDigest(ws, dig)
	if len(runs) != n {
		t.Fatalf("write-once race associated %d nodes, want %d", len(runs), n)
	}
}

func nodeName(i int) string {
	return "n" + string(rune('a'+i))
}

func TestImageDigestWriteOnceRaceBbolt(t *testing.T) {
	imageDigestWriteOnceRaceSuite(t, testStore(t))
}

func TestImageDigestWriteOnceRaceSQL(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		imageDigestWriteOnceRaceSuite(t, s)
	})
}

func TestCVEsForNodeFannedError(t *testing.T) {
	s := testStore(t)
	if _, err := cvesForNodeFanned(errImageStore{Store: s, failDigests: true}, "ws", "n1"); err == nil {
		t.Fatal("want fan-out error, got nil")
	}
}
