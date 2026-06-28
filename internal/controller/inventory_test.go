package controller

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"geneza.io/internal/affected/vulnfeed/osv"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/sbom"
)

// inventoryReportFor builds an InventoryReport for a set of components exactly as
// the agent would: encode to CycloneDX, hash the canonical doc, zstd-compress.
func inventoryReportFor(t *testing.T, node string, comps []sbom.Component) *genezav1.InventoryReport {
	t.Helper()
	doc, err := sbom.Encode(node, comps)
	if err != nil {
		t.Fatalf("encode sbom: %v", err)
	}
	hash := sbom.Hash(doc)
	blob, err := sbom.Compress(doc)
	if err != nil {
		t.Fatalf("compress sbom: %v", err)
	}
	return &genezav1.InventoryReport{
		Format:        sbom.MediaType,
		ContentHash:   hash[:],
		Sbom:          blob,
		CollectedUnix: time.Now().Unix(),
		NodeId:        node,
	}
}

// inventoryIngestSuite drives the full SBOM->node_cve path through the controller
// dispatch entry point: an InventoryReport is ingested (stored, components
// extracted, re-matched) for each node, and the answer table is asserted. It runs
// against any Store so bbolt and both SQL engines share the assertions.
func inventoryIngestSuite(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	const wsA, wsB = "wsA", "wsB"
	if err := s.PutWorkspace(&WorkspaceRecord{ID: wsA, Name: "A"}); err != nil {
		t.Fatalf("PutWorkspace A: %v", err)
	}
	if err := s.PutWorkspace(&WorkspaceRecord{ID: wsB, Name: "B"}); err != nil {
		t.Fatalf("PutWorkspace B: %v", err)
	}

	// Seed the advisory the matcher resolves against, through the OSV dir feed's own
	// Sync (the same parse/store path production uses). The fixed event is the
	// DISTRO's backported version — the backport-aware match.
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
	if _, err := feed.Sync(ctx, time.Time{}); err != nil {
		t.Fatalf("feed.Sync: %v", err)
	}

	srv := &Server{store: s, inventoryFeed: feed}

	// wsA/n1: the BACKPORTED-and-patched openssl + a vulnerable npm dep.
	n1report := inventoryReportFor(t, "n1", []sbom.Component{
		{Purl: "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.16?distro=ubuntu-22.04", Name: "openssl", Version: "1.1.1f-1ubuntu2.16", Ecosystem: "Ubuntu:22.04", Distro: "ubuntu:22.04", Source: "os"},
		{Purl: "pkg:npm/ansi-regex@5.0.0", Name: "ansi-regex", Version: "5.0.0", Ecosystem: "npm", Source: "lang"},
	})
	// wsA/n2: an OLDER openssl -> affected.
	n2report := inventoryReportFor(t, "n2", []sbom.Component{
		{Purl: "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.10?distro=ubuntu-22.04", Name: "openssl", Version: "1.1.1f-1ubuntu2.10", Ecosystem: "Ubuntu:22.04", Distro: "ubuntu:22.04", Source: "os"},
	})
	// wsB/nB: the backported openssl, in a FOREIGN workspace — must never surface
	// under wsA.
	nBreport := inventoryReportFor(t, "nB", []sbom.Component{
		{Purl: "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.16?distro=ubuntu-22.04", Name: "openssl", Version: "1.1.1f-1ubuntu2.16", Ecosystem: "Ubuntu:22.04", Distro: "ubuntu:22.04", Source: "os"},
	})

	if _, err := srv.ingestInventoryReport(ctx, wsA, "n1", n1report); err != nil {
		t.Fatalf("ingest n1: %v", err)
	}
	if _, err := srv.ingestInventoryReport(ctx, wsA, "n2", n2report); err != nil {
		t.Fatalf("ingest n2: %v", err)
	}
	if _, err := srv.ingestInventoryReport(ctx, wsB, "nB", nBreport); err != nil {
		t.Fatalf("ingest nB: %v", err)
	}

	// --- the SBOM blob is stored verbatim, keyed to the authenticated node ---
	rec, err := s.GetNodeSBOM(wsA, "n1")
	if err != nil {
		t.Fatalf("GetNodeSBOM n1: %v", err)
	}
	if rec.Format != sbom.MediaType || len(rec.SBOM) == 0 || rec.ContentHash == "" {
		t.Fatalf("stored sbom incomplete: %+v", rec)
	}

	// --- components were extracted into the index ---
	comps, err := s.ListNodeComponents(wsA, "n1")
	if err != nil {
		t.Fatalf("ListNodeComponents n1: %v", err)
	}
	if len(comps) != 2 {
		t.Fatalf("n1 components: want 2, got %d (%+v)", len(comps), comps)
	}

	// --- node_cve: backported openssl is FIXED, the older one AFFECTED ---
	rows, err := s.NodesAffectedByCVE(wsA, "CVE-2022-0778")
	if err != nil {
		t.Fatalf("NodesAffectedByCVE: %v", err)
	}
	byNode := map[string]NodeCVERecord{}
	for _, r := range rows {
		byNode[r.NodeID] = r
	}
	if got := byNode["n1"].Status; got != "fixed" {
		t.Errorf("n1 backported openssl: want fixed, got %q", got)
	}
	if byNode["n1"].FixedVersion != "1.1.1f-1ubuntu2.16" {
		t.Errorf("n1 fixed version: want distro version, got %q", byNode["n1"].FixedVersion)
	}
	if got := byNode["n2"].Status; got != "affected" {
		t.Errorf("n2 older openssl: want affected, got %q", got)
	}
	// The npm dep on n1 is affected (5.0.0 < fixed 5.0.1).
	n1cves, _ := s.CVEsForNode(wsA, "n1")
	gotCVEs := map[string]string{}
	for _, r := range n1cves {
		gotCVEs[r.CVE] = r.Status
	}
	if gotCVEs["CVE-2022-0778"] != "fixed" || gotCVEs["CVE-2021-3807"] != "affected" {
		t.Errorf("n1 cve set wrong: %v", gotCVEs)
	}

	// --- foreign-workspace isolation: nB never appears under wsA, and wsB's own
	// verdict is backport-aware on its own ---
	for _, r := range rows {
		if r.NodeID == "nB" {
			t.Fatalf("foreign-ws node nB leaked into wsA answer set: %v", r)
		}
	}
	wsBrows, err := s.NodesAffectedByCVE(wsB, "CVE-2022-0778")
	if err != nil {
		t.Fatalf("NodesAffectedByCVE wsB: %v", err)
	}
	if len(wsBrows) != 1 || wsBrows[0].NodeID != "nB" || wsBrows[0].Status != "fixed" {
		t.Fatalf("wsB nB backported openssl: want one fixed row, got %v", wsBrows)
	}
	// wsB never gained a wsA component row.
	if c, _ := s.ListNodeComponents(wsB, "n1"); len(c) != 0 {
		t.Fatalf("wsB leaked wsA node n1 components: %v", c)
	}

	// --- a node binds to its AUTHENTICATED identity, never the report's node_id ---
	// nB's report self-names "nB", but ingesting it under (wsA, spoof) must store it
	// for spoof, not for the named node.
	spoof := inventoryReportFor(t, "nB", []sbom.Component{
		{Purl: "pkg:npm/left-pad@1.0.0", Name: "left-pad", Version: "1.0.0", Ecosystem: "npm", Source: "lang"},
	})
	if _, err := srv.ingestInventoryReport(ctx, wsA, "spoof", spoof); err != nil {
		t.Fatalf("ingest spoof: %v", err)
	}
	if _, err := s.GetNodeSBOM(wsA, "spoof"); err != nil {
		t.Fatalf("spoof sbom must be stored under the authenticated node: %v", err)
	}
	// The foreign node nB's stored SBOM is unchanged (still the openssl one, 1 comp).
	if c, _ := s.ListNodeComponents(wsB, "nB"); len(c) != 1 {
		t.Fatalf("report node_id must not let a node write another's inventory: nB now has %d comps", len(c))
	}

	// --- idempotent re-ingest (same hash) writes the same verdicts, no drift ---
	beforeN1, _ := s.CVEsForNode(wsA, "n1")
	if _, err := srv.ingestInventoryReport(ctx, wsA, "n1", n1report); err != nil {
		t.Fatalf("re-ingest n1: %v", err)
	}
	afterN1, _ := s.CVEsForNode(wsA, "n1")
	if len(afterN1) != len(beforeN1) {
		t.Errorf("idempotent re-ingest changed the verdict count: before=%d after=%d", len(beforeN1), len(afterN1))
	}

	// --- a content-hash that lies about the shipped bytes is rejected ---
	bad := inventoryReportFor(t, "n1", []sbom.Component{{Purl: "pkg:npm/x@1.0.0", Name: "x", Version: "1.0.0", Ecosystem: "npm"}})
	bad.ContentHash = []byte("0000000000000000000000000000000000000000000000000000000000000000")
	if _, err := srv.ingestInventoryReport(ctx, wsA, "n1", bad); err == nil {
		t.Errorf("a lying content hash must be rejected")
	}
}

func TestInventoryIngestBbolt(t *testing.T) {
	inventoryIngestSuite(t, testStore(t))
}

func TestInventoryIngestSQL(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		inventoryIngestSuite(t, s)
	})
}

// TestInventoryNoFeedStillIndexes proves that with no feed configured the report
// still stores the SBOM and indexes components (the answer table just stays empty
// until a feed lands), so the data source works ahead of the matcher being wired.
func TestInventoryNoFeedStillIndexes(t *testing.T) {
	s := testStore(t)
	if err := s.PutWorkspace(&WorkspaceRecord{ID: "ws", Name: "ws"}); err != nil {
		t.Fatalf("PutWorkspace: %v", err)
	}
	srv := &Server{store: s} // no inventoryFeed
	rep := inventoryReportFor(t, "n", []sbom.Component{
		{Purl: "pkg:npm/ansi-regex@5.0.0", Name: "ansi-regex", Version: "5.0.0", Ecosystem: "npm", Source: "lang"},
	})
	written, err := srv.ingestInventoryReport(context.Background(), "ws", "n", rep)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if written != 0 {
		t.Errorf("no feed: want 0 verdicts, got %d", written)
	}
	if c, _ := s.ListNodeComponents("ws", "n"); len(c) != 1 {
		t.Errorf("components still indexed without a feed: got %d", len(c))
	}
	if _, err := s.GetNodeSBOM("ws", "n"); err != nil {
		t.Errorf("sbom still stored without a feed: %v", err)
	}
}

// deltaReportFor builds a DELTA InventoryReport against a base hash exactly as the
// agent would: the result content hash is the canonical hash of the WHOLE next set,
// added/removed are the diff against base.
func deltaReportFor(t *testing.T, node string, base [32]byte, baseSet, next []sbom.Component) *genezav1.InventoryReport {
	t.Helper()
	doc, err := sbom.Encode(node, next)
	if err != nil {
		t.Fatalf("encode next: %v", err)
	}
	hash := sbom.Hash(doc)
	added, removed := sbom.Diff(baseSet, next)
	rep := &genezav1.InventoryReport{
		Format:        sbom.MediaType,
		ContentHash:   hash[:],
		CollectedUnix: time.Now().Unix(),
		NodeId:        node,
		BaseHash:      base[:],
	}
	for _, c := range added {
		rep.Added = append(rep.Added, componentProto(c))
	}
	for _, c := range removed {
		rep.Removed = append(rep.Removed, componentProto(c))
	}
	return rep
}

func componentProto(c sbom.Component) *genezav1.InventoryComponent {
	return &genezav1.InventoryComponent{
		Purl: c.Purl, Name: c.Name, Version: c.Version,
		Ecosystem: c.Ecosystem, Distro: c.Distro, Source: c.Source,
	}
}

// inventoryDeltaSuite proves the delta path end-to-end through the controller dispatch:
// a full report establishes the set, a delta (add+remove vs base_hash) updates the
// component index and re-matches, a STALE-base delta is rejected with the full-resend
// signal, and a delta is idempotent. It runs against any Store so bbolt and both SQL
// engines share the assertions.
func inventoryDeltaSuite(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	const ws = "wsD"
	if err := s.PutWorkspace(&WorkspaceRecord{ID: ws, Name: "D"}); err != nil {
		t.Fatalf("PutWorkspace: %v", err)
	}

	// A feed with a kernel advisory and an npm advisory, so the re-match after a delta
	// is observable in the answer table.
	dir := writeOSVFixtures(t, map[string]string{
		"kernel.json": `{
			"id": "USN-KERN", "modified": "2024-01-01T00:00:00Z", "aliases": ["CVE-2024-KERNEL"],
			"affected": [{"package": {"ecosystem": "Debian:12", "name": "linux-kernel"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "6.1.0-22"}]}]}],
			"license": "CC-BY-4.0"
		}`,
		"leftpad.json": `{
			"id": "GHSA-LP", "modified": "2024-01-01T00:00:00Z", "aliases": ["CVE-2024-LEFTPAD"],
			"affected": [{"package": {"ecosystem": "npm", "name": "left-pad"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.0"}]}]}]
		}`,
	})
	feed := osv.New(dir, FeedStore(s))
	if _, err := feed.Sync(ctx, time.Time{}); err != nil {
		t.Fatalf("feed.Sync: %v", err)
	}
	srv := &Server{store: s, inventoryFeed: feed}

	// --- a FULL report establishes the base set ---
	baseSet := []sbom.Component{
		{Purl: "pkg:npm/ansi-regex@5.0.0", Name: "ansi-regex", Version: "5.0.0", Ecosystem: "npm", Source: "lang"},
		{Purl: "pkg:generic/linux-kernel@6.1.0-21", Name: "linux-kernel", Version: "6.1.0-21", Ecosystem: "Debian:12", Distro: "debian:12", Source: "kernel"},
	}
	full := inventoryReportFor(t, "nD", baseSet)
	full.Full = true
	if _, err := srv.ingestInventoryReport(ctx, ws, "nD", full); err != nil {
		t.Fatalf("ingest full: %v", err)
	}
	baseHash := sbom.Hash(mustEncodeForTest(t, baseSet))
	if rec, _ := s.GetNodeSBOM(ws, "nD"); rec == nil || rec.ContentHash != hex.EncodeToString(baseHash[:]) {
		t.Fatalf("stored base hash mismatch: %+v", rec)
	}
	// The seeded vulnerable kernel is affected at the base.
	if cves, _ := s.CVEsForNode(ws, "nD"); statusOf(cves, "CVE-2024-KERNEL") != "affected" {
		t.Fatalf("base kernel must be affected: %v", cves)
	}

	// --- a DELTA: add left-pad, REMOVE ansi-regex, BUMP the kernel to a fixed version ---
	next := []sbom.Component{
		{Purl: "pkg:npm/left-pad@1.0.0", Name: "left-pad", Version: "1.0.0", Ecosystem: "npm", Source: "lang"},
		{Purl: "pkg:generic/linux-kernel@6.1.0-22", Name: "linux-kernel", Version: "6.1.0-22", Ecosystem: "Debian:12", Distro: "debian:12", Source: "kernel"},
	}
	delta := deltaReportFor(t, "nD", baseHash, baseSet, next)
	// The delta carries only the change, not the whole set.
	if delta.GetFull() || len(delta.GetSbom()) != 0 {
		t.Fatalf("delta must carry no full sbom")
	}
	if _, err := srv.ingestInventoryReport(ctx, ws, "nD", delta); err != nil {
		t.Fatalf("ingest delta: %v", err)
	}

	// --- the component index now reflects the delta-applied set ---
	comps, _ := s.ListNodeComponents(ws, "nD")
	got := map[string]string{}
	for _, c := range comps {
		got[c.Name] = c.Version
	}
	if len(comps) != 2 || got["left-pad"] != "1.0.0" || got["linux-kernel"] != "6.1.0-22" {
		t.Fatalf("delta-applied components wrong: %+v", comps)
	}
	if _, stale := got["ansi-regex"]; stale {
		t.Fatalf("removed component must be gone after delta: %+v", comps)
	}
	// The stored SBOM hash is the next set's hash, and round-trips.
	nextHash := sbom.Hash(mustEncodeForTest(t, next))
	if rec, _ := s.GetNodeSBOM(ws, "nD"); rec == nil || rec.ContentHash != hex.EncodeToString(nextHash[:]) {
		t.Fatalf("post-delta stored hash must be the next set hash: %+v", rec)
	}

	// --- the re-match ran on the new set: bumped kernel now FIXED, left-pad AFFECTED ---
	cves, _ := s.CVEsForNode(ws, "nD")
	if statusOf(cves, "CVE-2024-KERNEL") != "fixed" {
		t.Errorf("bumped kernel must be fixed after delta: %v", cves)
	}
	if statusOf(cves, "CVE-2024-LEFTPAD") != "affected" {
		t.Errorf("added left-pad must be affected after delta: %v", cves)
	}

	// --- idempotent: re-applying the SAME delta against the now-current set is a base
	// mismatch (the base is gone), so it asks for a full — it must not corrupt state ---
	if _, err := srv.ingestInventoryReport(ctx, ws, "nD", delta); !errors.Is(err, errInventoryNeedFull) {
		t.Errorf("re-applying a delta whose base is no longer held must request a full, got %v", err)
	}
	// State is unchanged by the rejected re-apply.
	if c2, _ := s.ListNodeComponents(ws, "nD"); len(c2) != 2 {
		t.Errorf("rejected delta must not change the component set: %d", len(c2))
	}

	// --- a STALE-base delta (a base the controller never held) is rejected for a full ---
	var bogus [32]byte
	for i := range bogus {
		bogus[i] = 0xab
	}
	staleNext := append([]sbom.Component{{Purl: "pkg:npm/x@1.0.0", Name: "x", Version: "1.0.0", Ecosystem: "npm", Source: "lang"}}, next...)
	stale := deltaReportFor(t, "nD", bogus, next, staleNext)
	if _, err := srv.ingestInventoryReport(ctx, ws, "nD", stale); !errors.Is(err, errInventoryNeedFull) {
		t.Fatalf("a delta with an unheld base must request a full, got %v", err)
	}
	if c3, _ := s.ListNodeComponents(ws, "nD"); len(c3) != 2 {
		t.Fatalf("stale-base rejection must not change state: %d", len(c3))
	}

	// --- a delta whose reconstructed set does NOT match its claimed content hash is
	// rejected outright (corruption), distinct from a base mismatch ---
	corrupt := deltaReportFor(t, "nD", nextHash, next, []sbom.Component{
		{Purl: "pkg:npm/left-pad@1.0.0", Name: "left-pad", Version: "1.0.0", Ecosystem: "npm", Source: "lang"},
	})
	corrupt.ContentHash = []byte("not-the-real-hash-not-the-real-ha")
	if _, err := srv.ingestInventoryReport(ctx, ws, "nD", corrupt); err == nil || errors.Is(err, errInventoryNeedFull) {
		t.Fatalf("a delta whose result mishashes must be rejected as corrupt, got %v", err)
	}
}

// inventoryImageMatchSuite proves the container-image dedup path end to end through
// the controller: a node reports a host package (clean) AND a container-image package
// (vulnerable) tagged source "image:<ref>@<digest>". The image SBOM is stored ONCE by
// digest and matched ONCE; the digest's verdict fans (via the node->digest
// association) to every node running it, while the host package stays on the per-node
// path. A second node running the SAME digest does NOT re-store the image set yet still
// surfaces as affected. Runs against any Store so bbolt and both SQL engines share the
// assertions.
func inventoryImageMatchSuite(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	const ws = "wsImg"
	if err := s.PutWorkspace(&WorkspaceRecord{ID: ws, Name: "img"}); err != nil {
		t.Fatalf("PutWorkspace: %v", err)
	}

	// A backport-aware advisory against a Debian image package: zlib is vulnerable
	// below the distro's fixed version. The host carries a PATCHED zlib (a different
	// purl/source) so we can prove host vs image isolation in the match.
	dir := writeOSVFixtures(t, map[string]string{
		"zlib.json": `{
			"id": "DSA-ZLIB", "modified": "2024-01-01T00:00:00Z", "aliases": ["CVE-2023-ZLIB"],
			"affected": [{"package": {"ecosystem": "Debian:12", "name": "zlib"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.13-1"}]}]}],
			"license": "CC-BY-4.0"
		}`,
	})
	feed := osv.New(dir, FeedStore(s))
	if _, err := feed.Sync(ctx, time.Time{}); err != nil {
		t.Fatalf("feed.Sync: %v", err)
	}
	srv := &Server{store: s, inventoryFeed: feed}

	const ref = "registry/app:1.0"
	const digest = "sha256:deadbeef"
	imageSource := "image:" + ref + "@" + digest

	// n1 runs the image (vulnerable zlib inside) and has a PATCHED zlib on the host.
	n1 := inventoryReportFor(t, "n1", []sbom.Component{
		// Host zlib is already fixed -> must NOT match.
		{Purl: "pkg:deb/debian/zlib@1.2.13-1?distro=debian-12", Name: "zlib", Version: "1.2.13-1", Ecosystem: "Debian:12", Distro: "debian:12", Source: "os"},
		// Image zlib is vulnerable -> must match, tagged to the image.
		{Purl: "pkg:deb/debian/zlib@1.2.11-1?distro=debian-12", Name: "zlib", Version: "1.2.11-1", Ecosystem: "Debian:12", Distro: "debian:12", Source: imageSource},
	})
	if _, err := srv.ingestInventoryReport(ctx, ws, "n1", n1); err != nil {
		t.Fatalf("ingest n1: %v", err)
	}

	// The image SBOM was stored ONCE keyed by digest (a single image component row),
	// not copied under n1's per-node index: the per-node index holds only the host zlib.
	if list, _ := s.ListImageComponents(digest); len(list) != 1 {
		t.Fatalf("image SBOM not stored once by digest: len=%d", len(list))
	}
	if list, _ := s.ListNodeComponents(ws, "n1"); len(list) != 1 || list[0].Source != "os" {
		t.Fatalf("image component leaked into the per-node index: %+v", list)
	}

	// n2 runs the SAME image digest (vulnerable zlib), nothing else. It must NOT
	// re-store the image component set — the digest is already held — only associate.
	n2 := inventoryReportFor(t, "n2", []sbom.Component{
		{Purl: "pkg:deb/debian/zlib@1.2.11-1?distro=debian-12", Name: "zlib", Version: "1.2.11-1", Ecosystem: "Debian:12", Distro: "debian:12", Source: imageSource},
	})
	if _, err := srv.ingestInventoryReport(ctx, ws, "n2", n2); err != nil {
		t.Fatalf("ingest n2: %v", err)
	}
	// Still exactly one stored image component set for the digest (store-once holds).
	if list, _ := s.ListImageComponents(digest); len(list) != 1 {
		t.Fatalf("second node re-stored the image SBOM: len=%d", len(list))
	}
	// Both nodes are associated with the digest.
	runs, _ := s.NodesRunningDigest(ws, digest)
	if len(runs) != 2 {
		t.Fatalf("both nodes must be associated with the digest, got %v", runs)
	}

	// --- the image verdict, matched once per digest, fans to BOTH nodes that run it.
	// The vulnerable IMAGE purl is "affected" on each; n1's patched HOST purl is "fixed",
	// keyed apart by purl so the image vulnerability is attributed distinctly. ---
	rows, err := nodesAffectedByCVEFanned(s, ws, "CVE-2023-ZLIB")
	if err != nil {
		t.Fatalf("nodesAffectedByCVEFanned: %v", err)
	}
	const vulnPurl = "pkg:deb/debian/zlib@1.2.11-1?distro=debian-12"
	const patchedPurl = "pkg:deb/debian/zlib@1.2.13-1?distro=debian-12"
	byNodePurl := map[[2]string]NodeCVERecord{}
	for _, r := range rows {
		byNodePurl[[2]string{r.NodeID, r.Purl}] = r
	}
	if got := byNodePurl[[2]string{"n1", vulnPurl}].Status; got != "affected" {
		t.Errorf("n1 image zlib must be affected, got %q (rows %v)", got, rows)
	}
	if got := byNodePurl[[2]string{"n2", vulnPurl}].Status; got != "affected" {
		t.Errorf("n2 on the same image digest must be affected, got %q", got)
	}

	// The per-node fanned read shows n1 carrying BOTH the image (affected) and the host
	// (fixed) zlib as distinct purls; n2 carries only the image one.
	n1cves, _ := cvesForNodeFanned(s, ws, "n1")
	c1 := map[string]string{}
	for _, r := range n1cves {
		c1[r.Purl] = r.Status
	}
	if c1[vulnPurl] != "affected" || c1[patchedPurl] != "fixed" {
		t.Errorf("n1 fanned cves wrong: %+v", c1)
	}
	n2cves, _ := cvesForNodeFanned(s, ws, "n2")
	if len(n2cves) != 1 || n2cves[0].Purl != vulnPurl || n2cves[0].Status != "affected" {
		t.Errorf("n2 fanned cves wrong: %+v", n2cves)
	}
}

func TestInventoryImageMatchBbolt(t *testing.T) {
	inventoryImageMatchSuite(t, testStore(t))
}

func TestInventoryImageMatchSQL(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		inventoryImageMatchSuite(t, s)
	})
}

func mustEncodeForTest(t *testing.T, comps []sbom.Component) []byte {
	t.Helper()
	doc, err := sbom.Encode("nD", comps)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return doc
}

func statusOf(cves []NodeCVERecord, cve string) string {
	for _, r := range cves {
		if r.CVE == cve {
			return r.Status
		}
	}
	return ""
}

func TestInventoryDeltaBbolt(t *testing.T) {
	inventoryDeltaSuite(t, testStore(t))
}

func TestInventoryDeltaSQL(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		inventoryDeltaSuite(t, s)
	})
}
