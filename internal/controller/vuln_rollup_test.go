package controller

import (
	"reflect"
	"sort"
	"testing"
)

// workspaceRollupSuite proves the fleet-wide rollup unions host and image verdicts
// and counts DISTINCT nodes per CVE: two nodes sharing an affected image count as
// two for that CVE, while a node carrying the same CVE from BOTH its host and an
// image counts once. It runs identically on bbolt and both SQL engines.
func workspaceRollupSuite(t *testing.T, s Store) {
	t.Helper()
	const ws = "wsA"
	const dig = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// n1 carries CVE-HOST on its host, and CVE-SHARED on its host too.
	hostRows := []NodeCVERecord{
		{WorkspaceID: ws, NodeID: "n1", CVE: "CVE-HOST", Purl: "pkg:deb/debian/openssl@1.0", Status: "affected", Severity: "HIGH", FixedVersion: "1.1"},
		{WorkspaceID: ws, NodeID: "n1", CVE: "CVE-SHARED", Purl: "pkg:npm/next@14.1.0", Status: "affected", Severity: "CRITICAL", FixedVersion: "14.2.25"},
	}
	for i := range hostRows {
		if err := s.UpsertNodeCVE(&hostRows[i]); err != nil {
			t.Fatalf("upsert host cve: %v", err)
		}
	}

	// One image digest carries CVE-IMG and CVE-SHARED; n1 and n2 both run it.
	imgRows := []ImageCVERecord{
		{Digest: dig, CVE: "CVE-IMG", Purl: "pkg:deb/debian/curl@7.0", Status: "affected", Severity: "MEDIUM", FixedVersion: "7.1"},
		{Digest: dig, CVE: "CVE-SHARED", Purl: "pkg:npm/next@14.1.0", Status: "affected", Severity: "CRITICAL", FixedVersion: "14.2.25"},
	}
	for i := range imgRows {
		if err := s.PutImageCVE(&imgRows[i]); err != nil {
			t.Fatalf("put image cve: %v", err)
		}
	}
	if err := s.SetNodeImages(ws, "n1", []string{dig}); err != nil {
		t.Fatalf("set node images n1: %v", err)
	}
	if err := s.SetNodeImages(ws, "n2", []string{dig}); err != nil {
		t.Fatalf("set node images n2: %v", err)
	}

	rollups, err := s.WorkspaceCVERollups(ws)
	if err != nil {
		t.Fatalf("WorkspaceCVERollups: %v", err)
	}
	got := map[string]WorkspaceCVERollup{}
	for _, r := range rollups {
		got[r.CVE] = r
	}

	// CVE-HOST: only n1's host.
	if r := got["CVE-HOST"]; r.NodeCount != 1 || !reflect.DeepEqual(r.Nodes, []string{"n1"}) {
		t.Fatalf("CVE-HOST: want 1 node [n1], got count=%d nodes=%v", r.NodeCount, r.Nodes)
	}
	// CVE-IMG: the image fans to both n1 and n2 -> two distinct nodes.
	if r := got["CVE-IMG"]; r.NodeCount != 2 || !sameNodes(r.Nodes, []string{"n1", "n2"}) {
		t.Fatalf("CVE-IMG: want 2 nodes [n1 n2], got count=%d nodes=%v", r.NodeCount, r.Nodes)
	}
	// CVE-SHARED: n1 carries it from BOTH host and image (counts once), plus n2 from
	// the image -> two distinct nodes, not three rows.
	if r := got["CVE-SHARED"]; r.NodeCount != 2 || !sameNodes(r.Nodes, []string{"n1", "n2"}) {
		t.Fatalf("CVE-SHARED: want 2 distinct nodes [n1 n2], got count=%d nodes=%v", r.NodeCount, r.Nodes)
	}
	// The CRITICAL CVE sorts ahead of the HIGH and MEDIUM ones.
	if len(rollups) != 3 || rollups[0].CVE != "CVE-SHARED" {
		t.Fatalf("rollup sort: want CVE-SHARED first, got %+v", rollups)
	}
	// The fixing version rides the affected rollup row.
	if got["CVE-SHARED"].FixedVersion != "14.2.25" {
		t.Fatalf("CVE-SHARED fixed version: want 14.2.25, got %q", got["CVE-SHARED"].FixedVersion)
	}

	// Tenant isolation: a different workspace running the same image sees only its
	// own associated nodes, never wsA's.
	if err := s.SetNodeImages("wsB", "nB", []string{dig}); err != nil {
		t.Fatalf("set node images wsB: %v", err)
	}
	bRollups, err := s.WorkspaceCVERollups("wsB")
	if err != nil {
		t.Fatalf("WorkspaceCVERollups wsB: %v", err)
	}
	for _, r := range bRollups {
		for _, n := range r.Nodes {
			if n == "n1" || n == "n2" {
				t.Fatalf("cross-tenant leak: wsB rollup names wsA node %q", n)
			}
		}
	}
	// wsB sees the image-borne CVEs on its own node only.
	bByCVE := map[string]WorkspaceCVERollup{}
	for _, r := range bRollups {
		bByCVE[r.CVE] = r
	}
	if r := bByCVE["CVE-IMG"]; r.NodeCount != 1 || !reflect.DeepEqual(r.Nodes, []string{"nB"}) {
		t.Fatalf("wsB CVE-IMG: want [nB], got count=%d nodes=%v", r.NodeCount, r.Nodes)
	}
	if _, ok := bByCVE["CVE-HOST"]; ok {
		t.Fatalf("wsB wrongly sees wsA host-only CVE-HOST")
	}
}

func sameNodes(got, want []string) bool {
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	return reflect.DeepEqual(g, w)
}

func TestWorkspaceRollupBbolt(t *testing.T) {
	workspaceRollupSuite(t, testStore(t))
}

func TestWorkspaceRollupSQL(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		workspaceRollupSuite(t, s)
	})
}

// TestDedupNodeCVERows proves a host package found by two extractors (one classified,
// one source=UNKNOWN) collapses to a single row keyed on (cve, base-purl), keeping
// the classified PURL.
func TestDedupNodeCVERows(t *testing.T) {
	rows := []NodeCVERecord{
		{NodeID: "n1", CVE: "CVE-1", Purl: "pkg:npm/next@14.1.0?source=UNKNOWN", Status: "affected"},
		{NodeID: "n1", CVE: "CVE-1", Purl: "pkg:npm/next@14.1.0", Status: "affected"},
		// A genuinely different version stays distinct.
		{NodeID: "n1", CVE: "CVE-1", Purl: "pkg:npm/next@15.0.0", Status: "affected"},
	}
	got := dedupCVEsForNode(rows)
	if len(got) != 2 {
		t.Fatalf("dedup per node: want 2 rows, got %d: %+v", len(got), got)
	}
	// The kept 14.1.0 row carries the classified (qualifier-free) PURL, even though
	// the UNKNOWN one was seen first.
	if got[0].Purl != "pkg:npm/next@14.1.0" {
		t.Fatalf("dedup preference: want classified purl kept, got %q", got[0].Purl)
	}

	// The per-cve view collapses on (node, base-purl): the same node+package found by
	// two extractors is one row, while a second node stays distinct.
	byCVE := []NodeCVERecord{
		{NodeID: "n1", CVE: "CVE-1", Purl: "pkg:npm/next@14.1.0?source=UNKNOWN"},
		{NodeID: "n1", CVE: "CVE-1", Purl: "pkg:npm/next@14.1.0"},
		{NodeID: "n2", CVE: "CVE-1", Purl: "pkg:npm/next@14.1.0"},
	}
	gotByCVE := dedupNodesForCVE(byCVE)
	if len(gotByCVE) != 2 {
		t.Fatalf("dedup per cve: want 2 rows (n1, n2), got %d: %+v", len(gotByCVE), gotByCVE)
	}
}
