package controller

import (
	"encoding/json"
	"errors"
	"testing"
)

// inventoryStoreSuite exercises the SBOM / component / cve / advisory tables across
// any Store impl, so bbolt and both SQL engines run the identical assertions.
func inventoryStoreSuite(t *testing.T, s Store) {
	t.Helper()
	const wsA, wsB = "wsA", "wsB"

	// --- node_sboms round-trip + miss ---
	if _, err := s.GetNodeSBOM(wsA, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetNodeSBOM miss: want ErrNotFound, got %v", err)
	}
	sbom := &NodeSBOMRecord{
		Format:        "cyclonedx-json",
		ContentHash:   "abc123",
		CollectedUnix: 1000,
		SBOM:          []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x01, 0x02}, // zstd magic + bytes
	}
	if err := s.PutNodeSBOM(wsA, "n1", sbom); err != nil {
		t.Fatalf("PutNodeSBOM: %v", err)
	}
	got, err := s.GetNodeSBOM(wsA, "n1")
	if err != nil {
		t.Fatalf("GetNodeSBOM: %v", err)
	}
	if got.WorkspaceID != wsA || got.NodeID != "n1" {
		t.Errorf("sbom key not stamped: %+v", got)
	}
	if got.Format != sbom.Format || got.ContentHash != sbom.ContentHash || got.CollectedUnix != sbom.CollectedUnix {
		t.Errorf("sbom fields round-trip wrong: %+v", got)
	}
	if string(got.SBOM) != string(sbom.SBOM) {
		t.Errorf("sbom blob round-trip wrong: %x", got.SBOM)
	}
	// Overwrite-in-place: a second put updates the same key.
	if err := s.PutNodeSBOM(wsA, "n1", &NodeSBOMRecord{ContentHash: "def456", SBOM: []byte{0xff}}); err != nil {
		t.Fatalf("PutNodeSBOM overwrite: %v", err)
	}
	if got, _ := s.GetNodeSBOM(wsA, "n1"); got.ContentHash != "def456" || string(got.SBOM) != "\xff" {
		t.Errorf("sbom overwrite wrong: %+v", got)
	}

	// --- node_components: replace-set, by-node and by-package fast paths ---
	comps := []ComponentRecord{
		{Purl: "pkg:deb/debian/openssl@1.1.1f", Source: "os", Ecosystem: "Debian", Name: "openssl", Version: "1.1.1f-1", Distro: "debian:11"},
		{Purl: "pkg:deb/debian/curl@7.74.0", Source: "os", Ecosystem: "Debian", Name: "curl", Version: "7.74.0-1", Distro: "debian:11"},
		{Purl: "pkg:deb/debian/openssl@1.1.1f", Source: "image:abc", Ecosystem: "Debian", Name: "openssl", Version: "1.1.1f-1", Distro: "debian:11"},
	}
	if err := s.UpsertNodeComponents(wsA, "n1", comps); err != nil {
		t.Fatalf("UpsertNodeComponents: %v", err)
	}
	// Same purl, two sources -> two distinct rows (source is part of the identity).
	if list, err := s.ListNodeComponents(wsA, "n1"); err != nil || len(list) != 3 {
		t.Fatalf("ListNodeComponents: err=%v len=%d", err, len(list))
	}
	// who-has-package fast path: both openssl rows (two sources), not curl.
	byPkg, err := s.ListComponentsByPackage(wsA, "Debian", "openssl")
	if err != nil {
		t.Fatalf("ListComponentsByPackage: %v", err)
	}
	if len(byPkg) != 2 {
		t.Fatalf("ListComponentsByPackage openssl: want 2 got %d", len(byPkg))
	}
	for _, c := range byPkg {
		if c.Name != "openssl" || c.NodeID != "n1" {
			t.Errorf("by-package wrong row: %+v", c)
		}
	}
	// Replace-set: re-index with a smaller set drops the stale rows.
	if err := s.UpsertNodeComponents(wsA, "n1", comps[:1]); err != nil {
		t.Fatalf("UpsertNodeComponents replace: %v", err)
	}
	if list, _ := s.ListNodeComponents(wsA, "n1"); len(list) != 1 {
		t.Fatalf("replace-set did not drop stale rows: len=%d", len(list))
	}
	if curl, _ := s.ListComponentsByPackage(wsA, "Debian", "curl"); len(curl) != 0 {
		t.Fatalf("stale curl still indexed after replace: len=%d", len(curl))
	}
	// Restore the full set for the cascade test below.
	if err := s.UpsertNodeComponents(wsA, "n1", comps); err != nil {
		t.Fatalf("UpsertNodeComponents restore: %v", err)
	}

	// --- node_cve: upsert, by-cve and by-node fast paths ---
	cveRows := []NodeCVERecord{
		{WorkspaceID: wsA, NodeID: "n1", CVE: "CVE-2021-1", Purl: "pkg:deb/debian/openssl@1.1.1f", Status: "affected", Severity: "high", KEV: true, EPSS: 0.42, FixedVersion: "1.1.1f-1+deb11u1", MatchedUnix: 5},
		{WorkspaceID: wsA, NodeID: "n1", CVE: "CVE-2021-2", Purl: "pkg:deb/debian/curl@7.74.0", Status: "fixed", Severity: "medium", MatchedUnix: 6},
	}
	for i := range cveRows {
		if err := s.UpsertNodeCVE(&cveRows[i]); err != nil {
			t.Fatalf("UpsertNodeCVE: %v", err)
		}
	}
	// Upsert in place: re-write the first row's status.
	cveRows[0].Status = "not_affected"
	cveRows[0].VEXJustification = "vulnerable_code_not_present"
	if err := s.UpsertNodeCVE(&cveRows[0]); err != nil {
		t.Fatalf("UpsertNodeCVE update: %v", err)
	}
	byCVE, err := s.NodesAffectedByCVE(wsA, "CVE-2021-1")
	if err != nil || len(byCVE) != 1 {
		t.Fatalf("NodesAffectedByCVE: err=%v len=%d", err, len(byCVE))
	}
	if byCVE[0].Status != "not_affected" || byCVE[0].VEXJustification != "vulnerable_code_not_present" {
		t.Errorf("cve upsert did not update in place: %+v", byCVE[0])
	}
	if !byCVE[0].KEV || byCVE[0].EPSS != 0.42 || byCVE[0].FixedVersion != "1.1.1f-1+deb11u1" {
		t.Errorf("cve prioritization fields round-trip wrong: %+v", byCVE[0])
	}
	if forNode, err := s.CVEsForNode(wsA, "n1"); err != nil || len(forNode) != 2 {
		t.Fatalf("CVEsForNode: err=%v len=%d", err, len(forNode))
	}

	// --- advisories: batch upsert + by-package resolve (global) ---
	advs := []AdvisoryRecord{
		{ID: "OSV-1", Source: "osv", Ecosystem: "Debian", PackageName: "openssl", Doc: json.RawMessage(`{"id":"OSV-1","license":"CC-BY-4.0"}`), ModifiedUnix: 10},
		{ID: "OSV-2", Source: "osv", Ecosystem: "Debian", PackageName: "curl", ModifiedUnix: 11},
		{ID: "OSV-3", Source: "nvd", Ecosystem: "PyPI", PackageName: "requests", ModifiedUnix: 12},
	}
	if err := s.PutAdvisories(advs); err != nil {
		t.Fatalf("PutAdvisories: %v", err)
	}
	osslAdv, err := s.AdvisoriesForPackage("Debian", "openssl")
	if err != nil || len(osslAdv) != 1 {
		t.Fatalf("AdvisoriesForPackage: err=%v len=%d", err, len(osslAdv))
	}
	if osslAdv[0].ID != "OSV-1" || osslAdv[0].Source != "osv" {
		t.Errorf("advisory fields round-trip wrong: %+v", osslAdv[0])
	}
	var doc map[string]any
	if err := json.Unmarshal(osslAdv[0].Doc, &doc); err != nil || doc["license"] != "CC-BY-4.0" {
		t.Errorf("advisory doc round-trip wrong: %v doc=%v", err, doc)
	}
	// Batch upsert is idempotent and updates in place.
	advs[0].PackageName = "openssl"
	advs[0].ModifiedUnix = 99
	if err := s.PutAdvisories([]AdvisoryRecord{advs[0]}); err != nil {
		t.Fatalf("PutAdvisories re-upsert: %v", err)
	}
	if again, _ := s.AdvisoriesForPackage("Debian", "openssl"); len(again) != 1 || again[0].ModifiedUnix != 99 {
		t.Fatalf("advisory upsert not idempotent: %+v", again)
	}

	// --- foreign-workspace isolation: wsB sees none of wsA's per-node rows ---
	if err := s.PutNodeSBOM(wsB, "nB", &NodeSBOMRecord{ContentHash: "b"}); err != nil {
		t.Fatalf("PutNodeSBOM wsB: %v", err)
	}
	if err := s.UpsertNodeComponents(wsB, "nB", []ComponentRecord{
		{Purl: "pkg:deb/debian/openssl@1.1.1f", Source: "os", Ecosystem: "Debian", Name: "openssl", Version: "x"},
	}); err != nil {
		t.Fatalf("UpsertNodeComponents wsB: %v", err)
	}
	if err := s.UpsertNodeCVE(&NodeCVERecord{WorkspaceID: wsB, NodeID: "nB", CVE: "CVE-2021-1", Purl: "p", Status: "affected"}); err != nil {
		t.Fatalf("UpsertNodeCVE wsB: %v", err)
	}
	if leak, _ := s.ListComponentsByPackage(wsA, "Debian", "openssl"); len(leak) != 2 {
		t.Fatalf("wsB component leaked into wsA: len=%d", len(leak))
	}
	if leak, _ := s.NodesAffectedByCVE(wsA, "CVE-2021-1"); len(leak) != 1 || leak[0].NodeID != "n1" {
		t.Fatalf("wsB cve row leaked into wsA: %+v", leak)
	}
	if _, err := s.GetNodeSBOM(wsA, "nB"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wsB sbom visible under wsA: %v", err)
	}

	// --- DeleteNode cascade: n1's sbom/components/cve rows all vanish ---
	// DeleteNode requires the node row itself to exist, so create it; the cascade is
	// what drops the inventory rows written above.
	if err := s.PutNode(wsA, &NodeRecord{ID: "n1", Name: "n1"}); err != nil {
		t.Fatalf("PutNode for cascade: %v", err)
	}
	if err := s.DeleteNode(wsA, "n1"); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	if _, err := s.GetNodeSBOM(wsA, "n1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteNode did not cascade sbom: %v", err)
	}
	if list, _ := s.ListNodeComponents(wsA, "n1"); len(list) != 0 {
		t.Errorf("DeleteNode did not cascade components: len=%d", len(list))
	}
	if list, _ := s.CVEsForNode(wsA, "n1"); len(list) != 0 {
		t.Errorf("DeleteNode did not cascade cve rows: len=%d", len(list))
	}
	// The component index no longer reports n1's openssl.
	if leak, _ := s.ListComponentsByPackage(wsA, "Debian", "openssl"); len(leak) != 0 {
		t.Errorf("DeleteNode left openssl in the package index: len=%d", len(leak))
	}
	// wsB's rows are untouched by wsA's delete.
	if list, _ := s.ListNodeComponents(wsB, "nB"); len(list) != 1 {
		t.Errorf("wsB component collateral-deleted: len=%d", len(list))
	}
}

func TestInventoryStoreBbolt(t *testing.T) {
	inventoryStoreSuite(t, testStore(t))
}

func TestInventoryStoreSQL(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		inventoryStoreSuite(t, s)
	})
}

// enrichStoreSuite proves EnrichNodeCVEs overlays KEV/EPSS onto existing verdict
// rows by CVE, fleet-wide, leaving non-matching rows untouched and being
// idempotent on a re-apply. It runs identically on bbolt and both SQL engines.
func enrichStoreSuite(t *testing.T, s Store) {
	t.Helper()
	const wsA, wsB = "wsA", "wsB"

	// Two workspaces, one CVE shared across both plus a CVE that gets no signal.
	rows := []NodeCVERecord{
		{WorkspaceID: wsA, NodeID: "n1", CVE: "CVE-2021-44228", Purl: "pkg:maven/log4j@2.14", Status: "affected"},
		{WorkspaceID: wsA, NodeID: "n2", CVE: "CVE-2021-44228", Purl: "pkg:maven/log4j@2.14", Status: "affected"},
		{WorkspaceID: wsB, NodeID: "nB", CVE: "CVE-2021-44228", Purl: "pkg:maven/log4j@2.14", Status: "affected"},
		{WorkspaceID: wsA, NodeID: "n1", CVE: "CVE-2020-0001", Purl: "pkg:deb/debian/x@1", Status: "affected"},
	}
	for i := range rows {
		if err := s.UpsertNodeCVE(&rows[i]); err != nil {
			t.Fatalf("UpsertNodeCVE: %v", err)
		}
	}

	scores := map[string]CVEEnrichment{
		"CVE-2021-44228": {KEV: true, EPSS: 0.975},
		// A CVE no row carries: must update nothing, not error.
		"CVE-2099-9999": {KEV: true, EPSS: 0.5},
	}
	n, err := s.EnrichNodeCVEs(scores)
	if err != nil {
		t.Fatalf("EnrichNodeCVEs: %v", err)
	}
	if n != 3 {
		t.Fatalf("want 3 rows enriched (the three CVE-2021-44228 rows), got %d", n)
	}

	// The matching rows in both workspaces carry KEV + EPSS now.
	for _, ws := range []string{wsA, wsB} {
		got, err := s.NodesAffectedByCVE(ws, "CVE-2021-44228")
		if err != nil {
			t.Fatalf("NodesAffectedByCVE %s: %v", ws, err)
		}
		if len(got) == 0 {
			t.Fatalf("%s: no rows for CVE-2021-44228", ws)
		}
		for _, r := range got {
			if !r.KEV || r.EPSS != 0.975 {
				t.Errorf("%s/%s: want kev=true epss=0.975, got kev=%v epss=%v", ws, r.NodeID, r.KEV, r.EPSS)
			}
		}
	}

	// The CVE with no signal stays unmarked.
	other, err := s.NodesAffectedByCVE(wsA, "CVE-2020-0001")
	if err != nil {
		t.Fatalf("NodesAffectedByCVE other: %v", err)
	}
	if len(other) != 1 || other[0].KEV || other[0].EPSS != 0 {
		t.Errorf("non-KEV row wrongly enriched: %+v", other)
	}

	// Idempotent: re-applying the same scores changes no rows.
	n2, err := s.EnrichNodeCVEs(scores)
	if err != nil {
		t.Fatalf("EnrichNodeCVEs re-apply: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("re-apply must update 0 rows, got %d", n2)
	}

	// An empty map is a no-op (config-gated: no sources -> no change).
	if n3, err := s.EnrichNodeCVEs(nil); err != nil || n3 != 0 {
		t.Fatalf("empty enrich: want (0,nil), got (%d,%v)", n3, err)
	}

	// A changed score updates again.
	n4, err := s.EnrichNodeCVEs(map[string]CVEEnrichment{"CVE-2021-44228": {KEV: true, EPSS: 0.5}})
	if err != nil {
		t.Fatalf("EnrichNodeCVEs change: %v", err)
	}
	if n4 != 3 {
		t.Fatalf("changed score must update 3 rows, got %d", n4)
	}
}

func TestEnrichStoreBbolt(t *testing.T) {
	enrichStoreSuite(t, testStore(t))
}

func TestEnrichStoreSQL(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		enrichStoreSuite(t, s)
	})
}
