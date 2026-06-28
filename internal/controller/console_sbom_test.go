package controller

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	openvex "github.com/openvex/go-vex/pkg/vex"

	"geneza.io/internal/affected/vulnfeed/osv"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/sbom"
)

// doBytes drives a request through a console handler and returns the status, the raw
// body and the response content-type — the SBOM and VEX exports are not JSON, so the
// JSON-decoding doJSON helper cannot read them.
func doBytes(t *testing.T, h http.Handler, method, path, bearer, body string) (int, []byte, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code, rr.Body.Bytes(), rr.Result().Header.Get("Content-Type")
}

// wireNextFeed configures the server's inventory feed with an OSV advisory for a
// known-vulnerable next.js (pkg:npm/next@14.1.0 is affected, fixed in 14.1.1), so an
// ingested or agent-reported SBOM carrying that package re-matches into a verdict.
func wireNextFeed(t *testing.T, srv *Server) {
	t.Helper()
	dir := writeOSVFixtures(t, map[string]string{
		"next.json": `{
			"id": "GHSA-next", "modified": "2024-02-01T00:00:00Z", "aliases": ["CVE-2024-NEXT"],
			"affected": [{"package": {"ecosystem": "npm", "name": "next"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "13.0.0"}, {"fixed": "14.1.1"}]}]}],
			"license": "CC-BY-4.0"
		}`,
	})
	feed := osv.New(dir, FeedStore(srv.store))
	if _, err := feed.Sync(context.Background(), time.Time{}); err != nil {
		t.Fatalf("feed sync: %v", err)
	}
	srv.inventoryFeed = feed
}

// nextSBOM builds a CycloneDX document an external scanner would upload: the
// vulnerable next.js plus a clean package, neither carrying a geneza source property
// (Extract derives the npm ecosystem from the purl), so the test exercises the
// foreign-producer path.
func nextSBOM(t *testing.T) string {
	t.Helper()
	doc, err := sbom.Encode("scanner", []sbom.Component{
		{Purl: "pkg:npm/next@14.1.0", Name: "next", Version: "14.1.0", Ecosystem: "npm"},
		{Purl: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("encode upload sbom: %v", err)
	}
	return string(doc)
}

// consoleSBOMSuite runs the full open-edge battery against a server whose store is
// already chosen, so the identical assertions cover bbolt and both SQL engines.
func consoleSBOMSuite(t *testing.T, srv *Server) {
	t.Helper()
	wireNextFeed(t, srv)
	const ws, node = defaultWorkspace, "n1"

	if err := srv.store.PutNode(ws, &NodeRecord{ID: node, Name: node}); err != nil {
		t.Fatalf("put node: %v", err)
	}
	// Seed the node with an agent-collected host component AND an image the node runs,
	// so the export must fan in image components and the ingest must not clobber the
	// agent's inventory.
	if err := srv.store.UpsertNodeComponents(ws, node, []ComponentRecord{
		{WorkspaceID: ws, NodeID: node, Purl: "pkg:deb/debian/openssl@1.1.1f", Source: "os", Ecosystem: "Debian", Name: "openssl", Version: "1.1.1f-1", Distro: "debian:11"},
	}); err != nil {
		t.Fatalf("seed agent component: %v", err)
	}
	const dig = "sha256:" + "aaaabbbbccccddddeeeeffff00001111222233334444555566667777"
	if err := srv.store.PutImageComponents(dig, []ImageComponentRecord{
		{Digest: dig, Purl: "pkg:npm/express@4.18.0", Source: "image:app@" + dig, Ecosystem: "npm", Name: "express", Version: "4.18.0"},
	}); err != nil {
		t.Fatalf("put image components: %v", err)
	}
	if err := srv.store.SetNodeImages(ws, node, []string{dig}); err != nil {
		t.Fatalf("set node images: %v", err)
	}

	api, err := srv.newConsoleAPI()
	if err != nil {
		t.Fatalf("console api: %v", err)
	}
	h := api.handler()

	member := mintConsoleSession(t, srv, ws, "alice", roleWSMember)
	viewer := mintConsoleSession(t, srv, ws, "vic", "ws-viewer")
	admin := mintConsoleSession(t, srv, ws, "adm", roleWSAdmin)

	// --- (e) auth: only an operator may ingest ---
	if code, _, _ := doBytes(t, h, "POST", "/api/v1/nodes/"+node+"/sbom", member, nextSBOM(t)); code != http.StatusForbidden {
		t.Fatalf("ws-member ingest: want 403, got %d", code)
	}
	if code, _, _ := doBytes(t, h, "POST", "/api/v1/nodes/"+node+"/sbom", viewer, nextSBOM(t)); code != http.StatusForbidden {
		t.Fatalf("ws-viewer ingest: want 403, got %d", code)
	}

	// --- (a) round-trip: an operator uploads the vulnerable SBOM, the CVE surfaces ---
	code, body, _ := doBytes(t, h, "POST", "/api/v1/nodes/"+node+"/sbom?source=trivy", admin, nextSBOM(t))
	if code != http.StatusOK {
		t.Fatalf("ingest: want 200, got %d (%s)", code, body)
	}
	var ingest map[string]any
	if err := json.Unmarshal(body, &ingest); err != nil {
		t.Fatalf("ingest response: %v", err)
	}
	if ingest["source"] != "external:trivy" {
		t.Fatalf("ingest source tag: want external:trivy, got %v", ingest["source"])
	}

	cveCode, cveResp := doJSON(t, h, "GET", "/api/v1/nodes/"+node+"/cves", member, "")
	if cveCode != http.StatusOK {
		t.Fatalf("node cves: %d %v", cveCode, cveResp)
	}
	var sawNext bool
	for _, c := range cveResp["cves"].([]any) {
		row := c.(map[string]any)
		if row["cve"] == "CVE-2024-NEXT" && row["status"] == "affected" {
			sawNext = strings.Contains(row["purl"].(string), "next")
		}
	}
	if !sawNext {
		t.Fatalf("uploaded SBOM did not produce the next.js verdict: %v", cveResp["cves"])
	}

	// --- (d) the ingest tagged external and did NOT clobber the agent's openssl ---
	comps, err := srv.store.ListNodeComponents(ws, node)
	if err != nil {
		t.Fatalf("list components: %v", err)
	}
	var haveOpenssl, haveExternalNext bool
	for _, comp := range comps {
		if comp.Purl == "pkg:deb/debian/openssl@1.1.1f" && comp.Source == "os" {
			haveOpenssl = true
		}
		if comp.Purl == "pkg:npm/next@14.1.0" && comp.Source == "external:trivy" {
			haveExternalNext = true
		}
	}
	if !haveOpenssl {
		t.Fatal("external ingest clobbered the agent-collected openssl component")
	}
	if !haveExternalNext {
		t.Fatal("external ingest did not store the next.js component under the external source")
	}

	// --- (b) export: the CycloneDX round-trips and carries host + image + external ---
	sbomCode, sbomBody, sbomCT := doBytes(t, h, "GET", "/api/v1/nodes/"+node+"/sbom", member, "")
	if sbomCode != http.StatusOK {
		t.Fatalf("sbom export: %d", sbomCode)
	}
	if sbomCT != sbom.MediaType {
		t.Fatalf("sbom content-type: want %q, got %q", sbom.MediaType, sbomCT)
	}
	exported, err := sbom.Extract(sbomBody)
	if err != nil {
		t.Fatalf("exported sbom does not round-trip: %v", err)
	}
	purls := map[string]bool{}
	for _, comp := range exported {
		purls[comp.Purl] = true
	}
	for _, want := range []string{
		"pkg:deb/debian/openssl@1.1.1f", // host (agent)
		"pkg:npm/express@4.18.0",        // image fan-in
		"pkg:npm/next@14.1.0",           // external
	} {
		if !purls[want] {
			t.Fatalf("exported sbom missing %q; got %v", want, purls)
		}
	}

	// --- (c) VEX export: a valid OpenVEX doc with the next.js statement affected ---
	vexCode, vexBody, vexCT := doBytes(t, h, "GET", "/api/v1/nodes/"+node+"/findings.vex", member, "")
	if vexCode != http.StatusOK {
		t.Fatalf("vex export: %d", vexCode)
	}
	if vexCT != "application/vnd.openvex+json" {
		t.Fatalf("vex content-type: %q", vexCT)
	}
	var doc openvex.VEX
	if err := json.Unmarshal(vexBody, &doc); err != nil {
		t.Fatalf("vex export is not valid openvex json: %v", err)
	}
	if doc.Context == "" || len(doc.Statements) == 0 {
		t.Fatalf("vex doc empty: %+v", doc)
	}
	var nextStmt *openvex.Statement
	for i := range doc.Statements {
		if doc.Statements[i].Vulnerability.Name == "CVE-2024-NEXT" {
			nextStmt = &doc.Statements[i]
		}
	}
	if nextStmt == nil {
		t.Fatalf("vex doc missing the next.js statement: %+v", doc.Statements)
	}
	if nextStmt.Status != openvex.StatusAffected {
		t.Fatalf("next.js vex status: want affected, got %q", nextStmt.Status)
	}
	if err := nextStmt.Validate(); err != nil {
		t.Fatalf("next.js vex statement invalid: %v", err)
	}

	// A ws-viewer CAN export (reads are vuln-view-gated, which a viewer fails) — confirm
	// the viewer is denied the export too, matching the other vuln reads.
	if code, _, _ := doBytes(t, h, "GET", "/api/v1/nodes/"+node+"/sbom", viewer, ""); code != http.StatusForbidden {
		t.Fatalf("viewer sbom export: want 403, got %d", code)
	}

	// --- (e) workspace isolation: a foreign-workspace operator never reaches the node ---
	foreign := mintConsoleSession(t, srv, "wsOther", "mallory", roleWSAdmin)
	if code, _, _ := doBytes(t, h, "POST", "/api/v1/nodes/"+node+"/sbom", foreign, nextSBOM(t)); code != http.StatusNotFound {
		t.Fatalf("cross-ws ingest: want 404, got %d", code)
	}
	if code, _, _ := doBytes(t, h, "GET", "/api/v1/nodes/"+node+"/sbom", foreign, ""); code != http.StatusNotFound {
		t.Fatalf("cross-ws export: want 404, got %d", code)
	}

	// --- (d cont.) re-POST replaces the prior external set (idempotent) ---
	replacement, err := sbom.Encode("scanner", []sbom.Component{
		{Purl: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
	})
	if err != nil {
		t.Fatalf("encode replacement: %v", err)
	}
	if code, _, _ := doBytes(t, h, "POST", "/api/v1/nodes/"+node+"/sbom", admin, string(replacement)); code != http.StatusOK {
		t.Fatalf("re-ingest: %d", code)
	}
	comps2, err := srv.store.ListNodeComponents(ws, node)
	if err != nil {
		t.Fatalf("list components after re-ingest: %v", err)
	}
	for _, comp := range comps2 {
		if comp.Purl == "pkg:npm/next@14.1.0" {
			t.Fatal("re-ingest did not drop the prior external next.js component")
		}
	}
	// The agent's openssl still survives the replace.
	var stillOpenssl bool
	for _, comp := range comps2 {
		if comp.Purl == "pkg:deb/debian/openssl@1.1.1f" {
			stillOpenssl = true
		}
	}
	if !stillOpenssl {
		t.Fatal("re-ingest clobbered the agent-collected openssl component")
	}
}

func TestConsoleSBOMEdgesBbolt(t *testing.T) {
	consoleSBOMSuite(t, newReplayServer(t))
}

func TestConsoleSBOMEdgesSQL(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, sqls *sqlStore) {
		consoleSBOMSuite(t, newReplayServerWithStore(t, sqls))
	})
}

// TestExternalSBOMPreservesAgentDeltaStream proves the headline cross-path
// invariant: an external SBOM upload sharing the node's component index does NOT
// desync the agent's gRPC delta stream. The agent reports a full SBOM, an operator
// uploads an external scan, and a subsequent agent delta against the prior base still
// reconstructs the agent's exact set (the external rows are invisible to the agent
// path), so it commits rather than failing into a full resend — and the external rows
// survive the agent's commit.
func TestExternalSBOMPreservesAgentDeltaStream(t *testing.T) {
	run := func(t *testing.T, srv *Server) {
		const ws, node = defaultWorkspace, "n1"
		if err := srv.store.PutNode(ws, &NodeRecord{ID: node, Name: node}); err != nil {
			t.Fatalf("put node: %v", err)
		}

		// The agent reports a full SBOM of its own collected set.
		agentBase := []sbom.Component{
			{Purl: "pkg:npm/left-pad@1.0.0", Name: "left-pad", Version: "1.0.0", Ecosystem: "npm", Source: "lang"},
		}
		baseDoc, err := sbom.Encode(node, agentBase)
		if err != nil {
			t.Fatal(err)
		}
		baseSum := sbom.Hash(baseDoc)
		baseBlob, err := sbom.Compress(baseDoc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := srv.ingestInventoryReport(context.Background(), ws, node, &genezav1.InventoryReport{
			Full: true, Sbom: baseBlob, ContentHash: baseSum[:],
		}); err != nil {
			t.Fatalf("agent full report: %v", err)
		}

		// An operator uploads an external scan into the SAME node's component index.
		if _, err := srv.ingestExternalSBOM(context.Background(), ws, node, "external", []sbom.Component{
			{Purl: "pkg:npm/next@14.1.0", Name: "next", Version: "14.1.0", Ecosystem: "npm"},
		}); err != nil {
			t.Fatalf("external ingest: %v", err)
		}

		// The agent now sends a DELTA against its prior base (adds a package). The base it
		// applies on top of is its OWN slice, so the external row must not perturb the
		// re-hash — the delta must commit, NOT fail into errInventoryNeedFull.
		agentNext := append(append([]sbom.Component{}, agentBase...),
			sbom.Component{Purl: "pkg:npm/ansi-regex@5.0.0", Name: "ansi-regex", Version: "5.0.0", Ecosystem: "npm", Source: "lang"})
		nextDoc, err := sbom.Encode(node, agentNext)
		if err != nil {
			t.Fatal(err)
		}
		nextSum := sbom.Hash(nextDoc)
		added, removed := sbom.Diff(agentBase, agentNext)
		if _, err := srv.ingestInventoryReport(context.Background(), ws, node, &genezav1.InventoryReport{
			BaseHash: baseSum[:], ContentHash: nextSum[:],
			Added: componentsToProto(added), Removed: componentsToProto(removed),
		}); err != nil {
			t.Fatalf("agent delta after external upload must commit, got: %v", err)
		}

		// Both producers' slices survive: the agent's two lang packages AND the external
		// next.js are all present.
		comps, err := srv.store.ListNodeComponents(ws, node)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, c := range comps {
			got[c.Purl] = c.Source
		}
		if got["pkg:npm/left-pad@1.0.0"] != "lang" || got["pkg:npm/ansi-regex@5.0.0"] != "lang" {
			t.Fatalf("agent delta lost an agent component: %v", got)
		}
		if got["pkg:npm/next@14.1.0"] != "external" {
			t.Fatalf("agent delta clobbered the external component: %v", got)
		}
	}
	t.Run("bbolt", func(t *testing.T) { run(t, newReplayServer(t)) })
	t.Run("sql", func(t *testing.T) {
		forEachSQLEngine(t, func(t *testing.T, sqls *sqlStore) {
			run(t, newReplayServerWithStore(t, sqls))
		})
	})
}

// componentsToProto lifts the flat SBOM view into the delta wire components an
// InventoryReport carries, the inverse of componentsFromProto, so a test can drive
// the gRPC delta path with a computed diff.
func componentsToProto(in []sbom.Component) []*genezav1.InventoryComponent {
	out := make([]*genezav1.InventoryComponent, 0, len(in))
	for _, c := range in {
		out = append(out, &genezav1.InventoryComponent{
			Purl: c.Purl, Name: c.Name, Version: c.Version,
			Ecosystem: c.Ecosystem, Distro: c.Distro, Source: c.Source,
		})
	}
	return out
}
