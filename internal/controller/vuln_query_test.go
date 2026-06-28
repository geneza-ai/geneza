package controller

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// seedVulnFixture writes a node plus two node_cve rows (one affected, one fixed) and
// two inventory components for it, so the query RPCs have deterministic data.
func seedVulnFixture(t *testing.T, srv *Server, ws, node string) {
	t.Helper()
	if err := srv.store.PutNode(ws, &NodeRecord{ID: node, Name: node}); err != nil {
		t.Fatalf("put node: %v", err)
	}
	rows := []NodeCVERecord{
		{WorkspaceID: ws, NodeID: node, CVE: "CVE-2021-1", Purl: "pkg:deb/debian/openssl@1.1.1f", Status: "affected", Severity: "high", KEV: true, EPSS: 0.42, FixedVersion: "1.1.1f-1+deb11u1", MatchedUnix: 5},
		{WorkspaceID: ws, NodeID: node, CVE: "CVE-2021-2", Purl: "pkg:deb/debian/curl@7.74.0", Status: "fixed", Severity: "medium", MatchedUnix: 6},
	}
	for i := range rows {
		if err := srv.store.UpsertNodeCVE(&rows[i]); err != nil {
			t.Fatalf("upsert node cve: %v", err)
		}
	}
	if err := srv.store.UpsertNodeComponents(ws, node, []ComponentRecord{
		{Purl: "pkg:deb/debian/openssl@1.1.1f", Source: "os", Ecosystem: "Debian", Name: "openssl", Version: "1.1.1f-1", Distro: "debian:11"},
		{Purl: "pkg:deb/debian/curl@7.74.0", Source: "os", Ecosystem: "Debian", Name: "curl", Version: "7.74.0-1", Distro: "debian:11"},
	}); err != nil {
		t.Fatalf("upsert components: %v", err)
	}
}

// vulnQuerySuite runs the full set of RPC assertions against a server whose store is
// already chosen, so the identical checks cover bbolt and both SQL engines.
func vulnQuerySuite(t *testing.T, srv *Server) {
	t.Helper()
	const ws, node = defaultWorkspace, "n1"
	seedVulnFixture(t, srv, ws, node)
	memberCtx := userCtx(ws, "alice", roleWSMember)

	// ListNodeCVEs: both rows for the node, resolvable by id.
	all, err := u(srv).ListNodeCVEs(memberCtx, &genezav1.ListNodeCVEsRequest{NodeId: node})
	if err != nil {
		t.Fatalf("ListNodeCVEs: %v", err)
	}
	if all.GetTotal() != 2 || len(all.GetCves()) != 2 {
		t.Fatalf("ListNodeCVEs: want 2 rows, got total=%d len=%d", all.GetTotal(), len(all.GetCves()))
	}
	// The prioritization fields ride the row.
	var seenKEV bool
	for _, c := range all.GetCves() {
		if c.GetCve() == "CVE-2021-1" {
			seenKEV = c.GetKev() && c.GetEpss() == 0.42 && c.GetFixedVersion() == "1.1.1f-1+deb11u1" && c.GetSeverity() == "high"
		}
	}
	if !seenKEV {
		t.Fatalf("ListNodeCVEs did not carry the prioritization fields: %+v", all.GetCves())
	}

	// affected_only filters to the single still-affected row.
	aff, err := u(srv).ListNodeCVEs(memberCtx, &genezav1.ListNodeCVEsRequest{NodeId: node, AffectedOnly: true})
	if err != nil {
		t.Fatalf("ListNodeCVEs affected_only: %v", err)
	}
	if aff.GetTotal() != 1 || aff.GetCves()[0].GetCve() != "CVE-2021-1" {
		t.Fatalf("affected_only: want the one affected row, got total=%d %+v", aff.GetTotal(), aff.GetCves())
	}

	// ListNodesAffectedByCVE: the inverse view names the node.
	byCVE, err := u(srv).ListNodesAffectedByCVE(memberCtx, &genezav1.ListNodesAffectedByCVERequest{Cve: "CVE-2021-1"})
	if err != nil {
		t.Fatalf("ListNodesAffectedByCVE: %v", err)
	}
	if byCVE.GetTotal() != 1 || byCVE.GetNodes()[0].GetNodeId() != node {
		t.Fatalf("ListNodesAffectedByCVE: want node %q, got %+v", node, byCVE.GetNodes())
	}
	// A CVE no node carries returns empty (not an error).
	none, err := u(srv).ListNodesAffectedByCVE(memberCtx, &genezav1.ListNodesAffectedByCVERequest{Cve: "CVE-9999-0"})
	if err != nil || none.GetTotal() != 0 {
		t.Fatalf("ListNodesAffectedByCVE unknown cve: want empty, got total=%d err=%v", none.GetTotal(), err)
	}

	// ListNodeComponents: the node's inventory.
	comps, err := u(srv).ListNodeComponents(memberCtx, &genezav1.ListNodeComponentsRequest{NodeId: node})
	if err != nil {
		t.Fatalf("ListNodeComponents: %v", err)
	}
	if comps.GetTotal() != 2 {
		t.Fatalf("ListNodeComponents: want 2, got %d", comps.GetTotal())
	}

	// A missing node is NotFound, not a leak.
	if _, err := u(srv).ListNodeCVEs(memberCtx, &genezav1.ListNodeCVEsRequest{NodeId: "ghost"}); status.Code(err) != codes.NotFound {
		t.Fatalf("missing node: want NotFound, got %v", err)
	}
}

func TestVulnQueryBbolt(t *testing.T) {
	vulnQuerySuite(t, newReplayServer(t))
}

func TestVulnQuerySQL(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, sqls *sqlStore) {
		vulnQuerySuite(t, newReplayServerWithStore(t, sqls))
	})
}

// TestVulnQueryAuthz proves the capability gate: a ws-viewer (below ws-member) is
// denied, and a ws-member is allowed.
func TestVulnQueryAuthz(t *testing.T) {
	run := func(t *testing.T, srv *Server) {
		const ws, node = defaultWorkspace, "n1"
		seedVulnFixture(t, srv, ws, node)

		// Denied: a read-only ws-viewer cannot see the exploitable surface.
		viewer := userCtx(ws, "vic", "ws-viewer")
		if _, err := u(srv).ListNodeCVEs(viewer, &genezav1.ListNodeCVEsRequest{NodeId: node}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("viewer ListNodeCVEs: want PermissionDenied, got %v", err)
		}
		if _, err := u(srv).ListNodesAffectedByCVE(viewer, &genezav1.ListNodesAffectedByCVERequest{Cve: "CVE-2021-1"}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("viewer ListNodesAffectedByCVE: want PermissionDenied, got %v", err)
		}
		if _, err := u(srv).ListNodeComponents(viewer, &genezav1.ListNodeComponentsRequest{NodeId: node}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("viewer ListNodeComponents: want PermissionDenied, got %v", err)
		}

		// Allowed: ws-member.
		member := userCtx(ws, "alice", roleWSMember)
		if _, err := u(srv).ListNodeCVEs(member, &genezav1.ListNodeCVEsRequest{NodeId: node}); err != nil {
			t.Fatalf("member ListNodeCVEs: %v", err)
		}
		// Allowed: ws-admin implies the view too.
		admin := userCtx(ws, "adm", roleWSAdmin)
		if _, err := u(srv).ListNodesAffectedByCVE(admin, &genezav1.ListNodesAffectedByCVERequest{Cve: "CVE-2021-1"}); err != nil {
			t.Fatalf("admin ListNodesAffectedByCVE: %v", err)
		}
	}
	t.Run("bbolt", func(t *testing.T) { run(t, newReplayServer(t)) })
	t.Run("sql", func(t *testing.T) {
		forEachSQLEngine(t, func(t *testing.T, sqls *sqlStore) {
			run(t, newReplayServerWithStore(t, sqls))
		})
	})
}

// TestVulnQueryCrossWorkspaceIsolation proves a wsA-scoped caller cannot reach wsB's
// node CVEs or inventory: the workspace is taken from the cert, and no request
// carries a workspace, so a wsB node is invisible — even by id, even for the same
// CVE — to a wsA caller who otherwise holds the capability.
func TestVulnQueryCrossWorkspaceIsolation(t *testing.T) {
	run := func(t *testing.T, srv *Server) {
		// Seed a node + CVE in wsB only.
		seedVulnFixture(t, srv, "wsB", "nB")

		aCtx := userCtx("wsA", "alice", roleWSMember) // capable, but in workspace A

		// wsB's node is not found from wsA (no cross-tenant id resolution).
		if _, err := u(srv).ListNodeCVEs(aCtx, &genezav1.ListNodeCVEsRequest{NodeId: "nB"}); status.Code(err) != codes.NotFound {
			t.Fatalf("cross-ws ListNodeCVEs: want NotFound, got %v", err)
		}
		if _, err := u(srv).ListNodeComponents(aCtx, &genezav1.ListNodeComponentsRequest{NodeId: "nB"}); status.Code(err) != codes.NotFound {
			t.Fatalf("cross-ws ListNodeComponents: want NotFound, got %v", err)
		}
		// The same CVE id resolves to nothing in wsA's fleet (wsB's row is invisible).
		byCVE, err := u(srv).ListNodesAffectedByCVE(aCtx, &genezav1.ListNodesAffectedByCVERequest{Cve: "CVE-2021-1"})
		if err != nil || byCVE.GetTotal() != 0 {
			t.Fatalf("cross-ws ListNodesAffectedByCVE: want empty, got total=%d err=%v", byCVE.GetTotal(), err)
		}
	}
	t.Run("bbolt", func(t *testing.T) { run(t, newReplayServer(t)) })
	t.Run("sql", func(t *testing.T) {
		forEachSQLEngine(t, func(t *testing.T, sqls *sqlStore) {
			run(t, newReplayServerWithStore(t, sqls))
		})
	})
}
