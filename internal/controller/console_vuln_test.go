package controller

import (
	"testing"
)

// mintConsoleSession writes a session record and returns the raw bearer token a
// console request would carry, so a handler test exercises the real auth path.
func mintConsoleSession(t *testing.T, srv *Server, ws, user string, roles ...string) string {
	t.Helper()
	tok := "tok-" + user
	if err := srv.store.PutAuthSession(&AuthSession{
		TokenHash: hashToken(tok),
		User:      user,
		Provider:  "local",
		Subject:   "u-" + user,
		Workspace: ws,
		Roles:     roles,
		Admin:     isWorkspaceAdmin(roles),
	}); err != nil {
		t.Fatalf("put auth session: %v", err)
	}
	return tok
}

// TestConsoleVulnRoutes drives the three vulnerability REST routes through the
// real console mux: a ws-member reads the by-node CVEs (with the affected-only
// filter), the inverse by-CVE view and the inventory; a read-only ws-viewer is
// denied; and a missing node is a 404, not a cross-tenant leak.
func TestConsoleVulnRoutes(t *testing.T) {
	srv := newReplayServer(t)
	const ws, node = defaultWorkspace, "n1"
	seedVulnFixture(t, srv, ws, node)

	api, err := srv.newConsoleAPI()
	if err != nil {
		t.Fatalf("console api: %v", err)
	}
	h := api.handler()
	member := mintConsoleSession(t, srv, ws, "alice", roleWSMember)

	// By node: both verdict rows, carrying the prioritization fields.
	code, resp := doJSON(t, h, "GET", "/api/v1/nodes/"+node+"/cves", member, "")
	if code != 200 {
		t.Fatalf("node cves: %d %v", code, resp)
	}
	if resp["total"].(float64) != 2 {
		t.Fatalf("node cves: want total 2, got %v", resp["total"])
	}
	cves := resp["cves"].([]any)
	var sawKEV bool
	for _, c := range cves {
		row := c.(map[string]any)
		if row["cve"] == "CVE-2021-1" {
			sawKEV = row["kev"] == true && row["epss"] == 0.42 &&
				row["fixedVersion"] == "1.1.1f-1+deb11u1" && row["severity"] == "high"
		}
	}
	if !sawKEV {
		t.Fatalf("node cves dropped the prioritization fields: %v", cves)
	}

	// affected_only narrows to the single still-affected row.
	code, resp = doJSON(t, h, "GET", "/api/v1/nodes/"+node+"/cves?affected_only=true", member, "")
	if code != 200 || resp["total"].(float64) != 1 {
		t.Fatalf("affected_only: want 1 row, got %d %v", code, resp)
	}
	if resp["cves"].([]any)[0].(map[string]any)["cve"] != "CVE-2021-1" {
		t.Fatalf("affected_only: want the affected row, got %v", resp["cves"])
	}

	// By CVE: the inverse view names the node.
	code, resp = doJSON(t, h, "GET", "/api/v1/cves/CVE-2021-1/nodes", member, "")
	if code != 200 || resp["total"].(float64) != 1 {
		t.Fatalf("nodes by cve: want 1 node, got %d %v", code, resp)
	}
	if resp["nodes"].([]any)[0].(map[string]any)["nodeId"] != node {
		t.Fatalf("nodes by cve: want node %q, got %v", node, resp["nodes"])
	}

	// Inventory: the node's resolved components.
	code, resp = doJSON(t, h, "GET", "/api/v1/nodes/"+node+"/components", member, "")
	if code != 200 || resp["total"].(float64) != 2 {
		t.Fatalf("components: want 2, got %d %v", code, resp)
	}

	// A read-only ws-viewer cannot see the exploitable surface.
	viewer := mintConsoleSession(t, srv, ws, "vic", "ws-viewer")
	for _, path := range []string{
		"/api/v1/nodes/" + node + "/cves",
		"/api/v1/cves/CVE-2021-1/nodes",
		"/api/v1/nodes/" + node + "/components",
	} {
		if code, _ := doJSON(t, h, "GET", path, viewer, ""); code != 403 {
			t.Fatalf("viewer %s: want 403, got %d", path, code)
		}
	}

	// A missing node is a 404, never a leak.
	if code, _ := doJSON(t, h, "GET", "/api/v1/nodes/ghost/cves", member, ""); code != 404 {
		t.Fatalf("missing node: want 404, got %d", code)
	}
}
