package controller

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
)

// The nodes list filtered in the browser, over whichever page happened to arrive.
// The store orders by node id, so the first page is the 100 lowest ids — a set that
// correlates with nothing. On a fleet larger than one page the "Pending" tab could
// therefore render EMPTY while nodes were genuinely waiting for approval, and
// approval is the one mutation that page exists to perform.
func TestNodesListFiltersServerSideAcrossPages(t *testing.T) {
	srv, api, _ := buildLaunchServer(t, EmbedConfig{})
	tok := mintConsoleSession(t, srv, defaultWorkspace, "admin", roleWSAdmin)

	// 120 nodes; only the highest-id one is pending, so it lands beyond page one.
	const n = 120
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("n-%03d", i)
		seedLaunchNode(t, srv, defaultWorkspace, id, "i-"+id, "proj-a", nil)
		node, err := srv.store.FindNode(defaultWorkspace, id)
		if err != nil {
			t.Fatalf("find %s: %v", id, err)
		}
		node.Approved = i != n-1
		if err := srv.store.PutNode(defaultWorkspace, node); err != nil {
			t.Fatalf("put %s: %v", id, err)
		}
	}

	get := func(query string) map[string]any {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/v1/nodes"+query, nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		api.handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("nodes%s: %d %s", query, w.Code, w.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	// Unfiltered, the default page cannot show every node.
	all := get("")
	if total, _ := all["total"].(float64); int(total) != n {
		t.Fatalf("total = %v, want %d", all["total"], n)
	}
	if rows, _ := all["nodes"].([]any); len(rows) >= n {
		t.Fatalf("precondition: the fleet must exceed one page, got %d rows", len(rows))
	}

	// Filtered, the pending node must be found regardless of where its id sorts.
	pending := get("?state=pending")
	rows, _ := pending["nodes"].([]any)
	if total, _ := pending["total"].(float64); int(total) != 1 || len(rows) != 1 {
		t.Fatalf("state=pending must find the one pending node wherever it sits: total=%v rows=%d",
			pending["total"], len(rows))
	}
	got, _ := rows[0].(map[string]any)
	if got["nodeId"] != fmt.Sprintf("n-%03d", n-1) {
		t.Fatalf("wrong node returned: %v", got["nodeId"])
	}

	// And a search must reach past the first page too.
	found := get("?q=n-119")
	if total, _ := found["total"].(float64); int(total) != 1 {
		t.Fatalf("q=n-119 total = %v, want 1", found["total"])
	}
}

// Node detail resolved a node by fetching the LIST and searching it, so a node
// past the first page rendered "Node not found." for a node that exists.
func TestSingleNodeLookupDoesNotDependOnPaging(t *testing.T) {
	srv, api, _ := buildLaunchServer(t, EmbedConfig{})
	tok := mintConsoleSession(t, srv, defaultWorkspace, "admin", roleWSAdmin)
	for i := 0; i < 120; i++ {
		id := fmt.Sprintf("n-%03d", i)
		seedLaunchNode(t, srv, defaultWorkspace, id, "i-"+id, "proj-a", nil)
	}

	r := httptest.NewRequest("GET", "/api/v1/nodes/n-119", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	api.handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("a node beyond the first page must resolve: %d %s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["nodeId"] != "n-119" {
		t.Fatalf("got %v", body["nodeId"])
	}

	// An unknown id must still 404 rather than silently returning something.
	r = httptest.NewRequest("GET", "/api/v1/nodes/nope", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w = httptest.NewRecorder()
	api.handler().ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("unknown node: %d, want 404", w.Code)
	}
}
