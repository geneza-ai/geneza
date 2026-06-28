package controller

import (
	"encoding/json"
	"net/url"
	"testing"
)

// TestAuditWorkspaceScoping proves a tenant audit query sees only its own
// workspace's events — never another tenant's, never cluster-scoped ones.
func TestAuditWorkspaceScoping(t *testing.T) {
	dir := t.TempDir()
	a, err := OpenAudit(dir+"/audit.jsonl", dir+"/audit.key", dir+"/audit.chk", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	mustAppend := func(ws, typ string) {
		if err := a.AppendWS(ws, typ, "actor", "", "", nil); err != nil {
			t.Fatal(err)
		}
	}
	mustAppend("ws-a", "node_approval")
	mustAppend("ws-b", "node_approval")
	mustAppend("", "set_desired_version") // cluster-scoped
	mustAppend("ws-a", "token_create")

	wsOf := func(line []byte) string {
		var e AuditEvent
		_ = json.Unmarshal(line, &e)
		return e.Workspace
	}

	// Tenant A sees only ws-a events (2), never ws-b or cluster.
	aLines, ok, err := a.Query(0, "", "ws-a", 100)
	if err != nil || !ok {
		t.Fatalf("query ws-a: err=%v chainOk=%v", err, ok)
	}
	if len(aLines) != 2 {
		t.Fatalf("ws-a sees %d events, want 2", len(aLines))
	}
	for _, l := range aLines {
		if wsOf(l) != "ws-a" {
			t.Fatalf("ws-a query leaked a %q event", wsOf(l))
		}
	}

	// The cluster path (workspace="") sees everything (4).
	allLines, _, _ := a.Query(0, "", "", 100)
	if len(allLines) != 4 {
		t.Fatalf("cluster query sees %d events, want 4", len(allLines))
	}
}

// TestMetricsWorkspaceScoping proves the metrics proxy forces a server-side
// workspace label matcher for a tenant, and none for the cluster path — so a
// tenant's PromQL can never widen past its own series.
func TestMetricsWorkspaceScoping(t *testing.T) {
	v := url.Values{"query": {`{__name__=~".+"}`}}
	scopeWorkspace(v, "ws-a")
	if got := v.Get("extra_label"); got != "workspace=ws-a" {
		t.Fatalf("tenant scope = %q, want workspace=ws-a", got)
	}
	// A tenant cannot override the enforced label with its own matcher: extra_label
	// is applied by VictoriaMetrics to every selector server-side.
	v2 := url.Values{"query": {`up{workspace="ws-b"}`}}
	scopeWorkspace(v2, "ws-a")
	if got := v2.Get("extra_label"); got != "workspace=ws-a" {
		t.Fatalf("scope not enforced over client matcher: %q", got)
	}
	// Cluster path: no restriction.
	v3 := url.Values{"query": {"up"}}
	scopeWorkspace(v3, "")
	if v3.Get("extra_label") != "" {
		t.Fatal("cluster path must not set a workspace matcher")
	}
}
