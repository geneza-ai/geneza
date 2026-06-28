package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWorkspacePolicySeedAndStore proves the on-disk policy_file seeds the store
// once, the store then holds it, and a fresh engine build reads from the store.
func TestWorkspacePolicySeedAndStore(t *testing.T) {
	srv, _ := testConsoleServer(t)

	// On startup the default workspace's engine was seeded from policy_file into
	// the store. Reading it back returns the seeded doc with "bootstrap" provenance.
	doc, meta, err := srv.GetWorkspacePolicy(defaultWorkspace)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if len(doc) == 0 {
		t.Fatal("empty seeded policy")
	}
	if meta.UpdatedBy != "bootstrap" {
		t.Fatalf("seed provenance = %q, want bootstrap", meta.UpdatedBy)
	}
	if _, ok, _ := getStoredWorkspacePolicy(srv.store, defaultWorkspace); !ok {
		t.Fatal("policy was not persisted to the store on seed")
	}
}

// TestSetWorkspacePolicyValidatesAndSwaps proves an edit validates, persists, and
// hot-swaps the live engine — and that an invalid edit changes nothing.
func TestSetWorkspacePolicyValidatesAndSwaps(t *testing.T) {
	srv, _ := testConsoleServer(t)

	good := "roles:\n  ws-admin:\n    allow:\n      - actions: [\"*\"]\n        node_labels: {\"*\": \"*\"}\nbindings:\n  - role: ws-admin\n    users: [alice]\n"
	if err := srv.SetWorkspacePolicy(defaultWorkspace, []byte(good), "console:alice"); err != nil {
		t.Fatalf("set good policy: %v", err)
	}
	doc, meta, err := srv.GetWorkspacePolicy(defaultWorkspace)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(doc, []byte(good)) {
		t.Fatal("stored policy doc does not match what was set")
	}
	if meta.UpdatedBy != "console:alice" {
		t.Fatalf("provenance = %q, want console:alice", meta.UpdatedBy)
	}

	// A binding to an unknown role must be rejected and leave the prior doc intact.
	bad := "roles:\n  ws-admin:\n    allow:\n      - actions: [\"*\"]\n        node_labels: {\"*\": \"*\"}\nbindings:\n  - role: nonexistent\n    users: [alice]\n"
	if err := srv.SetWorkspacePolicy(defaultWorkspace, []byte(bad), "console:alice"); err == nil {
		t.Fatal("invalid policy (unknown role) was accepted")
	}
	doc2, _, _ := srv.GetWorkspacePolicy(defaultWorkspace)
	if !bytes.Equal(doc2, []byte(good)) {
		t.Fatal("rejected edit mutated the stored policy")
	}
}

// TestConsolePolicyEndpoints exercises GET (workspace-scoped), the live validate
// endpoint, and PUT (ws-admin gated) through the real console handlers.
func TestConsolePolicyEndpoints(t *testing.T) {
	_, api := testConsoleServer(t)
	admin := &consoleUser{Name: "alice", Workspace: defaultWorkspace, Admin: true}

	// GET returns the workspace's policy as raw yaml + editable flag.
	rec := httptest.NewRecorder()
	api.handlePolicy(rec, httptest.NewRequest(http.MethodGet, "/api/v1/policy", nil), admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET policy: %d", rec.Code)
	}
	var got struct {
		Workspace string `json:"workspace"`
		Yaml      string `json:"yaml"`
		Editable  bool   `json:"editable"`
	}
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Workspace != defaultWorkspace || got.Yaml == "" || !got.Editable {
		t.Fatalf("GET policy body unexpected: %+v", got)
	}

	// validate: a malformed doc returns valid:false (200, not an HTTP error).
	body := func(y string) *bytes.Reader {
		b, _ := json.Marshal(map[string]string{"yaml": y})
		return bytes.NewReader(b)
	}
	rec = httptest.NewRecorder()
	api.handleValidatePolicy(rec, httptest.NewRequest(http.MethodPost, "/api/v1/policy/validate", body("roles: [oops")), admin)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "\"valid\":false") {
		t.Fatalf("validate(bad) = %d %s", rec.Code, rec.Body.String())
	}

	// PUT a valid policy, then confirm GET reflects it.
	good := "roles:\n  ws-admin:\n    allow:\n      - actions: [exec]\n        node_labels: {env: prod}\nbindings:\n  - role: ws-admin\n    groups: [admins]\n"
	rec = httptest.NewRecorder()
	api.handleSetPolicy(rec, httptest.NewRequest(http.MethodPut, "/api/v1/policy", body(good)), admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT policy: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	api.handlePolicy(rec, httptest.NewRequest(http.MethodGet, "/api/v1/policy", nil), admin)
	json.Unmarshal(rec.Body.Bytes(), &got)
	if !strings.Contains(got.Yaml, "env: prod") {
		t.Fatalf("PUT did not take effect; yaml=%q", got.Yaml)
	}

	// PUT an invalid policy -> 400, store unchanged.
	rec = httptest.NewRecorder()
	api.handleSetPolicy(rec, httptest.NewRequest(http.MethodPut, "/api/v1/policy", body("bindings:\n  - role: ghost\n    users: [x]\n")), admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT invalid policy = %d, want 400", rec.Code)
	}
}
