package controller

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// The console's session list applied NO user filter while `geneza ps --all` tested
// the reserved cluster role that no login can hold. So the CLI never widened for a
// workspace admin, and the console showed everything to everyone — two surfaces
// disagreeing about who may see who was on which host and when.
func TestConsoleSessionListIsScopedToTheCaller(t *testing.T) {
	srv, api, _ := buildLaunchServer(t, EmbedConfig{})

	for _, s := range []struct{ id, user string }{
		{"s-alice", "alice"},
		{"s-bob", "bob"},
	} {
		if err := srv.store.PutSession(defaultWorkspace, &SessionRecord{
			ID: s.id, NodeID: "n1", NodeName: "n1", User: s.user,
			Action: "shell", State: "active", StartedUnix: 1,
		}); err != nil {
			t.Fatalf("seed %s: %v", s.id, err)
		}
	}

	list := func(tok string) []string {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/v1/sessions", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		api.handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("sessions: %d %s", w.Code, w.Body.String())
		}
		var body struct {
			Sessions []struct {
				SessionID string `json:"sessionId"`
			} `json:"sessions"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		out := make([]string, 0, len(body.Sessions))
		for _, s := range body.Sessions {
			out = append(out, s.SessionID)
		}
		return out
	}

	// A plain member sees only their own.
	bobTok := mintConsoleSession(t, srv, defaultWorkspace, "bob", roleWSMember)
	got := list(bobTok)
	if len(got) != 1 || got[0] != "s-bob" {
		t.Fatalf("a non-admin must see only their own sessions, got %v", got)
	}

	// A workspace admin sees the workspace.
	adminTok := mintConsoleSession(t, srv, defaultWorkspace, "admin", roleWSAdmin)
	got = list(adminTok)
	if len(got) != 2 {
		t.Fatalf("a workspace admin must see the whole workspace, got %v", got)
	}
}
