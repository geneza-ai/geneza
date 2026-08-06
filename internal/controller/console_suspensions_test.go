package controller

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// The console enforced suspension on login, on the web-shell watchdog and on cert
// auth — and offered no way to cause one, lift one, or see that one existed. An
// operator mid-incident had to drop to the CLI for the one verb the console was
// already policing.
func TestConsoleCanSuspendListAndLift(t *testing.T) {
	srv, api, _ := buildLaunchServer(t, EmbedConfig{})
	tok := mintConsoleSession(t, srv, defaultWorkspace, "admin", roleWSAdmin)

	do := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		var r *httptest.ResponseRecorder = httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		api.handler().ServeHTTP(r, req)
		return r
	}

	// Nothing suspended yet.
	w := do("GET", "/api/v1/suspensions", "")
	if w.Code != 200 {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var list map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if rows, _ := list["suspensions"].([]any); len(rows) != 0 {
		t.Fatalf("expected no suspensions, got %v", list["suspensions"])
	}

	// Suspend by explicit subject (the durable authorization key).
	w = do("POST", "/api/v1/suspensions",
		`{"provider":"keystone","subject":"ks-mallory","username":"mallory","reason":"incident 42"}`)
	if w.Code != 200 {
		t.Fatalf("suspend: %d %s", w.Code, w.Body.String())
	}

	// It must now be visible AND actually enforced by the store.
	w = do("GET", "/api/v1/suspensions", "")
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	rows, _ := list["suspensions"].([]any)
	if len(rows) != 1 {
		t.Fatalf("suspension must be listable, got %v", list["suspensions"])
	}
	got, _ := rows[0].(map[string]any)
	if got["subject"] != "ks-mallory" || got["reason"] != "incident 42" {
		t.Fatalf("wrong record: %v", got)
	}
	if got["suspendedBy"] != "console:admin" {
		t.Fatalf("the console user must be recorded as the actor, got %v", got["suspendedBy"])
	}
	if !srv.store.IsSuspended(defaultWorkspace, "keystone", "ks-mallory") {
		t.Fatalf("the suspension must be enforced by the same path the broker reads")
	}

	// Lift it.
	w = do("DELETE", "/api/v1/suspensions/keystone/ks-mallory", "")
	if w.Code != 200 {
		t.Fatalf("lift: %d %s", w.Code, w.Body.String())
	}
	if srv.store.IsSuspended(defaultWorkspace, "keystone", "ks-mallory") {
		t.Fatalf("lifting must restore authorization immediately, not after a cache TTL")
	}
}

// Suspending must be admin-only: a plain member could otherwise lock out their
// own workspace's admins.
func TestSuspensionRoutesRequireAdmin(t *testing.T) {
	srv, api, _ := buildLaunchServer(t, EmbedConfig{})
	tok := mintConsoleSession(t, srv, defaultWorkspace, "bob", "ws-member")

	req := httptest.NewRequest("POST", "/api/v1/suspensions",
		strings.NewReader(`{"provider":"local","subject":"alice","username":"alice"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handler().ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("a non-admin must not be able to suspend: %d %s", w.Code, w.Body.String())
	}
}
