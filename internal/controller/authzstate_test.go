package controller

import (
	"testing"
)

func TestSuspensionStoreAndKeyNormalization(t *testing.T) {
	s := testStore(t)
	// Suspend via the console-session provider ("keystone").
	if err := s.SuspendPrincipal(defaultWorkspace, providerKeystone, "ks-uid-1", "alice", "admin", "policy violation"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	// The cert path's provider is "device:keystone" — principalKey MUST normalize
	// so the broker/sweep read the SAME key the suspend wrote.
	if !s.IsSuspended(defaultWorkspace, "device:keystone", "ks-uid-1") {
		t.Fatalf("device:keystone must resolve to the same suspension as keystone")
	}
	if !s.IsSuspended(defaultWorkspace, providerKeystone, "ks-uid-1") {
		t.Fatalf("principal should be suspended")
	}
	// A different workspace / subject is not affected.
	if s.IsSuspended("other", providerKeystone, "ks-uid-1") || s.IsSuspended(defaultWorkspace, providerKeystone, "ks-uid-2") {
		t.Fatalf("suspension leaked across workspace/subject")
	}
	// Operational certs (empty subject: break-glass / node) are NEVER member-
	// suspendable — they must pass (they are killed via the cert denylist).
	if s.IsSuspended(defaultWorkspace, "breakglass", "") {
		t.Fatalf("empty-subject (operational) principal must not be member-suspendable")
	}
	// Lift restores.
	if err := s.LiftSuspension(defaultWorkspace, providerKeystone, "ks-uid-1"); err != nil {
		t.Fatalf("lift: %v", err)
	}
	if s.IsSuspended(defaultWorkspace, providerKeystone, "ks-uid-1") {
		t.Fatalf("principal should be un-suspended after lift")
	}
	// SuspendPrincipal refuses an empty subject (unkeyable).
	if err := s.SuspendPrincipal(defaultWorkspace, providerLocal, "", "x", "admin", ""); err == nil {
		t.Fatalf("suspending an empty subject must fail closed")
	}
}

// TestSuspensionDropsLiveSessionInSweep proves the headline property at the
// reauthorize layer: a suspended principal's live session is no longer authorized
// (the sweep would revoke it), independent of the cert still being valid.
func TestSuspensionDropsLiveSessionInSweep(t *testing.T) {
	srv, _ := testConsoleServer(t)
	rec := &SessionRecord{
		ID: "s-1", WorkspaceID: defaultWorkspace, User: "alice",
		Provider: "device:keystone", Subject: "ks-uid-1",
		NodeID: "n-1", Action: "exec", State: SessionActive, Roles: []string{"ops"},
	}
	// Not suspended yet -> reauthorize fails only on missing node (allowed path),
	// so assert specifically that suspension flips it.
	if err := srv.store.SuspendPrincipal(defaultWorkspace, providerKeystone, "ks-uid-1", "alice", "admin", "test"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	d := srv.reauthorize(rec)
	if d.Allow || d.Reason != "principal suspended" {
		t.Fatalf("suspended principal must fail reauthorize, got allow=%v reason=%q", d.Allow, d.Reason)
	}
	// A different (non-suspended) principal on the same session id is unaffected.
	rec2 := &SessionRecord{ID: "s-2", WorkspaceID: defaultWorkspace, User: "bob", Provider: "device:keystone", Subject: "ks-uid-2", NodeID: "n-1", Action: "exec", State: SessionActive, Roles: []string{"ops"}}
	if d2 := srv.reauthorize(rec2); !d2.Allow && d2.Reason == "principal suspended" {
		t.Fatalf("non-suspended principal must not be flagged suspended")
	}
}

// TestSuspendDeniesBrowserLogin proves that a suspended principal cannot mint
// a new browser session even though authentication (the password) is valid.
func TestSuspendDeniesBrowserLogin(t *testing.T) {
	srv, api := testConsoleServer(t)
	h := api.handler()
	// alice (local) logs in fine first.
	if code, _ := doJSON(t, h, "POST", "/api/v1/session/local", "", `{"username":"alice","password":"hunter2"}`); code != 200 {
		t.Fatalf("baseline login should succeed, got %d", code)
	}
	// Suspend the local principal (subject == username for local).
	if err := srv.store.SuspendPrincipal(defaultWorkspace, providerLocal, "alice", "alice", "admin", "test"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	// Same valid password now yields 403 (authorization suspended), not a session.
	code, resp := doJSON(t, h, "POST", "/api/v1/session/local", "", `{"username":"alice","password":"hunter2"}`)
	if code != 403 {
		t.Fatalf("suspended principal login must be 403, got %d %v", code, resp)
	}
	if _, hasTok := resp["token"]; hasTok {
		t.Fatalf("suspended login must not return a token")
	}
}
