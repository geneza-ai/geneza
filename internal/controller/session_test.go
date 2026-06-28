package controller

import (
	"context"
	"errors"
	"testing"
	"time"
)

func testConsoleServer(t *testing.T) (*Server, *consoleAPI) {
	t.Helper()
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatalf("init: %v", err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	api, err := srv.newConsoleAPI()
	if err != nil {
		t.Fatalf("new console api: %v", err)
	}
	return srv, api
}

func TestAuthSessionMintAndCarrier(t *testing.T) {
	srv, api := testConsoleServer(t)

	tok, rec, err := srv.mintAuthSession(sessionInput{
		Provider: providerOIDC, User: "gadmin", Subject: "sub-1",
		Workspace: defaultWorkspace, Roles: []string{roleWSAdmin}, Groups: []string{"geneza-admins"},
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// Hash-at-rest: the bucket key is sha256(token), NOT the raw token. Looking up
	// by the raw token misses; only the hash hits. The record carries no raw token.
	if rec.TokenHash != hashToken(tok) {
		t.Fatalf("session not keyed by token hash")
	}
	if _, err := srv.store.GetAuthSession(tok); !errors.Is(err, ErrNotFound) {
		t.Fatalf("raw token must NOT be a stored key (got %v)", err)
	}

	// The carrier path resolves workspace/roles/admin ONLY from the record.
	u, err := api.authenticateToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if u.Name != "gadmin" || u.Workspace != defaultWorkspace || !u.Admin {
		t.Fatalf("console user wrong: %+v", u)
	}
	if len(u.Roles) != 1 || u.Roles[0] != roleWSAdmin {
		t.Fatalf("roles wrong: %v", u.Roles)
	}

	// Revocation: deleting the session makes the next carrier call fail closed.
	if err := srv.store.DeleteAuthSession(rec.TokenHash); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := api.authenticateToken(context.Background(), tok); err == nil {
		t.Fatalf("revoked session must not authenticate")
	}
}

// TestAuthSessionTTLCapByUpstream proves a session can never outlive the
// upstream credential that authorized it: when the upstream expiry is sooner
// than the console default TTL, the session expiry is clamped to it.
func TestAuthSessionTTLCapByUpstream(t *testing.T) {
	srv, _ := testConsoleServer(t)
	// Upstream expires in 2 minutes; the console default TTL is 8h.
	up := time.Now().Add(2 * time.Minute).Unix()
	_, rec, err := srv.mintAuthSession(sessionInput{
		Provider: providerKeystone, User: "alice", Subject: "ks-1",
		Workspace: defaultWorkspace, Roles: []string{"ws-viewer"}, UpstreamExp: up,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if rec.ExpiresUnix != up {
		t.Fatalf("session TTL must be capped by upstream expiry: got %d want %d", rec.ExpiresUnix, up)
	}
	// Without an upstream cap, the session uses the console TTL (~8h out).
	_, rec2, _ := srv.mintAuthSession(sessionInput{
		Provider: providerLocal, User: "admin", Subject: "admin",
		Workspace: defaultWorkspace, Roles: []string{roleWSAdmin},
	})
	if rec2.ExpiresUnix <= time.Now().Add(7*time.Hour).Unix() {
		t.Fatalf("local session should get the full console TTL, got exp %d", rec2.ExpiresUnix)
	}
}

func TestAuthSessionExpirySweepAndCarrier(t *testing.T) {
	srv, api := testConsoleServer(t)
	// Mint then force-expire by rewriting the record in the past.
	tok, rec, _ := srv.mintAuthSession(sessionInput{
		Provider: providerLocal, User: "u", Subject: "u",
		Workspace: defaultWorkspace, Roles: []string{"ws-viewer"},
	})
	rec.ExpiresUnix = time.Now().Add(-time.Minute).Unix()
	if err := srv.store.PutAuthSession(rec); err != nil {
		t.Fatalf("put: %v", err)
	}
	// Carrier rejects an expired session (and deletes it on the way).
	if _, err := api.authenticateToken(context.Background(), tok); err == nil {
		t.Fatalf("expired session must not authenticate")
	}
	if _, err := srv.store.GetAuthSession(rec.TokenHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session should be deleted on carrier reject")
	}
	// Sweep removes expired rows in bulk.
	_, r2, _ := srv.mintAuthSession(sessionInput{Provider: providerLocal, User: "v", Subject: "v", Workspace: defaultWorkspace, Roles: []string{"ws-viewer"}})
	r2.ExpiresUnix = time.Now().Add(-time.Minute).Unix()
	_ = srv.store.PutAuthSession(r2)
	n, err := srv.store.SweepExpiredAuthSessions(time.Now().Unix())
	if err != nil || n < 1 {
		t.Fatalf("sweep should remove >=1 expired, got n=%d err=%v", n, err)
	}
}

// TestRevokeUserDropsAuthSessions proves the RevokeUser fan-out: kicking
// a user drops every browser session they hold.
func TestRevokeUserDropsAuthSessions(t *testing.T) {
	srv, _ := testConsoleServer(t)
	for i := 0; i < 3; i++ {
		if _, _, err := srv.mintAuthSession(sessionInput{Provider: providerOIDC, User: "victim", Subject: "victim", Workspace: defaultWorkspace, Roles: []string{"ws-viewer"}}); err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}
	}
	// An unrelated user's session must survive.
	tokKeep, _, _ := srv.mintAuthSession(sessionInput{Provider: providerOIDC, User: "bystander", Subject: "bystander", Workspace: defaultWorkspace, Roles: []string{"ws-viewer"}})

	if _, err := srv.revokeUser("victim", "test"); err != nil {
		t.Fatalf("revokeUser: %v", err)
	}
	all, _ := srv.store.ListAuthSessions()
	for _, s := range all {
		if s.User == "victim" {
			t.Fatalf("victim session survived RevokeUser fan-out")
		}
	}
	if _, err := srv.store.GetAuthSession(hashToken(tokKeep)); err != nil {
		t.Fatalf("bystander session must survive: %v", err)
	}
}

func TestWSTicketSingleUseAndScope(t *testing.T) {
	s := testStore(t)
	tok, _, _ := func() (string, *AuthSession, error) {
		srv, _ := testConsoleServer(t)
		return srv.mintAuthSession(sessionInput{Provider: providerLocal, User: "u", Subject: "u", Workspace: defaultWorkspace, Roles: []string{roleWSAdmin}})
	}()
	sh := hashToken(tok)
	ticket, err := s.MintWSTicket(sh, "n-123", time.Minute)
	if err != nil {
		t.Fatalf("mint ticket: %v", err)
	}
	// Redeem once -> returns the session hash + node.
	gotHash, gotNode, err := s.RedeemWSTicket(ticket, time.Now().Unix())
	if err != nil || gotHash != sh || gotNode != "n-123" {
		t.Fatalf("redeem: hash=%q node=%q err=%v", gotHash, gotNode, err)
	}
	// Single-use: a second redeem fails.
	if _, _, err := s.RedeemWSTicket(ticket, time.Now().Unix()); err == nil {
		t.Fatalf("ticket must be single-use")
	}
	// Expired ticket fails.
	exp, _ := s.MintWSTicket(sh, "n-1", time.Minute)
	if _, _, err := s.RedeemWSTicket(exp, time.Now().Add(2*time.Minute).Unix()); err == nil {
		t.Fatalf("expired ticket must fail")
	}
}
