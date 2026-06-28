package controller

import (
	"context"
	"crypto/ed25519"
	"testing"

	"geneza.io/internal/ca"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

func TestExcludeRelayAddr(t *testing.T) {
	floor := []string{"r1:7403", "r2:7403", "r3:7403"}
	got := excludeRelayAddr(floor, "r2:7403")
	if len(got) != 2 || got[0] != "r1:7403" || got[1] != "r3:7403" {
		t.Fatalf("drop dead relay: got %v", got)
	}
	// Dropping the only relay falls back to the original (degraded floor beats none).
	if got := excludeRelayAddr([]string{"only:7403"}, "only:7403"); len(got) != 1 || got[0] != "only:7403" {
		t.Fatalf("sole relay must not empty the floor: got %v", got)
	}
	// An empty dead addr is a no-op.
	if got := excludeRelayAddr(floor, ""); len(got) != 3 {
		t.Fatalf("empty dead addr: got %v", got)
	}
}

func TestExcludeRelayCandidate(t *testing.T) {
	cands := []types.RelayCandidate{{RelayID: "a"}, {RelayID: "b"}, {RelayID: "c"}}
	got := excludeRelayCandidate(cands, "b")
	if len(got) != 2 || got[0].RelayID != "a" || got[1].RelayID != "c" {
		t.Fatalf("drop dead candidate: got %v", got)
	}
}

// activeSession creates a real session and marks it active so it is re-homeable.
func activeSession(t *testing.T, b *Broker, store Store, action string, detachable bool) (*genezav1.CreateSessionResponse, ed25519.PublicKey) {
	t.Helper()
	b.SetSessionP2P(&fakeP2P{})
	ident := &ca.Identity{Kind: ca.KindUser, Workspace: defaultWorkspace, Name: "alice", Roles: []string{"ops"}}
	resp, err := b.CreateSession(context.Background(), ident, &genezav1.CreateSessionRequest{
		Node:           "web1",
		Action:         action,
		WantPty:        action == "shell",
		WantDetachable: detachable,
		Command:        commandForAction(action),
		ClientNoisePub: clientNoise(),
		ClientPath:     "native",
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := store.UpdateSession(defaultWorkspace, resp.SessionId, func(r *SessionRecord) {
		r.State = SessionActive
		if detachable {
			r.HostSessionID = "h-live-1"
		}
	}); err != nil {
		t.Fatal(err)
	}
	return resp, nil
}

func commandForAction(action string) string {
	if action == "exec" {
		return "uptime"
	}
	return ""
}

// TestReissueGrantSwapsRendezvousKeepsScope proves a re-home re-mints only the
// rendezvous-scoped fields (fresh single-use token, healthy floor with the dead
// relay dropped, new window) while keeping the session identity + scope.
func TestReissueGrantSwapsRendezvousKeepsScope(t *testing.T) {
	b, _, store, pub := testBroker(t)
	// Two relays so re-home has a survivor to pick.
	b.SetRelayFloor(func() []string { return []string{"r1:7403", "r2:7403"} })
	resp, _ := activeSession(t, b, store, "exec", false)

	origSigned, _ := types.DecodeSigned(resp.SignedGrant)
	orig, _ := types.VerifyGrant(map[string]ed25519.PublicKey{types.KeyIDFor(pub): pub}, origSigned)

	rg, err := b.ReissueGrant(defaultWorkspace, resp.SessionId, "", "r1:7403", 0)
	if err != nil {
		t.Fatalf("ReissueGrant: %v", err)
	}
	if rg.Epoch != 1 {
		t.Fatalf("first re-home epoch = %d, want 1", rg.Epoch)
	}
	signed, _ := types.DecodeSigned(rg.SignedGrant)
	ng, err := types.VerifyGrant(map[string]ed25519.PublicKey{types.KeyIDFor(pub): pub}, signed)
	if err != nil {
		t.Fatalf("re-issued grant does not verify: %v", err)
	}
	// Identity + scope preserved.
	if ng.ID != orig.ID || ng.User != orig.User || ng.NodeID != orig.NodeID ||
		ng.Action != orig.Action || ng.Command != orig.Command {
		t.Fatalf("scope changed across re-home: %+v vs %+v", ng, orig)
	}
	// Rendezvous re-minted: the dead relay is gone and the token is fresh.
	if len(ng.RelayFloor) != 1 || ng.RelayFloor[0] != "r2:7403" {
		t.Fatalf("dead relay not excluded from floor: %v", ng.RelayFloor)
	}
	if ng.RelayToken == orig.RelayToken {
		t.Fatalf("re-home must mint a FRESH single-use relay token")
	}
	if !ng.IssuedAt.After(orig.IssuedAt) && !ng.ExpiresAt.After(orig.ExpiresAt) {
		t.Fatalf("re-home must open a fresh rendezvous window")
	}
}

// TestReissueIdempotentPerEpoch proves two requests at the same applied epoch mint
// exactly one new generation (the single-minter rule), so the two ends converge.
func TestReissueIdempotentPerEpoch(t *testing.T) {
	b, _, store, _ := testBroker(t)
	b.SetRelayFloor(func() []string { return []string{"r1:7403", "r2:7403"} })
	resp, _ := activeSession(t, b, store, "exec", false)

	first, err := b.ReissueGrant(defaultWorkspace, resp.SessionId, "", "r1:7403", 0)
	if err != nil {
		t.Fatalf("first re-issue: %v", err)
	}
	// A second request still naming applied=0 (a stale/duplicate) must NOT mint a new
	// generation: it returns the current epoch unchanged.
	second, err := b.ReissueGrant(defaultWorkspace, resp.SessionId, "", "r1:7403", 0)
	if err != nil {
		t.Fatalf("second re-issue: %v", err)
	}
	if first.Epoch != 1 || second.Epoch != 1 {
		t.Fatalf("epochs = %d,%d, want 1,1 (single-minter per generation)", first.Epoch, second.Epoch)
	}
	// A request acknowledging epoch 1 advances to 2.
	third, err := b.ReissueGrant(defaultWorkspace, resp.SessionId, "", "r2:7403", 1)
	if err != nil {
		t.Fatalf("third re-issue: %v", err)
	}
	if third.Epoch != 2 {
		t.Fatalf("acked-epoch re-issue = %d, want 2", third.Epoch)
	}
}

// TestReissueRefusesTerminalSession proves re-home never resurrects or extends an
// ended/revoked session — the lease/teardown path stays authoritative.
func TestReissueRefusesTerminalSession(t *testing.T) {
	b, _, store, _ := testBroker(t)
	b.SetRelayFloor(func() []string { return []string{"r1:7403", "r2:7403"} })
	resp, _ := activeSession(t, b, store, "exec", false)
	if err := store.UpdateSession(defaultWorkspace, resp.SessionId, func(r *SessionRecord) {
		r.State = SessionRevoked
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ReissueGrant(defaultWorkspace, resp.SessionId, "", "r1:7403", 0); err == nil {
		t.Fatal("re-home must refuse a revoked session")
	}
}

// TestReissueDetachableShellBecomesAttach proves a detachable shell re-homes by
// RE-ATTACHING its persisted host PTY (action rewritten to attach + AttachID).
func TestReissueDetachableShellBecomesAttach(t *testing.T) {
	b, _, store, pub := testBroker(t)
	b.SetRelayFloor(func() []string { return []string{"r1:7403", "r2:7403"} })
	resp, _ := activeSession(t, b, store, "shell", true)

	rg, err := b.ReissueGrant(defaultWorkspace, resp.SessionId, "", "r1:7403", 0)
	if err != nil {
		t.Fatalf("ReissueGrant: %v", err)
	}
	signed, _ := types.DecodeSigned(rg.SignedGrant)
	ng, err := types.VerifyGrant(map[string]ed25519.PublicKey{types.KeyIDFor(pub): pub}, signed)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ng.Action != types.ActionAttach {
		t.Fatalf("detachable shell re-home action = %q, want attach", ng.Action)
	}
	if ng.AttachID != "h-live-1" {
		t.Fatalf("re-home must re-attach the persisted host PTY: AttachID=%q", ng.AttachID)
	}
}
