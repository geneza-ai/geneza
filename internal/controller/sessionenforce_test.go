package controller

import (
	"crypto/ed25519"
	"testing"
	"time"

	"geneza.io/internal/defaults"
	"geneza.io/internal/types"
)

func enforceTestServer(t *testing.T) (*Server, ed25519.PublicKey) {
	t.Helper()
	pub, priv, keyID, err := types.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return &Server{grantKey: priv, grantKeyID: keyID, store: testStore(t)}, pub
}

func TestNextEpochMonotonicPerSession(t *testing.T) {
	s, _ := enforceTestServer(t)
	if err := s.store.PutSession("ws", &SessionRecord{ID: "a", State: SessionActive}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.PutSession("ws", &SessionRecord{ID: "b", State: SessionActive}); err != nil {
		t.Fatal(err)
	}
	if e := s.nextEpoch("ws", "a"); e != 1 {
		t.Fatalf("first epoch = %d, want 1", e)
	}
	if e := s.nextEpoch("ws", "a"); e != 2 {
		t.Fatalf("second epoch = %d, want 2", e)
	}
	if e := s.nextEpoch("ws", "b"); e != 1 {
		t.Fatalf("independent session epoch = %d, want 1", e)
	}
	// The counter is durable on the record, so a different controller taking the
	// session over (a fresh Server sharing the same store, simulating a re-home or
	// restart) continues the sequence instead of restarting at 1.
	s2 := &Server{store: s.store}
	if e := s2.nextEpoch("ws", "a"); e != 3 {
		t.Fatalf("epoch after takeover = %d, want 3 (must not reset)", e)
	}
}

func TestSignLeaseVerifies(t *testing.T) {
	s, pub := enforceTestServer(t)
	trusted := map[string]ed25519.PublicKey{s.grantKeyID: pub}
	cnp := []byte("client-noise-pub-0123456789abcdef")
	exp := time.Now().Add(defaults.SessionLeaseTTL).UnixMilli()

	lease, err := s.signLease("sess-x", 7, exp, cnp)
	if err != nil {
		t.Fatal(err)
	}
	if lease.GetEpoch() != 7 || lease.GetSessionId() != "sess-x" {
		t.Fatal("lease wire fields not populated")
	}
	// The sig carries the full types.Signed envelope; verify under the policy context.
	env, err := types.DecodeSigned(lease.GetSig())
	if err != nil {
		t.Fatal(err)
	}
	var p types.LeasePayload
	if _, err := types.Verify(trusted, defaults.ContextSessionPolicy, env, &p); err != nil {
		t.Fatalf("verify lease: %v", err)
	}
	if p.Epoch != 7 || p.SessionID != "sess-x" || string(p.ClientNoisePub) != string(cnp) {
		t.Fatalf("verified payload mismatch: %+v", p)
	}

	// A grant-context verification must FAIL: domain separation prevents a lease
	// signature from being accepted as a grant (and vice-versa).
	if _, err := types.Verify(trusted, defaults.ContextGrant, env, nil); err == nil {
		t.Fatal("lease envelope must not verify under the grant context")
	}
}
