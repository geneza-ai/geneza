package agentd

import (
	"crypto/ed25519"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"geneza.io/internal/defaults"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

// leaseWorker builds a minimal Worker whose trusted set verifies the controller
// signer, plus a registered live session with an observable cancel.
func leaseWorker(t *testing.T) (*Worker, ed25519.PrivateKey, string, *atomic.Bool, []byte) {
	t.Helper()
	priv, keyID, trusted := testKeys(t)
	w := &Worker{
		trusted: trusted,
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		events:  make(chan *genezav1.AgentMsg, 64),
		// A dead host socket so killHostSession (on the explicit-revoke path) fails
		// fast (connection refused) instead of dereferencing a nil config.
		cfg: &Config{SessionHostSocket: "/nonexistent/geneza-test-host.sock"},
	}
	g := testGrant(time.Now())
	var canceled atomic.Bool
	w.registerLive(g.ID, func() { canceled.Store(true) }, &g, "direct")
	return w, priv, keyID, &canceled, g.ClientNoisePub
}

func signEnf(t *testing.T, priv ed25519.PrivateKey, keyID string, payload any) []byte {
	t.Helper()
	env, err := types.Sign(priv, keyID, defaults.ContextSessionPolicy, payload)
	if err != nil {
		t.Fatal(err)
	}
	b, err := env.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (w *Worker) epochOf(id string) int64 {
	w.liveMu.Lock()
	ls := w.live[id]
	w.liveMu.Unlock()
	if ls == nil {
		return -1
	}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return ls.epoch
}

func (w *Worker) drainRevoked(id string) bool {
	for {
		select {
		case m := <-w.events:
			if ev := m.GetSessionEvent(); ev != nil && ev.GetSessionId() == id && ev.GetEvent() == "revoked" {
				return true
			}
		default:
			return false
		}
	}
}

func lease(sid string, epoch, expiryMs int64, cnp []byte) types.LeasePayload {
	return types.LeasePayload{SessionID: sid, Epoch: epoch, ExpiryUnixMs: expiryMs, ClientNoisePub: cnp}
}

// A starved lease (deadline passed without a renewal) tears the CONDUIT (cancel)
// but not via a "revoked" event — a detachable PTY survives. The session leaves
// w.live.
func TestLeaseExpiryTearsConduit(t *testing.T) {
	w, priv, keyID, canceled, cnp := leaseWorker(t)
	exp := time.Now().Add(120 * time.Millisecond).UnixMilli()
	w.applyLease(&genezav1.SessionLease{SessionId: "sess-1", Epoch: 1, LeaseExpiryUnixMs: exp,
		Sig: signEnf(t, priv, keyID, lease("sess-1", 1, exp, cnp))})
	time.Sleep(300 * time.Millisecond)
	if !canceled.Load() {
		t.Fatal("expected conduit torn on lease starvation")
	}
	if w.epochOf("sess-1") != -1 {
		t.Fatal("expected session removed from live set after lease expiry")
	}
	if w.drainRevoked("sess-1") {
		t.Fatal("lease starvation must NOT emit a revoked event (detachable PTY preserved)")
	}
}

// A fresh higher-epoch lease re-arms the timer; the old deadline must not fire.
func TestFreshLeaseReArms(t *testing.T) {
	w, priv, keyID, canceled, cnp := leaseWorker(t)
	e1 := time.Now().Add(150 * time.Millisecond).UnixMilli()
	w.applyLease(&genezav1.SessionLease{SessionId: "sess-1", Epoch: 1, LeaseExpiryUnixMs: e1,
		Sig: signEnf(t, priv, keyID, lease("sess-1", 1, e1, cnp))})
	time.Sleep(60 * time.Millisecond)
	e2 := time.Now().Add(5 * time.Second).UnixMilli()
	w.applyLease(&genezav1.SessionLease{SessionId: "sess-1", Epoch: 2, LeaseExpiryUnixMs: e2,
		Sig: signEnf(t, priv, keyID, lease("sess-1", 2, e2, cnp))})
	time.Sleep(200 * time.Millisecond)
	if canceled.Load() {
		t.Fatal("a re-leased session must not be torn at the old deadline")
	}
	if w.epochOf("sess-1") != 2 {
		t.Fatalf("epoch = %d, want 2", w.epochOf("sess-1"))
	}
}

// Lease epoch must strictly increase; replay/rollback and bad signatures are dropped.
func TestLeaseEpochAndSignature(t *testing.T) {
	w, priv, keyID, _, cnp := leaseWorker(t)
	mk := func(epoch int64) *genezav1.SessionLease {
		exp := time.Now().Add(10 * time.Second).UnixMilli()
		return &genezav1.SessionLease{SessionId: "sess-1", Epoch: epoch, LeaseExpiryUnixMs: exp,
			Sig: signEnf(t, priv, keyID, lease("sess-1", epoch, exp, cnp))}
	}
	w.applyLease(mk(2))
	if w.epochOf("sess-1") != 2 {
		t.Fatal("epoch 2 should apply")
	}
	w.applyLease(mk(2)) // replay (not strictly greater)
	if w.epochOf("sess-1") != 2 {
		t.Fatal("replayed epoch must be ignored")
	}
	w.applyLease(mk(1)) // rollback
	if w.epochOf("sess-1") != 2 {
		t.Fatal("rolled-back epoch must be ignored")
	}
	w.applyLease(mk(3))
	if w.epochOf("sess-1") != 3 {
		t.Fatal("epoch 3 should apply")
	}
	// Tampered signature: flip a payload byte.
	bad := mk(4)
	bad.Sig[len(bad.Sig)/2] ^= 0xff
	w.applyLease(bad)
	if w.epochOf("sess-1") != 3 {
		t.Fatal("tampered lease must be dropped, epoch unchanged")
	}
}

// Lease binding: a lease whose payload client key differs from the live session is
// dropped even with a valid signature (cross-session lease cannot extend another).
func TestLeaseBindingMismatch(t *testing.T) {
	w, priv, keyID, _, _ := leaseWorker(t)
	other := make([]byte, 32) // not the session's client key
	exp := time.Now().Add(10 * time.Second).UnixMilli()
	w.applyLease(&genezav1.SessionLease{SessionId: "sess-1", Epoch: 5, LeaseExpiryUnixMs: exp,
		Sig: signEnf(t, priv, keyID, lease("sess-1", 5, exp, other))})
	if w.epochOf("sess-1") != 0 {
		t.Fatal("lease bound to a different client key must be dropped")
	}
}

// An explicit signed revoke tears the conduit AND emits "revoked" (authz deny);
// a replayed lower-epoch revoke is dropped while the session is live.
func TestApplyRevokeEpochGate(t *testing.T) {
	w, priv, keyID, canceled, cnp := leaseWorker(t)
	exp := time.Now().Add(10 * time.Second).UnixMilli()
	w.applyLease(&genezav1.SessionLease{SessionId: "sess-1", Epoch: 4, LeaseExpiryUnixMs: exp,
		Sig: signEnf(t, priv, keyID, lease("sess-1", 4, exp, cnp))})
	// Stale revoke (epoch <= current) is ignored.
	w.applyRevoke(&genezav1.SessionRevoke{SessionId: "sess-1", Epoch: 3, Reason: "stale",
		Sig: signEnf(t, priv, keyID, types.RevokePayload{SessionID: "sess-1", Epoch: 3, Reason: "stale", ClientNoisePub: cnp})})
	if canceled.Load() || w.epochOf("sess-1") == -1 {
		t.Fatal("stale revoke must be ignored")
	}
	// Fresh revoke tears down and acks.
	w.applyRevoke(&genezav1.SessionRevoke{SessionId: "sess-1", Epoch: 5, Reason: "denied",
		Sig: signEnf(t, priv, keyID, types.RevokePayload{SessionID: "sess-1", Epoch: 5, Reason: "denied", ClientNoisePub: cnp})})
	if !canceled.Load() {
		t.Fatal("fresh revoke must tear the conduit")
	}
	if !w.drainRevoked("sess-1") {
		t.Fatal("revoke must emit a revoked ack")
	}
}

// A downgrade delta with allow=false is a full cut (tears + acks); a delta that
// would ADD a capability beyond the grant is rejected.
func TestApplyDelta(t *testing.T) {
	w, priv, keyID, canceled, cnp := leaseWorker(t)
	// Non-downgrade (adds a forward target the shell grant never had) -> rejected.
	badCaps := &genezav1.SessionCaps{Allow: true, ForwardTargets: []string{"10.0.0.9:22"}}
	w.applyDelta(&genezav1.SessionPolicyDelta{SessionId: "sess-1", Epoch: 2, Caps: badCaps,
		Sig: signEnf(t, priv, keyID, types.DeltaPayload{SessionID: "sess-1", Epoch: 2,
			Caps: capsFromProto(badCaps), ClientNoisePub: cnp})})
	if canceled.Load() {
		t.Fatal("a non-downgrade delta must be rejected, not applied")
	}
	// Full cut.
	cut := &genezav1.SessionCaps{Allow: false}
	w.applyDelta(&genezav1.SessionPolicyDelta{SessionId: "sess-1", Epoch: 3, Caps: cut,
		Sig: signEnf(t, priv, keyID, types.DeltaPayload{SessionID: "sess-1", Epoch: 3,
			Caps: capsFromProto(cut), ClientNoisePub: cnp})})
	if !canceled.Load() {
		t.Fatal("allow=false delta must cut the session")
	}
}

// capsAllowForward gates new forward channels by the live downgrade: nil caps =
// no downgrade (allow), else the target must be in the allowed set.
func TestCapsAllowForward(t *testing.T) {
	if !capsAllowForward(nil, "10.0.0.5", 5432) {
		t.Fatal("nil caps (no downgrade) must allow")
	}
	allow := &genezav1.SessionCaps{Allow: true, ForwardTargets: []string{"10.0.0.5:5432"}}
	if !capsAllowForward(allow, "10.0.0.5", 5432) {
		t.Fatal("target in allowed set must be allowed")
	}
	if capsAllowForward(allow, "10.0.0.9", 22) {
		t.Fatal("target not in allowed set must be denied")
	}
	revoked := &genezav1.SessionCaps{Allow: true, ForwardTargets: nil}
	if capsAllowForward(revoked, "10.0.0.5", 5432) {
		t.Fatal("empty allowed set (revoke_forward) must deny all")
	}
}
