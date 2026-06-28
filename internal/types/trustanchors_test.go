package types

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"testing"
	"time"
)

// anchorSigner is one offline trust key used in tests.
type anchorSigner struct {
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	keyID string
}

func newAnchorSigner(t *testing.T) anchorSigner {
	t.Helper()
	pub, priv, id, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return anchorSigner{pub, priv, id}
}

func (s anchorSigner) trustKey() TrustKey { return TrustKey{KeyID: s.keyID, PublicKey: s.pub} }

// signAnchors signs a TrustAnchors payload with each given signer, assembling a
// MultiSigned. The first signer's marshalled anchors is the payload.
func signAnchors(t *testing.T, a *TrustAnchors, signers ...anchorSigner) *MultiSigned {
	t.Helper()
	payload := marshalJSON(t, a)
	ms := &MultiSigned{Payload: payload}
	for _, s := range signers {
		one, err := SignOne(s.priv, s.keyID, contextTrustAnchors, payload)
		if err != nil {
			t.Fatal(err)
		}
		ms.Sigs = append(ms.Sigs, one)
	}
	return ms
}

func marshalJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// signRoutineMap signs a routine map bound to the given anchor payload with a
// grant key.
func signRoutineMap(t *testing.T, rm *RoutineMap, anchorPayload []byte, priv ed25519.PrivateKey, keyID string) *Signed {
	t.Helper()
	rm.AnchorDigest = AnchorDigestOf(anchorPayload)
	s, err := Sign(priv, keyID, contextRoutineMap, rm)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMultiSigThresholdAccept(t *testing.T) {
	a, b, c := newAnchorSigner(t), newAnchorSigner(t), newAnchorSigner(t)
	pinned := map[string]ed25519.PublicKey{a.keyID: a.pub, b.keyID: b.pub, c.keyID: c.pub}
	payload := []byte(`{"x":1}`)

	mk := func(signers ...anchorSigner) *MultiSigned {
		ms := &MultiSigned{Payload: payload}
		for _, s := range signers {
			one, err := SignOne(s.priv, s.keyID, "ctx", payload)
			if err != nil {
				t.Fatal(err)
			}
			ms.Sigs = append(ms.Sigs, one)
		}
		return ms
	}

	// 2-of-3: two distinct valid sigs accept.
	if _, err := VerifyMultiSig(pinned, 2, "ctx", mk(a, b), nil); err != nil {
		t.Fatalf("2 of 3 must accept: %v", err)
	}
	// fewer than threshold reject.
	if _, err := VerifyMultiSig(pinned, 2, "ctx", mk(a), nil); err == nil {
		t.Fatal("1 of required 2 must be rejected")
	}
	// duplicate key id counts once: a twice does not reach 2.
	if _, err := VerifyMultiSig(pinned, 2, "ctx", mk(a, a), nil); err == nil {
		t.Fatal("a duplicate key id must count once and fail the 2-threshold")
	}
	// a non-pinned key's signature does not count.
	stranger := newAnchorSigner(t)
	if _, err := VerifyMultiSig(pinned, 2, "ctx", mk(a, stranger), nil); err == nil {
		t.Fatal("a non-pinned signer must not contribute to quorum")
	}
	// single-signer (threshold 0 and 1) accepts one valid sig.
	for _, th := range []int{0, 1} {
		if _, err := VerifyMultiSig(pinned, th, "ctx", mk(a), nil); err != nil {
			t.Fatalf("single-signer threshold %d must accept one sig: %v", th, err)
		}
	}
}

func TestMultiSigWrongContextRejected(t *testing.T) {
	a := newAnchorSigner(t)
	pinned := map[string]ed25519.PublicKey{a.keyID: a.pub}
	payload := []byte(`{"x":1}`)
	one, _ := SignOne(a.priv, a.keyID, "ctxA", payload)
	ms := &MultiSigned{Payload: payload, Sigs: []OneSig{one}}
	if _, err := VerifyMultiSig(pinned, 1, "ctxB", ms, nil); err == nil {
		t.Fatal("a signature over a different context must not verify (domain separation)")
	}
}

// nonEd25519Signer reports an RSA-sized signature so MultiSig refuses it.
type nonEd25519Signer struct{ pub ed25519.PublicKey }

func (n nonEd25519Signer) Public() crypto.PublicKey { return n.pub }
func (n nonEd25519Signer) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return make([]byte, 256), nil // not an Ed25519-sized signature
}

func TestSignOneRejectsNonEd25519(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := SignOne(nonEd25519Signer{pub: pub}, "k", "ctx", []byte("p")); err == nil {
		t.Fatal("a non-Ed25519 signer must be rejected at sign time")
	}
}

func TestVerifyFleetStateHappyPath(t *testing.T) {
	off := newAnchorSigner(t)
	gPub, gPriv, gID, _ := GenerateSigningKey()
	anchors := &TrustAnchors{
		AnchorVersion: 1,
		GrantKeys:     []GrantKey{{KeyID: gID, PublicKey: gPub}},
		TrustKeys:     []TrustKey{off.trustKey()},
	}
	anchorEnv := signAnchors(t, anchors, off)
	rm := &RoutineMap{ConfigVersion: 1, AnchorVersion: 1}
	mapEnv := signRoutineMap(t, rm, anchorEnv.Payload, gPriv, gID)

	pinned := map[string]ed25519.PublicKey{off.keyID: off.pub}
	fs, err := VerifyFleetState(pinned, 1, 0, 0, anchorEnv, mapEnv, time.Now())
	if err != nil {
		t.Fatalf("valid pair must verify: %v", err)
	}
	if fs.Anchors.AnchorVersion != 1 || fs.Map.ConfigVersion != 1 {
		t.Fatalf("unexpected fleet state: %+v", fs)
	}
}

func TestVerifyFleetStateRejectsWrongAnchorDigest(t *testing.T) {
	off := newAnchorSigner(t)
	gPub, gPriv, gID, _ := GenerateSigningKey()
	anchors := &TrustAnchors{AnchorVersion: 1, GrantKeys: []GrantKey{{KeyID: gID, PublicKey: gPub}}, TrustKeys: []TrustKey{off.trustKey()}}
	anchorEnv := signAnchors(t, anchors, off)
	pinned := map[string]ed25519.PublicKey{off.keyID: off.pub}

	// Map bound to a DIFFERENT anchor payload's digest (right version, wrong bytes).
	other := &TrustAnchors{AnchorVersion: 1, GrantKeys: []GrantKey{{KeyID: gID, PublicKey: gPub}}, TrustKeys: []TrustKey{off.trustKey()}, AuditRecipient: "age1different"}
	otherEnv := signAnchors(t, other, off)
	rm := &RoutineMap{ConfigVersion: 1, AnchorVersion: 1}
	mapEnv := signRoutineMap(t, rm, otherEnv.Payload, gPriv, gID) // digest of the OTHER anchors
	if _, err := VerifyFleetState(pinned, 1, 0, 0, anchorEnv, mapEnv, time.Now()); err == nil {
		t.Fatal("a routine map carrying a foreign anchor digest must be rejected")
	}
}

func TestVerifyFleetStateRejectsWrongAnchorVersion(t *testing.T) {
	off := newAnchorSigner(t)
	gPub, gPriv, gID, _ := GenerateSigningKey()
	anchors := &TrustAnchors{AnchorVersion: 2, GrantKeys: []GrantKey{{KeyID: gID, PublicKey: gPub}}, TrustKeys: []TrustKey{off.trustKey()}}
	anchorEnv := signAnchors(t, anchors, off)
	pinned := map[string]ed25519.PublicKey{off.keyID: off.pub}

	// Correct digest but the map claims a different anchor version.
	rm := &RoutineMap{ConfigVersion: 1, AnchorVersion: 1}
	mapEnv := signRoutineMap(t, rm, anchorEnv.Payload, gPriv, gID)
	if _, err := VerifyFleetState(pinned, 1, 0, 0, anchorEnv, mapEnv, time.Now()); err == nil {
		t.Fatal("a routine map claiming a mismatched anchor version must be rejected")
	}
}

func TestVerifyFleetStateRollbackFloors(t *testing.T) {
	off := newAnchorSigner(t)
	gPub, gPriv, gID, _ := GenerateSigningKey()
	anchors := &TrustAnchors{AnchorVersion: 2, GrantKeys: []GrantKey{{KeyID: gID, PublicKey: gPub}}, TrustKeys: []TrustKey{off.trustKey()}}
	anchorEnv := signAnchors(t, anchors, off)
	rm := &RoutineMap{ConfigVersion: 3, AnchorVersion: 2}
	mapEnv := signRoutineMap(t, rm, anchorEnv.Payload, gPriv, gID)
	pinned := map[string]ed25519.PublicKey{off.keyID: off.pub}

	// held anchor version higher than incoming -> rollback rejected.
	if _, err := VerifyFleetState(pinned, 1, 3, 0, anchorEnv, mapEnv, time.Now()); err == nil {
		t.Fatal("an anchor version below the held floor must be rejected")
	}
	// held config version higher than incoming -> rollback rejected.
	if _, err := VerifyFleetState(pinned, 1, 2, 4, anchorEnv, mapEnv, time.Now()); err == nil {
		t.Fatal("a routine-map version below the held floor must be rejected")
	}
	// at-or-above both floors -> accepted.
	if _, err := VerifyFleetState(pinned, 1, 2, 3, anchorEnv, mapEnv, time.Now()); err != nil {
		t.Fatalf("a pair at the held floors must verify: %v", err)
	}
}

func TestVerifyFleetStateExpiry(t *testing.T) {
	off := newAnchorSigner(t)
	gPub, gPriv, gID, _ := GenerateSigningKey()
	now := time.Now()
	anchors := &TrustAnchors{AnchorVersion: 1, GrantKeys: []GrantKey{{KeyID: gID, PublicKey: gPub}}, TrustKeys: []TrustKey{off.trustKey()}, ExpiresAt: now.Add(-time.Hour)}
	anchorEnv := signAnchors(t, anchors, off)
	rm := &RoutineMap{ConfigVersion: 1, AnchorVersion: 1}
	mapEnv := signRoutineMap(t, rm, anchorEnv.Payload, gPriv, gID)
	pinned := map[string]ed25519.PublicKey{off.keyID: off.pub}
	if _, err := VerifyFleetState(pinned, 1, 0, 0, anchorEnv, mapEnv, now); err == nil {
		t.Fatal("expired anchors must be rejected when ExpiresAt is set (anti-freeze)")
	}
}

// THE CORE PROPERTY: a holder of only the online grant key cannot produce a
// TrustAnchors that nodes accept (cannot add a grant key, swap CA roots, loosen
// policy) — but it CAN still sign a routine map bound to the real anchor.
func TestCorePropertyGrantKeyCannotForgeAnchors(t *testing.T) {
	off := newAnchorSigner(t)
	gPub, gPriv, gID, _ := GenerateSigningKey()
	anchors := &TrustAnchors{
		AnchorVersion: 1,
		GrantKeys:     []GrantKey{{KeyID: gID, PublicKey: gPub}},
		CARootsPEM:    []byte("real-roots"),
		AgentPolicy:   AgentPolicy{ForbidDetach: true},
		TrustKeys:     []TrustKey{off.trustKey()},
	}
	realEnv := signAnchors(t, anchors, off)
	pinned := map[string]ed25519.PublicKey{off.keyID: off.pub}

	// The attacker holds ONLY the grant key. They craft hostile anchors: add their
	// own grant key, swap CA roots, flip ForbidDetach off.
	attPub, _, attID, _ := GenerateSigningKey()
	forged := &TrustAnchors{
		AnchorVersion: 2,
		GrantKeys: []GrantKey{
			{KeyID: gID, PublicKey: gPub},
			{KeyID: attID, PublicKey: attPub}, // attacker key added
		},
		CARootsPEM:  []byte("attacker-roots"), // swapped
		AgentPolicy: AgentPolicy{ForbidDetach: false},
		TrustKeys:   []TrustKey{off.trustKey()},
	}
	forgedPayload := marshalJSON(t, forged)
	// Sign the forged anchors with the GRANT key (all the attacker has), labelled as
	// the offline key id to try to slip past — both must fail.
	oneGrant, _ := SignOne(gPriv, gID, contextTrustAnchors, forgedPayload)
	oneSpoof, _ := SignOne(gPriv, off.keyID, contextTrustAnchors, forgedPayload) // wrong key under the offline id
	for name, env := range map[string]*MultiSigned{
		"grant-key-id":   {Payload: forgedPayload, Sigs: []OneSig{oneGrant}},
		"spoofed-key-id": {Payload: forgedPayload, Sigs: []OneSig{oneSpoof}},
	} {
		rm := &RoutineMap{ConfigVersion: 1, AnchorVersion: 2}
		mapEnv := signRoutineMap(t, rm, env.Payload, gPriv, gID)
		if _, err := VerifyFleetState(pinned, 1, 0, 0, env, mapEnv, time.Now()); err == nil {
			t.Fatalf("grant key must NOT be able to forge anchors (%s)", name)
		}
	}

	// But the grant key CAN still sign a routine map bound to the REAL anchors.
	rm := &RoutineMap{ConfigVersion: 7, AnchorVersion: 1, ControllerEndpoints: []ControllerEndpoint{{ControllerID: "gw1", Addrs: []string{"10.0.0.1:7401"}}}}
	mapEnv := signRoutineMap(t, rm, realEnv.Payload, gPriv, gID)
	fs, err := VerifyFleetState(pinned, 1, 0, 0, realEnv, mapEnv, time.Now())
	if err != nil {
		t.Fatalf("the grant key must still sign a routine map bound to the real anchors: %v", err)
	}
	if len(fs.Map.ControllerEndpoints) != 1 {
		t.Fatalf("routine map content lost: %+v", fs.Map)
	}
}

// Rotation: new TrustKeys signed by the OLD threshold of the OLD keys is accepted
// and re-pins; signed by fewer than the old threshold is rejected.
func TestVerifyFleetStateRotation(t *testing.T) {
	o1, o2, o3 := newAnchorSigner(t), newAnchorSigner(t), newAnchorSigner(t)
	gPub, gPriv, gID, _ := GenerateSigningKey()
	// Held pinned set: 2-of-3 of the OLD officers.
	oldPinned := map[string]ed25519.PublicKey{o1.keyID: o1.pub, o2.keyID: o2.pub, o3.keyID: o3.pub}

	n1, n2 := newAnchorSigner(t), newAnchorSigner(t)
	rotated := &TrustAnchors{
		AnchorVersion: 2,
		GrantKeys:     []GrantKey{{KeyID: gID, PublicKey: gPub}},
		TrustKeys:     []TrustKey{n1.trustKey(), n2.trustKey()}, // brand-new officer set
		Threshold:     2,
	}

	// Signed by 2 of the OLD officers -> accepted, then re-pin to the new set.
	good := signAnchors(t, rotated, o1, o2)
	rm := &RoutineMap{ConfigVersion: 1, AnchorVersion: 2}
	mapEnv := signRoutineMap(t, rm, good.Payload, gPriv, gID)
	fs, err := VerifyFleetState(oldPinned, 2, 1, 0, good, mapEnv, time.Now())
	if err != nil {
		t.Fatalf("a rotation signed by the old threshold must be accepted: %v", err)
	}
	newPinned, err := fs.Anchors.PinnedTrustKeys()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := newPinned[n1.keyID]; !ok {
		t.Fatal("the new officer set must be re-pinnable from the rotated anchors")
	}

	// Signed by only ONE old officer -> rejected (below the old threshold of 2).
	bad := signAnchors(t, rotated, o1)
	badMap := signRoutineMap(t, &RoutineMap{ConfigVersion: 1, AnchorVersion: 2}, bad.Payload, gPriv, gID)
	if _, err := VerifyFleetState(oldPinned, 2, 1, 0, bad, badMap, time.Now()); err == nil {
		t.Fatal("a rotation signed by fewer than the old threshold must be rejected")
	}
}
