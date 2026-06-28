package main

import (
	"bytes"
	"testing"

	"geneza.io/internal/defaults"
	"geneza.io/internal/types"
)

// The canonical payload is deterministic: signing the same proposed anchors twice
// yields identical bytes, so every officer signs the same input.
func TestCanonicalAnchorPayloadDeterministic(t *testing.T) {
	pub, _, id, _ := types.GenerateSigningKey()
	a := &types.TrustAnchors{
		AnchorVersion: 3,
		GrantKeys:     []types.GrantKey{{KeyID: id, PublicKey: pub}},
		TrustKeys:     []types.TrustKey{{KeyID: id, PublicKey: pub}},
		Threshold:     1,
	}
	b1, err := canonicalAnchorPayload(a)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := canonicalAnchorPayload(a)
	if !bytes.Equal(b1, b2) {
		t.Fatal("canonical payload must be byte-identical across calls")
	}
}

// assemble's threshold guard: an envelope with fewer than Threshold distinct valid
// signatures must not verify against the candidate's own trust keys.
func TestAssembleThresholdGuard(t *testing.T) {
	o1Pub, o1Priv, o1ID, _ := types.GenerateSigningKey()
	o2Pub, o2Priv, o2ID, _ := types.GenerateSigningKey()
	o3Pub, _, o3ID, _ := types.GenerateSigningKey()
	a := &types.TrustAnchors{
		AnchorVersion: 1,
		GrantKeys:     []types.GrantKey{{KeyID: o1ID, PublicKey: o1Pub}},
		TrustKeys: []types.TrustKey{
			{KeyID: o1ID, PublicKey: o1Pub},
			{KeyID: o2ID, PublicKey: o2Pub},
			{KeyID: o3ID, PublicKey: o3Pub},
		},
		Threshold: 2,
	}
	payload, _ := canonicalAnchorPayload(a)
	pinned, _ := a.PinnedTrustKeys()

	s1, _ := types.SignOne(o1Priv, o1ID, defaults.ContextTrustAnchors, payload)
	s2, _ := types.SignOne(o2Priv, o2ID, defaults.ContextTrustAnchors, payload)

	// One signature: below threshold -> rejected.
	if _, err := types.VerifyMultiSig(pinned, a.Threshold, defaults.ContextTrustAnchors,
		&types.MultiSigned{Payload: payload, Sigs: []types.OneSig{s1}}, nil); err == nil {
		t.Fatal("one signature must not meet a threshold of 2")
	}
	// Two distinct signatures: meets threshold -> accepted.
	if _, err := types.VerifyMultiSig(pinned, a.Threshold, defaults.ContextTrustAnchors,
		&types.MultiSigned{Payload: payload, Sigs: []types.OneSig{s1, s2}}, nil); err != nil {
		t.Fatalf("two distinct signatures must meet the threshold: %v", err)
	}
}
