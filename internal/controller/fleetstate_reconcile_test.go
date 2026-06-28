package controller

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"geneza.io/internal/defaults"
	"geneza.io/internal/types"
)

// In split mode a controller holding only its grant key re-signs the ROUTINE MAP on
// drift (bound to the held anchors) but never authors the anchors — which it
// cannot, since it has no offline trust key. The re-signed pair verifies; the
// anchors are byte-for-byte untouched.
func TestSplitReconcileResignsRoutineMapNotAnchors(t *testing.T) {
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// This controller's grant key (the genesis config's grant key).
	gpub, err := ed25519PublicKey(srv.grantKey)
	if err != nil {
		t.Fatal(err)
	}
	gID := srv.grantKeyID

	// Offline officer + anchors authorizing this controller's grant key.
	oPub, oPriv, oID, _ := types.GenerateSigningKey()
	anchors := &types.TrustAnchors{
		AnchorVersion: 1,
		GrantKeys:     []types.GrantKey{{KeyID: gID, PublicKey: gpub}},
		CARootsPEM:    srv.ca.RootsPEM,
		TrustKeys:     []types.TrustKey{{KeyID: oID, PublicKey: oPub}},
	}
	anchorPayload, _ := json.Marshal(anchors)
	one, err := types.SignOne(oPriv, oID, defaults.ContextTrustAnchors, anchorPayload)
	if err != nil {
		t.Fatal(err)
	}
	anchorEnv := &types.MultiSigned{Payload: anchorPayload, Sigs: []types.OneSig{one}}
	anchorBytes, _ := anchorEnv.Encode()

	// A routine map at v1 bound to these anchors (grant-key-signed).
	rm0 := buildRoutineMap(1, nil, nil, srv.cfg.RelayAddrs, 1, anchorPayload)
	rm0Bytes, err := signRoutineMap(rm0, srv.grantKey, gID)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.store.SetSignedFleetState(1, rm0Bytes, 1, 1, anchorBytes); err != nil {
		t.Fatal(err)
	}

	// Force routine drift by adding a relay addr to the live config.
	srv.cfg.RelayAddrs = append(append([]string{}, srv.cfg.RelayAddrs...), "extra.relay:7403")

	if err := srv.reconcileClusterConfig(); err != nil {
		t.Fatalf("split reconcile: %v", err)
	}

	mapV, mapSigned, anchorV, anchorSigned, err := srv.store.FleetStateSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if mapV != 2 {
		t.Fatalf("routine map should have advanced to v2, got v%d", mapV)
	}
	if anchorV != 1 || string(anchorSigned) != string(anchorBytes) {
		t.Fatal("the trust anchors must be byte-for-byte untouched by a routine re-sign")
	}

	// The re-signed pair verifies against the pinned officer key.
	pinned := map[string]ed25519.PublicKey{oID: oPub}
	ms, _ := types.DecodeMultiSigned(anchorSigned)
	sg, _ := types.DecodeSigned(mapSigned)
	fs, err := types.VerifyFleetState(pinned, 1, 1, 1, ms, sg, time.Now())
	if err != nil {
		t.Fatalf("re-signed fleet state must verify: %v", err)
	}
	found := false
	for _, a := range fs.Map.RelayAddrs {
		if a == "extra.relay:7403" {
			found = true
		}
	}
	if !found {
		t.Fatalf("re-signed routine map missing the drifted relay: %+v", fs.Map.RelayAddrs)
	}
}

// A controller whose grant key the anchors do NOT authorize must leave the published
// routine map untouched (its re-sign would be rejected fleet-wide).
func TestSplitReconcileRefusesWhenGrantKeyNotAuthorized(t *testing.T) {
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Anchors that authorize SOME OTHER grant key, not this controller's.
	oPub, oPriv, oID, _ := types.GenerateSigningKey()
	otherPub, _, otherID, _ := types.GenerateSigningKey()
	anchors := &types.TrustAnchors{
		AnchorVersion: 1,
		GrantKeys:     []types.GrantKey{{KeyID: otherID, PublicKey: otherPub}},
		TrustKeys:     []types.TrustKey{{KeyID: oID, PublicKey: oPub}},
	}
	anchorPayload, _ := json.Marshal(anchors)
	one, _ := types.SignOne(oPriv, oID, defaults.ContextTrustAnchors, anchorPayload)
	anchorBytes, _ := (&types.MultiSigned{Payload: anchorPayload, Sigs: []types.OneSig{one}}).Encode()

	// A pre-published routine map at v5 (signed by the OTHER grant key is irrelevant
	// to the store; the store does not verify). Bind it to these anchors.
	rm0 := buildRoutineMap(5, nil, nil, srv.cfg.RelayAddrs, 1, anchorPayload)
	rm0Bytes, _ := signRoutineMap(rm0, srv.grantKey, srv.grantKeyID)
	if err := srv.store.SetSignedFleetState(5, rm0Bytes, 1, 1, anchorBytes); err != nil {
		t.Fatal(err)
	}

	srv.cfg.RelayAddrs = append(append([]string{}, srv.cfg.RelayAddrs...), "extra.relay:7403")
	if err := srv.reconcileClusterConfig(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if mapV, _, _, _, _ := srv.store.FleetStateSnapshot(); mapV != 5 {
		t.Fatalf("a controller whose key the anchors do not authorize must not bump the map; got v%d", mapV)
	}
}
