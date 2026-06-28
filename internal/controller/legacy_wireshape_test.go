package controller

import (
	"encoding/json"
	"testing"

	"geneza.io/internal/types"
)

// A cluster with no offline anchor configured produces the legacy single-envelope
// ClusterConfig and writes NO trust anchors — the split is invisible on the wire
// and in the store until an operator establishes an anchor.
func TestGenesisStaysLegacyNoAnchor(t *testing.T) {
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Split mode must be inactive: no anchor in the store.
	if active, err := splitModeActive(srv.store); err != nil || active {
		t.Fatalf("genesis must be legacy (split inactive); active=%v err=%v", active, err)
	}
	mapV, mapSigned, anchorV, anchorSigned, err := srv.store.FleetStateSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if anchorV != 0 || anchorSigned != nil {
		t.Fatalf("genesis wrote trust anchors: v%d %v", anchorV, anchorSigned)
	}
	if mapV != 1 {
		t.Fatalf("genesis config version = %d, want 1", mapV)
	}
	// The stored config is a legacy Signed ClusterConfig that self-verifies via its
	// own grant keys (TrustKeys absent) — exactly the pre-split representation.
	env, err := types.DecodeSigned(mapSigned)
	if err != nil {
		t.Fatalf("genesis config must be a legacy Signed envelope: %v", err)
	}
	var parsed types.ClusterConfig
	if err := json.Unmarshal(env.Payload, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.TrustKeys) != 0 {
		t.Fatalf("legacy genesis must carry no TrustKeys, got %+v", parsed.TrustKeys)
	}
	trust, err := parsed.TrustedConfigKeys()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := types.VerifyClusterConfig(trust, env, 0); err != nil {
		t.Fatalf("legacy genesis config must verify via its own grant keys: %v", err)
	}
}
