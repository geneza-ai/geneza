package controller

import (
	"encoding/json"
	"testing"

	"geneza.io/internal/defaults"
	"geneza.io/internal/types"
)

// canSignConfig: a controller may sign a config with no separate trust root (the
// grant key is the root), or one whose trust set includes its own grant key id;
// never one protected by a foreign trust key.
func TestCanSignConfig(t *testing.T) {
	s := &Server{grantKeyID: "gw1"}
	if !s.canSignConfig(nil) {
		t.Fatal("empty trust set must be signable (grant key is the root)")
	}
	if !s.canSignConfig([]types.TrustKey{{KeyID: "gw1"}, {KeyID: "other"}}) {
		t.Fatal("a trust set containing this controller's key must be signable")
	}
	if s.canSignConfig([]types.TrustKey{{KeyID: "offline"}}) {
		t.Fatal("a foreign-only trust set must NOT be signable by this controller")
	}
}

// Once an operator CASes in a config protected by a separate offline trust key,
// the controller's reconcile loop must NOT strip the TrustKeys nor re-sign with its
// grant key — it leaves the offline-signed config untouched even when it sees
// drift it would otherwise apply.
func TestReconcilePreservesForeignTrustConfig(t *testing.T) {
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// A separate offline trust key the controller does NOT hold.
	tPub, tPriv, tID, err := types.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	storedV, _ := srv.store.ClusterConfigVersion()
	raw, _ := srv.store.SignedClusterConfig()
	sgn, _ := types.DecodeSigned(raw)
	var cur types.ClusterConfig
	if err := json.Unmarshal(sgn.Payload, &cur); err != nil {
		t.Fatal(err)
	}
	cur.ConfigVersion = storedV + 1
	cur.TrustKeys = []types.TrustKey{{KeyID: tID, PublicKey: tPub}}
	cur.RelayAddrs = append(append([]string{}, cur.RelayAddrs...), "extra.relay:7403") // force drift
	foreign, err := types.Sign(tPriv, tID, defaults.ContextClusterConfig, cur)
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := foreign.Encode()
	if err := srv.store.SetSignedClusterConfig(storedV+1, enc); err != nil {
		t.Fatal(err)
	}

	// Reconcile: the controller sees drift (the extra relay) but holds no trust key.
	if err := srv.reconcileClusterConfig(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	gotV, _ := srv.store.ClusterConfigVersion()
	if gotV != storedV+1 {
		t.Fatalf("reconcile bumped a config it cannot sign: version %d", gotV)
	}
	raw2, _ := srv.store.SignedClusterConfig()
	sgn2, _ := types.DecodeSigned(raw2)
	if sgn2.KeyID != tID {
		t.Fatalf("reconcile re-signed with %q; the offline trust signature %q must stand", sgn2.KeyID, tID)
	}
	var got types.ClusterConfig
	if err := json.Unmarshal(sgn2.Payload, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.TrustKeys) != 1 || got.TrustKeys[0].KeyID != tID {
		t.Fatalf("reconcile stripped the trust keys: %+v", got.TrustKeys)
	}
}
