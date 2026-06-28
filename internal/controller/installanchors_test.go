package controller

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"geneza.io/internal/defaults"
	"geneza.io/internal/types"
)

// assembleAnchor signs a TrustAnchors document with the given officer keys and returns
// the MultiSigned envelope bytes plus the canonical payload.
func assembleAnchor(t *testing.T, a *types.TrustAnchors, officers []signer) []byte {
	t.Helper()
	payload, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	ms := &types.MultiSigned{Payload: payload}
	for _, o := range officers {
		one, serr := types.SignOne(o.priv, o.id, defaults.ContextTrustAnchors, payload)
		if serr != nil {
			t.Fatal(serr)
		}
		ms.Sigs = append(ms.Sigs, one)
	}
	env, err := ms.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

type signer struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	id   string
}

func newSigner(t *testing.T) signer {
	t.Helper()
	p, k, id, err := types.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return signer{p, k, id}
}

// Installing a threshold-signed anchor flips the cluster into split mode, the controller
// serves the split pair fresh, and a subsequent routine churn re-signs the routine map
// AND refreshes the served documents (so what a connecting agent is handed is never a
// stale legacy blob). This proves the activation e2e and the served-freshness fix.
func TestInstallTrustAnchorsActivatesSplitAndStaysFresh(t *testing.T) {
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	gpub, err := ed25519PublicKey(srv.grantKey)
	if err != nil {
		t.Fatal(err)
	}

	// Two-of-two officers authorize the controller's grant key.
	o1, o2 := newSigner(t), newSigner(t)
	anchors := &types.TrustAnchors{
		AnchorVersion: 1,
		GrantKeys:     []types.GrantKey{{KeyID: srv.grantKeyID, PublicKey: gpub}},
		CARootsPEM:    srv.ca.RootsPEM,
		TrustKeys:     []types.TrustKey{{KeyID: o1.id, PublicKey: o1.pub}, {KeyID: o2.id, PublicKey: o2.pub}},
		Threshold:     2,
	}
	anchorBytes := assembleAnchor(t, anchors, []signer{o1, o2})

	// Before install: legacy.
	if active, _ := splitModeActive(srv.store); active {
		t.Fatal("cluster must be legacy before an anchor is installed")
	}

	anchorV, configV, err := srv.installTrustAnchors(anchorBytes)
	if err != nil {
		t.Fatalf("install trust anchors: %v", err)
	}
	if anchorV != 1 {
		t.Fatalf("anchor version = %d, want 1", anchorV)
	}
	if active, _ := splitModeActive(srv.store); !active {
		t.Fatal("split mode did not activate after install")
	}

	// The controller now serves the split pair, verifiable against the pinned officers.
	_, legacy, anchorWire, mapWire := srv.fleetWire()
	if len(anchorWire) == 0 || len(mapWire) == 0 {
		t.Fatal("served fleet wire is missing the split documents")
	}
	pinned := map[string]ed25519.PublicKey{o1.id: o1.pub, o2.id: o2.pub}
	ms, _ := types.DecodeMultiSigned(anchorWire)
	sg, _ := types.DecodeSigned(mapWire)
	fs, err := types.VerifyFleetState(pinned, 2, 0, 0, ms, sg, time.Now())
	if err != nil {
		t.Fatalf("served split pair must verify against the pinned officers: %v", err)
	}
	if fs.Map.ConfigVersion != configV {
		t.Fatalf("served routine map version %d != install-reported %d", fs.Map.ConfigVersion, configV)
	}
	// The legacy fallback is still served (for un-pinned nodes during migration) and
	// self-verifies via the grant key.
	if len(legacy) == 0 {
		t.Fatal("split mode must still serve a legacy fallback config")
	}

	// Force a routine churn: a new relay addr. The served routine map must advance and
	// the served documents must reflect it — NOT the prior (now stale) blob.
	beforeV, _, _, beforeMap := srv.fleetWire()
	srv.cfg.RelayAddrs = append(append([]string{}, srv.cfg.RelayAddrs...), "churn.relay:7403")
	if err := srv.reconcileClusterConfig(); err != nil {
		t.Fatalf("split reconcile after churn: %v", err)
	}
	afterV, _, afterAnchor, afterMap := srv.fleetWire()
	if afterV <= beforeV {
		t.Fatalf("served config version did not advance after churn: %d -> %d", beforeV, afterV)
	}
	if string(afterMap) == string(beforeMap) {
		t.Fatal("served routine map was not refreshed after churn (stale blob)")
	}
	// The freshly served map carries the churned relay and binds to the SAME anchor.
	ms2, _ := types.DecodeMultiSigned(afterAnchor)
	sg2, _ := types.DecodeSigned(afterMap)
	fs2, err := types.VerifyFleetState(pinned, 2, 1, 0, ms2, sg2, time.Now())
	if err != nil {
		t.Fatalf("refreshed served pair must verify: %v", err)
	}
	found := false
	for _, a := range fs2.Map.RelayAddrs {
		if a == "churn.relay:7403" {
			found = true
		}
	}
	if !found {
		t.Fatalf("served routine map after churn is missing the new relay: %+v", fs2.Map.RelayAddrs)
	}
	if fs2.Anchors.AnchorVersion != 1 {
		t.Fatalf("a routine churn must not change the anchor version; got %d", fs2.Anchors.AnchorVersion)
	}
}

// With NO anchor installed the controller serves only the legacy config: fleetWire carries
// no split documents, the agent push is the bare cluster_config arm, and the served
// bytes are byte-for-byte the stored legacy config. This is the backward-compat floor.
func TestLegacyServesNoSplitDocuments(t *testing.T) {
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, legacy, anchorWire, mapWire := srv.fleetWire()
	if len(anchorWire) != 0 || len(mapWire) != 0 {
		t.Fatal("a legacy cluster must serve no split documents")
	}
	// The agent push is the legacy cluster_config arm carrying exactly the stored bytes.
	msg := srv.fleetControllerMsg()
	cc := msg.GetClusterConfig()
	if cc == nil {
		t.Fatal("legacy push must use the cluster_config arm, not FleetState")
	}
	if string(cc) != string(legacy) {
		t.Fatal("served legacy push bytes differ from the served legacy config")
	}
	_, stored, err := srv.store.ClusterConfigSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(legacy) {
		t.Fatal("served legacy config is not byte-for-byte the stored config")
	}
}

// With require-split set, an active split controller stops serving the legacy fallback:
// the served wire carries only the anchor + routine-map pair, so an un-pinned node must
// upgrade. An un-split cluster with the flag set is unaffected (it still serves legacy).
func TestRequireSplitSuppressesLegacyFallback(t *testing.T) {
	cfg := testServerConfig(t)
	cfg.RequireSplitTrust = true
	if err := InitDataDir(cfg); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Un-split: the flag has no effect, legacy is still served.
	if _, legacy, _, _ := srv.fleetWire(); len(legacy) == 0 {
		t.Fatal("require-split must not suppress the legacy config on an un-split cluster")
	}

	gpub, _ := ed25519PublicKey(srv.grantKey)
	o1 := newSigner(t)
	anchors := &types.TrustAnchors{
		AnchorVersion: 1,
		GrantKeys:     []types.GrantKey{{KeyID: srv.grantKeyID, PublicKey: gpub}},
		TrustKeys:     []types.TrustKey{{KeyID: o1.id, PublicKey: o1.pub}},
	}
	if _, _, err := srv.installTrustAnchors(assembleAnchor(t, anchors, []signer{o1})); err != nil {
		t.Fatal(err)
	}
	_, legacy, anchorWire, mapWire := srv.fleetWire()
	if len(legacy) != 0 {
		t.Fatal("require-split active split controller must serve no legacy fallback")
	}
	if len(anchorWire) == 0 || len(mapWire) == 0 {
		t.Fatal("require-split must still serve the split pair")
	}
	// The push uses the FleetState arm with an empty legacy field.
	if cc := srv.fleetControllerMsg().GetClusterConfig(); cc != nil {
		t.Fatal("require-split must not use the legacy cluster_config arm")
	}
}

// An anchor that does not meet its own threshold (only one of two required sigs) is
// refused at ingest — the controller never stores an envelope a fleet would reject.
func TestInstallTrustAnchorsRefusesUnderThreshold(t *testing.T) {
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gpub, _ := ed25519PublicKey(srv.grantKey)
	o1, o2 := newSigner(t), newSigner(t)
	anchors := &types.TrustAnchors{
		AnchorVersion: 1,
		GrantKeys:     []types.GrantKey{{KeyID: srv.grantKeyID, PublicKey: gpub}},
		TrustKeys:     []types.TrustKey{{KeyID: o1.id, PublicKey: o1.pub}, {KeyID: o2.id, PublicKey: o2.pub}},
		Threshold:     2,
	}
	// Only ONE officer signs a 2-of-2 document.
	underSigned := assembleAnchor(t, anchors, []signer{o1})
	if _, _, err := srv.installTrustAnchors(underSigned); err == nil {
		t.Fatal("an under-threshold anchor must be refused at install")
	}
	if active, _ := splitModeActive(srv.store); active {
		t.Fatal("a refused install must not activate split mode")
	}
}

// An anchor whose grant set does NOT include this controller's grant key is refused: the
// controller could not sign a usable routine map, so the install would freeze routing.
func TestInstallTrustAnchorsRefusesUnauthorizedGrantKey(t *testing.T) {
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	o1 := newSigner(t)
	other := newSigner(t) // a grant key that is NOT this controller's
	anchors := &types.TrustAnchors{
		AnchorVersion: 1,
		GrantKeys:     []types.GrantKey{{KeyID: other.id, PublicKey: other.pub}},
		TrustKeys:     []types.TrustKey{{KeyID: o1.id, PublicKey: o1.pub}},
	}
	env := assembleAnchor(t, anchors, []signer{o1})
	if _, _, err := srv.installTrustAnchors(env); err == nil {
		t.Fatal("an anchor not authorizing this controller's grant key must be refused")
	}
}

// The config doorbell/poll fires on every controller when the routine map advances. On a
// follower whose in-memory version lags the store, the handler must refresh the served
// split documents in place — not parse the stored routine-map envelope as a legacy
// ClusterConfig, which would blank the split pair and serve pinned nodes a stale config
// they refuse (a routing freeze). This reproduces that follower case.
func TestConfigDoorbellSplitModeRefreshesNotClobbers(t *testing.T) {
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gpub, _ := ed25519PublicKey(srv.grantKey)
	o1 := newSigner(t)
	anchors := &types.TrustAnchors{
		AnchorVersion: 1,
		GrantKeys:     []types.GrantKey{{KeyID: srv.grantKeyID, PublicKey: gpub}},
		CARootsPEM:    srv.ca.RootsPEM,
		TrustKeys:     []types.TrustKey{{KeyID: o1.id, PublicKey: o1.pub}},
	}
	if _, _, err := srv.installTrustAnchors(assembleAnchor(t, anchors, []signer{o1})); err != nil {
		t.Fatal(err)
	}

	// Simulate a follower whose cached version lags the store so the doorbell takes the
	// apply path (not the equal-version early-out that masks this single-node).
	srv.ccMu.Lock()
	srv.ccVersion = 0
	srv.ccMu.Unlock()

	srv.applyClusterConfigFromStore() // the geneza_config doorbell / poll reaction

	_, _, anchorWire, mapWire := srv.fleetWire()
	if len(anchorWire) == 0 || len(mapWire) == 0 {
		t.Fatal("the config doorbell clobbered the served split documents on a lagging follower")
	}
	pinned := map[string]ed25519.PublicKey{o1.id: o1.pub}
	ms, _ := types.DecodeMultiSigned(anchorWire)
	sg, _ := types.DecodeSigned(mapWire)
	if _, err := types.VerifyFleetState(pinned, 1, 0, 0, ms, sg, time.Now()); err != nil {
		t.Fatalf("served split pair after the doorbell must still verify: %v", err)
	}
}
