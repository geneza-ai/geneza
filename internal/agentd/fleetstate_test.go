package agentd

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"geneza.io/internal/defaults"
	"geneza.io/internal/types"
)

// splitFixture builds an offline officer key, a controller grant key, a TrustAnchors
// document the officer signs, and a routine map the grant key signs bound to those
// anchors. It returns the signed envelopes and the keys so a test can forge variants.
type splitFixture struct {
	officerPub  ed25519.PublicKey
	officerPriv ed25519.PrivateKey
	officerID   string
	grantPub    ed25519.PublicKey
	grantPriv   ed25519.PrivateKey
	grantID     string
}

func newSplitFixture(t *testing.T) splitFixture {
	t.Helper()
	oPub, oPriv, oID, err := types.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	gPub, gPriv, gID, err := types.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return splitFixture{oPub, oPriv, oID, gPub, gPriv, gID}
}

func (f splitFixture) anchors(t *testing.T, version int64) ([]byte, []byte) {
	t.Helper()
	a := types.TrustAnchors{
		AnchorVersion: version,
		GrantKeys:     []types.GrantKey{{KeyID: f.grantID, PublicKey: f.grantPub}},
		TrustKeys:     []types.TrustKey{{KeyID: f.officerID, PublicKey: f.officerPub}},
	}
	payload, err := json.Marshal(&a)
	if err != nil {
		t.Fatal(err)
	}
	one, err := types.SignOne(f.officerPriv, f.officerID, defaults.ContextTrustAnchors, payload)
	if err != nil {
		t.Fatal(err)
	}
	env, err := (&types.MultiSigned{Payload: payload, Sigs: []types.OneSig{one}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return env, payload
}

func (f splitFixture) routineMap(t *testing.T, configVersion, anchorVersion int64, anchorPayload []byte, signer ed25519.PrivateKey, signerID string) []byte {
	t.Helper()
	rm := types.RoutineMap{
		ConfigVersion: configVersion,
		AnchorVersion: anchorVersion,
		AnchorDigest:  types.AnchorDigestOf(anchorPayload),
	}
	env, err := types.Sign(signer, signerID, defaults.ContextRoutineMap, rm)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newSplitWorker(t *testing.T) *Worker {
	t.Helper()
	dir := t.TempDir()
	return &Worker{
		cfg:     &Config{StateDir: dir, SessionHostSocket: filepath.Join(dir, "host.sock")},
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		st:      &State{Dir: dir},
		cluster: &types.ClusterConfig{ConfigVersion: 0},
	}
}

// A node TOFU-pins the trust keys from the first anchor, verifies the routine map the
// grant key signs against the keys those anchors authorize, and ADOPTS the pair. The
// held documents persist to the state dir so a reload re-pins from them.
func TestAgentAdoptsValidSplit(t *testing.T) {
	f := newSplitFixture(t)
	w := newSplitWorker(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	anchorEnv, anchorPayload := f.anchors(t, 1)
	mapEnv := f.routineMap(t, 1, 1, anchorPayload, f.grantPriv, f.grantID)

	w.handleFleetState(ctx, anchorEnv, mapEnv)

	if !w.alreadyPinned() {
		t.Fatal("node did not pin the trust root from the first anchor")
	}
	if got := w.clusterVersion(); got != 1 {
		t.Fatalf("held config version = %d, want 1", got)
	}
	if w.anchorVersion != 1 {
		t.Fatalf("held anchor version = %d, want 1", w.anchorVersion)
	}
	// The trusted grant set is the anchors' grant keys.
	if _, ok := w.trustedKeys()[f.grantID]; !ok {
		t.Fatal("adopted state does not trust the anchors' grant key")
	}
	if !w.st.SplitMode() {
		t.Fatal("state dir was not switched to split mode")
	}
	// The persisted pair re-verifies against the held anchors' own pinned set — the
	// reload integrity check a restart runs before trusting anything.
	if _, err := parseAndCheckFleetState(w.st.AnchorRaw, w.st.RoutineMapRaw, 0, 0); err != nil {
		t.Fatalf("persisted fleet state must re-verify on reload: %v", err)
	}
}

// A routine map SIGNED BY THE GRANT KEY but bound to a forged/absent anchor (wrong
// digest, or wrong version) is REJECTED: the grant key cannot pair its forgery with a
// trust set the node holds. This is the core property the split exists for.
func TestAgentRejectsGrantForgedRoutineMap(t *testing.T) {
	f := newSplitFixture(t)
	w := newSplitWorker(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	anchorEnv, anchorPayload := f.anchors(t, 1)
	good := f.routineMap(t, 1, 1, anchorPayload, f.grantPriv, f.grantID)
	w.handleFleetState(ctx, anchorEnv, good)
	if w.clusterVersion() != 1 {
		t.Fatal("setup: valid split not adopted")
	}

	// Forge a NEWER routine map signed by the real grant key but bound to a DIFFERENT
	// anchor payload (a forged trust set the node never pinned). Same anchor version,
	// different digest.
	forgedAnchors := types.TrustAnchors{
		AnchorVersion: 1,
		GrantKeys: []types.GrantKey{
			{KeyID: f.grantID, PublicKey: f.grantPub},
			{KeyID: "attacker", PublicKey: f.officerPub}, // attacker-added key
		},
		TrustKeys: []types.TrustKey{{KeyID: f.officerID, PublicKey: f.officerPub}},
	}
	forgedPayload, _ := json.Marshal(&forgedAnchors)
	forgedMap := f.routineMap(t, 2, 1, forgedPayload, f.grantPriv, f.grantID)

	// Deliver the forged map paired with the REAL anchor (a grant key cannot author a
	// new anchor, so it must reuse the held one). The digest binding rejects it.
	w.handleFleetState(ctx, anchorEnv, forgedMap)
	if got := w.clusterVersion(); got != 1 {
		t.Fatalf("grant-key-forged routine map (wrong anchor digest) was accepted; version = %d (want 1)", got)
	}

	// A map bound to a non-existent anchor VERSION is likewise rejected.
	wrongVersionMap := f.routineMap(t, 2, 99, anchorPayload, f.grantPriv, f.grantID)
	w.handleFleetState(ctx, anchorEnv, wrongVersionMap)
	if got := w.clusterVersion(); got != 1 {
		t.Fatalf("routine map bound to a wrong anchor version was accepted; version = %d (want 1)", got)
	}
}

// An anchor NOT signed by the pinned trust key (a forged or under-threshold anchor) is
// rejected: the node verifies against its HELD pinned set, never the incoming
// document's own trust keys.
func TestAgentRejectsForgedAnchor(t *testing.T) {
	f := newSplitFixture(t)
	w := newSplitWorker(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Pin the real officer first.
	anchorEnv, anchorPayload := f.anchors(t, 1)
	w.handleFleetState(ctx, anchorEnv, f.routineMap(t, 1, 1, anchorPayload, f.grantPriv, f.grantID))
	if !w.alreadyPinned() {
		t.Fatal("setup: trust root not pinned")
	}

	// An attacker mints a v2 anchor listing THEIR OWN key as the only trust key (the
	// document's own TrustKeys say "trust me") and signs it with that key. It must be
	// rejected: verification is against the HELD pinned officer, not the doc's own set.
	aPub, aPriv, aID, _ := types.GenerateSigningKey()
	attacker := types.TrustAnchors{
		AnchorVersion: 2,
		GrantKeys:     []types.GrantKey{{KeyID: f.grantID, PublicKey: f.grantPub}},
		TrustKeys:     []types.TrustKey{{KeyID: aID, PublicKey: aPub}},
	}
	aPayload, _ := json.Marshal(&attacker)
	aOne, _ := types.SignOne(aPriv, aID, defaults.ContextTrustAnchors, aPayload)
	aEnv, _ := (&types.MultiSigned{Payload: aPayload, Sigs: []types.OneSig{aOne}}).Encode()
	aMap := f.routineMap(t, 2, 2, aPayload, f.grantPriv, f.grantID)

	w.handleFleetState(ctx, aEnv, aMap)
	if got := w.anchorVersion; got != 1 {
		t.Fatalf("anchor signed by a non-pinned key was accepted; anchor version = %d (want 1)", got)
	}
	// The held grant set must still NOT include the attacker's key.
	if _, ok := w.trustedKeys()[aID]; ok {
		t.Fatal("the forged anchor's keys leaked into the held trust set")
	}
}

// A rotation anchor that carries a NEW trust key, signed by the OLD (held) pinned key,
// is accepted and the node re-pins to the new set for the next round.
func TestAgentAdoptsTrustKeyRotation(t *testing.T) {
	f := newSplitFixture(t)
	w := newSplitWorker(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	anchorEnv, anchorPayload := f.anchors(t, 1)
	w.handleFleetState(ctx, anchorEnv, f.routineMap(t, 1, 1, anchorPayload, f.grantPriv, f.grantID))

	// v2 anchors list a NEW officer (n) alongside the old (o), signed by the OLD officer.
	nPub, _, nID, _ := types.GenerateSigningKey()
	rot := types.TrustAnchors{
		AnchorVersion: 2,
		GrantKeys:     []types.GrantKey{{KeyID: f.grantID, PublicKey: f.grantPub}},
		TrustKeys: []types.TrustKey{
			{KeyID: f.officerID, PublicKey: f.officerPub},
			{KeyID: nID, PublicKey: nPub},
		},
	}
	rotPayload, _ := json.Marshal(&rot)
	rotOne, _ := types.SignOne(f.officerPriv, f.officerID, defaults.ContextTrustAnchors, rotPayload)
	rotEnv, _ := (&types.MultiSigned{Payload: rotPayload, Sigs: []types.OneSig{rotOne}}).Encode()
	rotMap := f.routineMap(t, 2, 2, rotPayload, f.grantPriv, f.grantID)

	w.handleFleetState(ctx, rotEnv, rotMap)
	if w.anchorVersion != 2 {
		t.Fatalf("rotation anchor signed by the held key was not adopted; anchor version = %d (want 2)", w.anchorVersion)
	}
	if _, ok := w.pinnedTrust[nID]; !ok {
		t.Fatal("node did not re-pin to the rotated trust set")
	}
}

// A pinned node refuses to regress to a legacy-only push (a downgrade off the anchored
// trust set), while an un-pinned node still accepts the legacy config (migration).
func TestAgentPinnedRefusesLegacyRegression(t *testing.T) {
	f := newSplitFixture(t)
	w := newSplitWorker(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	anchorEnv, anchorPayload := f.anchors(t, 1)
	w.handleFleetState(ctx, anchorEnv, f.routineMap(t, 1, 1, anchorPayload, f.grantPriv, f.grantID))
	if !w.alreadyPinned() {
		t.Fatal("setup: not pinned")
	}

	// A legacy-only push (no split pair) at a higher version must be ignored by a pinned
	// node. Build a legacy config signed by the grant key at v9.
	legacy := signedConfig(t, f.grantPriv, f.grantID, 9)
	w.handleFleetPush(ctx, nil, nil, legacy)
	if got := w.clusterVersion(); got != 1 {
		t.Fatalf("pinned node regressed to a legacy push; version = %d (want 1)", got)
	}
}
