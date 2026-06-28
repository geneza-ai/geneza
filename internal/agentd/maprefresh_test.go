package agentd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"

	"geneza.io/internal/types"
)

// signedConfig builds a signed cluster-config envelope at version v, signed by
// the given key (which it also lists as both grant and trust key).
func signedConfig(t *testing.T, priv ed25519.PrivateKey, keyID string, v int64) []byte {
	t.Helper()
	cc := types.ClusterConfig{
		ConfigVersion: v,
		GrantKeys:     []types.GrantKey{{KeyID: keyID, PublicKey: ed25519.PublicKey(priv.Public().(ed25519.PublicKey))}},
		TrustKeys:     []types.TrustKey{{KeyID: keyID, PublicKey: ed25519.PublicKey(priv.Public().(ed25519.PublicKey))}},
	}
	env, err := types.Sign(priv, keyID, "cluster-config", cc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Cluster-config adoption now has two concurrent callers — the Stream push and
// the unary map refresh — so the version check and the swap must be atomic: an
// older config must never win a race and roll the held trust set backwards.
// adoptMu guarantees the final held version is the maximum of all adopted ones.
func TestHandleClusterConfigMonotonicUnderConcurrency(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := types.KeyIDFor(pub)
	trust := map[string]ed25519.PublicKey{keyID: pub}

	dir := t.TempDir()
	w := &Worker{
		cfg:         &Config{StateDir: dir, SessionHostSocket: filepath.Join(dir, "host.sock")},
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		st:          &State{Dir: dir},
		cluster:     &types.ClusterConfig{ConfigVersion: 0, GrantKeys: []types.GrantKey{{KeyID: keyID, PublicKey: pub}}, TrustKeys: []types.TrustKey{{KeyID: keyID, PublicKey: pub}}},
		configTrust: trust,
		trusted:     trust,
	}

	// The adopt's final step pushes host policy to the (absent) session host; a
	// pre-cancelled context makes that return immediately instead of waiting out
	// the dial timeout. The adopt itself does not consult the context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	const n = 16
	var wg sync.WaitGroup
	for i := int64(1); i <= n; i++ {
		raw := signedConfig(t, priv, keyID, i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.handleClusterConfig(ctx, raw)
		}()
	}
	wg.Wait()

	if got := w.clusterVersion(); got != n {
		t.Fatalf("after %d concurrent adopts, held version = %d (want %d) — an older config won a race", n, got, int64(n))
	}
}

// A refreshed map signed by a key the agent does not trust, or one older than
// what it holds, must be rejected — the unary refresh path adopts through the
// same pinned-trust verification as a pushed config, so neither a hostile seed
// nor a lagging follower can downgrade the agent.
func TestHandleClusterConfigRejectsUntrustedAndRollback(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyID := types.KeyIDFor(pub)
	trust := map[string]ed25519.PublicKey{keyID: pub}

	dir := t.TempDir()
	w := &Worker{
		cfg:         &Config{StateDir: dir, SessionHostSocket: filepath.Join(dir, "host.sock")},
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		st:          &State{Dir: dir},
		cluster:     &types.ClusterConfig{ConfigVersion: 5, GrantKeys: []types.GrantKey{{KeyID: keyID, PublicKey: pub}}, TrustKeys: []types.TrustKey{{KeyID: keyID, PublicKey: pub}}},
		configTrust: trust,
		trusted:     trust,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// A newer config signed by an UNTRUSTED key is refused (held version unchanged).
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherID := types.KeyIDFor(otherPub)
	w.handleClusterConfig(ctx, signedConfig(t, otherPriv, otherID, 9))
	if got := w.clusterVersion(); got != 5 {
		t.Fatalf("untrusted-key config must be rejected; held version = %d (want 5)", got)
	}

	// A correctly-signed but OLDER config is refused (rollback).
	w.handleClusterConfig(ctx, signedConfig(t, priv, keyID, 3))
	if got := w.clusterVersion(); got != 5 {
		t.Fatalf("rolled-back config must be rejected; held version = %d (want 5)", got)
	}

	// A correctly-signed NEWER config is adopted.
	w.handleClusterConfig(ctx, signedConfig(t, priv, keyID, 7))
	if got := w.clusterVersion(); got != 7 {
		t.Fatalf("valid newer config must be adopted; held version = %d (want 7)", got)
	}

	// Re-delivering the SAME version (the refresh + Stream-reconcile overlap) is a
	// no-op: the held version is unchanged and nothing is re-applied.
	w.handleClusterConfig(ctx, signedConfig(t, priv, keyID, 7))
	if got := w.clusterVersion(); got != 7 {
		t.Fatalf("equal-version re-adopt must be a no-op; held version = %d (want 7)", got)
	}
}
