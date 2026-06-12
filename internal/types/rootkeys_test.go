package types

import (
	"crypto/ed25519"
	"testing"
	"time"
)

type signer struct {
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	keyID string
}

func newSigner(t *testing.T) signer {
	t.Helper()
	pub, priv, id, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return signer{pub, priv, id}
}

func (s signer) artifactKey() ArtifactKey { return ArtifactKey{KeyID: s.keyID, PublicKey: s.pub} }

// signRootKeys signs a RootKeys doc with the given root signer.
func signRootKeys(t *testing.T, root signer, version int64, expires time.Time, keys ...ArtifactKey) *Signed {
	t.Helper()
	s, err := Sign(root.priv, root.keyID, contextRootKeys, &RootKeys{Version: version, Keys: keys, ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func signManifest(t *testing.T, by signer, version string, createdAt time.Time) *Signed {
	t.Helper()
	m := &Manifest{Product: "geneza-agent", Version: version, OS: "linux", Arch: "amd64",
		SHA256: "abc", Size: 1, CreatedAt: createdAt}
	s, err := Sign(by.priv, by.keyID, contextManifestForChain, m)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestArtifactChain_HappyPath(t *testing.T) {
	root := newSigner(t)
	sk := newSigner(t)
	pinned := map[string]ed25519.PublicKey{root.keyID: root.pub}
	now := time.Now()

	rk := signRootKeys(t, root, 1, now.Add(24*time.Hour), sk.artifactKey())
	mf := signManifest(t, sk, "1.0.0", now)

	_, m, err := VerifyArtifactChain(pinned, rk, mf, 0, now)
	if err != nil {
		t.Fatalf("valid chain must verify: %v", err)
	}
	if m.Version != "1.0.0" {
		t.Fatalf("wrong manifest: %+v", m)
	}
}

func TestArtifactChain_ForeignSignerRejected(t *testing.T) {
	root := newSigner(t)
	sk := newSigner(t)
	attacker := newSigner(t) // never listed in root-keys
	pinned := map[string]ed25519.PublicKey{root.keyID: root.pub}
	now := time.Now()

	rk := signRootKeys(t, root, 1, now.Add(24*time.Hour), sk.artifactKey())
	mf := signManifest(t, attacker, "9.9.9", now) // signed by a key the root never authorized

	if _, _, err := VerifyArtifactChain(pinned, rk, mf, 0, now); err == nil {
		t.Fatal("manifest signed by an unauthorized key must be rejected")
	}
}

func TestArtifactChain_RoleSeparation_RootCannotSignManifest(t *testing.T) {
	root := newSigner(t)
	sk := newSigner(t)
	pinned := map[string]ed25519.PublicKey{root.keyID: root.pub}
	now := time.Now()

	rk := signRootKeys(t, root, 1, now.Add(24*time.Hour), sk.artifactKey())
	mf := signManifest(t, root, "1.0.0", now) // root key tries to sign a release directly

	if _, _, err := VerifyArtifactChain(pinned, rk, mf, 0, now); err == nil {
		t.Fatal("a manifest signed by the ROOT key (not a listed signing key) must be rejected")
	}
}

func TestArtifactChain_ForeignRootRejected(t *testing.T) {
	realRoot := newSigner(t)
	fakeRoot := newSigner(t)
	sk := newSigner(t)
	pinned := map[string]ed25519.PublicKey{realRoot.keyID: realRoot.pub}
	now := time.Now()

	rk := signRootKeys(t, fakeRoot, 1, now.Add(24*time.Hour), sk.artifactKey()) // signed by the WRONG root
	mf := signManifest(t, sk, "1.0.0", now)

	if _, _, err := VerifyArtifactChain(pinned, rk, mf, 0, now); err == nil {
		t.Fatal("root-keys signed by a non-pinned root must be rejected")
	}
}

func TestArtifactChain_KeyRotation(t *testing.T) {
	root := newSigner(t)
	oldKey := newSigner(t)
	newKey := newSigner(t)
	pinned := map[string]ed25519.PublicKey{root.keyID: root.pub}
	now := time.Now()
	exp := now.Add(24 * time.Hour)

	// v1: only oldKey is trusted.
	rkV1 := signRootKeys(t, root, 1, exp, oldKey.artifactKey())
	// v2 (rotation): drop oldKey, trust newKey. Signed by the same offline root.
	rkV2 := signRootKeys(t, root, 2, exp, newKey.artifactKey())

	// After rotation to v2, a manifest by newKey verifies...
	if _, _, err := VerifyArtifactChain(pinned, rkV2, signManifest(t, newKey, "2.0.0", now), 1, now); err != nil {
		t.Fatalf("rotated-in key must be trusted: %v", err)
	}
	// ...and a manifest by the RETIRED oldKey is rejected under v2.
	if _, _, err := VerifyArtifactChain(pinned, rkV2, signManifest(t, oldKey, "2.0.0", now), 1, now); err == nil {
		t.Fatal("a retired signing key must be rejected after rotation")
	}
	// And a node that has already accepted v2 refuses to roll back to v1.
	if _, err := VerifyRootKeys(pinned, rkV1, 2 /*held*/, now); err == nil {
		t.Fatal("root-keys rollback (v1 when v2 held) must be rejected")
	}
}

func TestArtifactChain_ExpiredRootRejected(t *testing.T) {
	root := newSigner(t)
	sk := newSigner(t)
	pinned := map[string]ed25519.PublicKey{root.keyID: root.pub}
	now := time.Now()

	rk := signRootKeys(t, root, 1, now.Add(-time.Hour), sk.artifactKey()) // already expired
	mf := signManifest(t, sk, "1.0.0", now)

	if _, _, err := VerifyArtifactChain(pinned, rk, mf, 0, now); err == nil {
		t.Fatal("expired root-keys must be rejected (anti-freeze)")
	}
}

func TestArtifactChain_TamperedManifestRejected(t *testing.T) {
	root := newSigner(t)
	sk := newSigner(t)
	pinned := map[string]ed25519.PublicKey{root.keyID: root.pub}
	now := time.Now()

	rk := signRootKeys(t, root, 1, now.Add(24*time.Hour), sk.artifactKey())
	mf := signManifest(t, sk, "1.0.0", now)
	mf.Payload = append([]byte(nil), mf.Payload...)
	mf.Payload[10] ^= 0xFF // flip a byte after signing

	if _, _, err := VerifyArtifactChain(pinned, rk, mf, 0, now); err == nil {
		t.Fatal("a tampered manifest payload must fail signature verification")
	}
}

func TestArtifactChain_OverlapDuringRotation(t *testing.T) {
	root := newSigner(t)
	oldKey := newSigner(t)
	newKey := newSigner(t)
	pinned := map[string]ed25519.PublicKey{root.keyID: root.pub}
	now := time.Now()
	exp := now.Add(24 * time.Hour)

	// Overlap window: BOTH keys listed — either can sign while you migrate CI.
	rk := signRootKeys(t, root, 2, exp, oldKey.artifactKey(), newKey.artifactKey())
	for _, s := range []signer{oldKey, newKey} {
		if _, _, err := VerifyArtifactChain(pinned, rk, signManifest(t, s, "2.0.0", now), 0, now); err != nil {
			t.Fatalf("both overlapped keys must verify during rotation: %v", err)
		}
	}
}
