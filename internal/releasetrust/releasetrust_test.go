package releasetrust

import (
	"crypto/ed25519"
	"os"
	"testing"
	"time"

	"geneza.io/internal/defaults"
	"geneza.io/internal/types"
)

func mustRootKeysV(t *testing.T, rootPriv ed25519.PrivateKey, rootID string, version int64, expires time.Time, authorized ...ed25519.PublicKey) []byte {
	t.Helper()
	rk := types.RootKeys{Version: version, ExpiresAt: expires}
	for _, pub := range authorized {
		rk.Keys = append(rk.Keys, types.ArtifactKey{KeyID: types.KeyIDFor(pub), PublicKey: pub})
	}
	signed, err := types.Sign(rootPriv, rootID, defaults.ContextRootKeys, &rk)
	if err != nil {
		t.Fatal(err)
	}
	b, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifySumsChain(t *testing.T) {
	rootPub, rootPriv, rootID, _ := types.GenerateSigningKey()
	signerPub, signerPriv, _, _ := types.GenerateSigningKey()
	now := time.Now()
	const tag = "v1.2.3"

	rootKeysJSON := mustRootKeysV(t, rootPriv, rootID, 1, now.Add(24*time.Hour), signerPub)
	sums := []byte("deadbeef  geneza_linux_amd64.tar.gz\n")
	signed, err := SignSums(signerPriv, tag, sums)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := signed.Encode()

	// Happy path returns the accepted root-keys version.
	ver, err := verifySumsWith(rootPub, rootKeysJSON, sums, sig, tag, 0, now)
	if err != nil || ver != 1 {
		t.Fatalf("valid chain: ver=%d err=%v", ver, err)
	}

	// Tampered SHA256SUMS -> hash mismatch.
	if _, err := verifySumsWith(rootPub, rootKeysJSON, []byte("tampered\n"), sig, tag, 0, now); err == nil {
		t.Fatal("tampered SHA256SUMS accepted")
	}

	// Wrong release tag -> cross-release replay rejected.
	if _, err := verifySumsWith(rootPub, rootKeysJSON, sums, sig, "v9.9.9", 0, now); err == nil {
		t.Fatal("signature for a different release tag accepted")
	}

	// Root-keys version below the floor -> rollback / signer-revival rejected.
	if _, err := verifySumsWith(rootPub, rootKeysJSON, sums, sig, tag, 2, now); err == nil {
		t.Fatal("rolled-back root-keys (version < floor) accepted")
	}

	// Signature by a key the root never authorized.
	_, attackerPriv, _, _ := types.GenerateSigningKey()
	evil, _ := SignSums(attackerPriv, tag, sums)
	evilSig, _ := evil.Encode()
	if _, err := verifySumsWith(rootPub, rootKeysJSON, sums, evilSig, tag, 0, now); err == nil {
		t.Fatal("signature from an unauthorized signer accepted")
	}

	// Expired root-keys.
	expired := mustRootKeysV(t, rootPriv, rootID, 1, now.Add(-1*time.Hour), signerPub)
	if _, err := verifySumsWith(rootPub, expired, sums, sig, tag, 0, now); err == nil {
		t.Fatal("expired root-keys accepted")
	}

	// Root-keys signed by a different (wrong) root.
	_, otherRootPriv, otherRootID, _ := types.GenerateSigningKey()
	forged := mustRootKeysV(t, otherRootPriv, otherRootID, 1, now.Add(24*time.Hour), signerPub)
	if _, err := verifySumsWith(rootPub, forged, sums, sig, tag, 0, now); err == nil {
		t.Fatal("root-keys signed by the wrong root accepted")
	}
}

func TestVerifySumsNotPinned(t *testing.T) {
	if _, err := verifySumsWith(nil, nil, nil, nil, "", 0, time.Now()); err != ErrNotPinned {
		t.Fatalf("err = %v, want ErrNotPinned", err)
	}
	// Under `go test` the ldflags pin is not injected, so RootPub is nil.
	if RootPub != nil {
		t.Fatal("expected no pinned root under go test (ldflags not injected)")
	}
	if _, err := VerifySums(nil, nil, nil, "", 0, time.Now()); err != ErrNotPinned {
		t.Fatalf("VerifySums err = %v, want ErrNotPinned", err)
	}
}

// TestCommittedRootMatchesRootKeys catches drift between the committed public
// root and the committed signed root-keys.json: the production pin is only set
// via ldflags (never under go test), so without this the real files are never
// verified together.
func TestCommittedRootMatchesRootKeys(t *testing.T) {
	pubPEM, err := os.ReadFile("../../deploy/release/root.pub")
	if err != nil {
		t.Skip("no committed root.pub")
	}
	rootPub, err := types.ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("committed root.pub: %v", err)
	}
	rk, err := os.ReadFile("../../deploy/release/root-keys.json")
	if err != nil {
		t.Skip("no committed root-keys.json")
	}
	signed, err := types.DecodeSigned(rk)
	if err != nil {
		t.Fatalf("committed root-keys.json: %v", err)
	}
	rootTrusted := map[string]ed25519.PublicKey{types.KeyIDFor(rootPub): rootPub}
	if _, err := types.VerifyRootKeys(rootTrusted, signed, 0, time.Now()); err != nil {
		t.Fatalf("committed root-keys.json is not signed by the committed root.pub: %v", err)
	}
}
