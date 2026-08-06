package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

// `geneza audit rec pull` used to check only the sha256 — a digest served in the
// same response, by the same party, as the bytes. That proves transport integrity
// and nothing about who produced the recording. The node's signature is the part a
// controller cannot forge; this asserts the CLI actually checks it.
func TestRecPullVerifiesTheNodeSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	const sessionID = "s-aaaaaaaaaaaa"
	cipher := []byte("sealed-cast-bytes")
	sum := sha256.Sum256(cipher)
	size := int64(len(cipher))
	const ended = int64(1700)

	sign := func(sha string, sz, end int64) []byte {
		sig, serr := ecdsa.SignASN1(rand.Reader, key,
			types.RecordingManifestDigest(sessionID, sha, sz, end))
		if serr != nil {
			t.Fatal(serr)
		}
		return sig
	}
	good := &genezav1.RecordingManifest{
		Sha256: sum[:], SizeBytes: size, EndedUnix: ended,
		NodeSig: sign(hex.EncodeToString(sum[:]), size, ended), NodeSpki: spki,
	}
	if err := verifyRecordingManifestSig(sessionID, good); err != nil {
		t.Fatalf("a genuine manifest must verify: %v", err)
	}

	// A controller that swaps the blob and re-states its own sha256 gets caught
	// here, because it cannot re-sign without the node's key.
	other := sha256.Sum256([]byte("substituted bytes"))
	swapped := &genezav1.RecordingManifest{
		Sha256: other[:], SizeBytes: size, EndedUnix: ended,
		NodeSig: good.NodeSig, NodeSpki: spki,
	}
	if err := verifyRecordingManifestSig(sessionID, swapped); err == nil {
		t.Fatal("a substituted blob with a re-stated sha256 passed verification")
	}

	// Same for a different session claiming this recording.
	if err := verifyRecordingManifestSig("s-bbbbbbbbbbbb", good); err == nil {
		t.Fatal("a signature transferred to another session passed verification")
	}

	// A key that is not a key must be reported, not ignored.
	bogus := &genezav1.RecordingManifest{
		Sha256: sum[:], SizeBytes: size, EndedUnix: ended,
		NodeSig: good.NodeSig, NodeSpki: []byte("not-a-key"),
	}
	if err := verifyRecordingManifestSig(sessionID, bogus); err == nil ||
		!strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("an unreadable node key must be an error, got %v", err)
	}

	// A recording stored before the key was retained carries no key. That is
	// "unchecked", not "failed" — the caller warns; it must not block the pull.
	legacy := &genezav1.RecordingManifest{
		Sha256: sum[:], SizeBytes: size, EndedUnix: ended, NodeSig: good.NodeSig,
	}
	if err := verifyRecordingManifestSig(sessionID, legacy); err != nil {
		t.Fatalf("a pre-upgrade recording must still be pullable: %v", err)
	}
}
