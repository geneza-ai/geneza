package controller

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"io"
	"math/big"
	"strings"
	"testing"

	"filippo.io/age"

	"geneza.io/internal/ca"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

// certFor wraps an ECDSA public key in a minimal certificate, standing in for the
// node leaf the upload interceptor would surface.
func certFor(t *testing.T, pub *ecdsa.PublicKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, mustECDSA(t))
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func mustECDSA(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ca.GenerateKey()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return k
}

// TestRecordingCiphertextRoundTrip proves the encryption boundary: a cast sealed
// to a recipient is opaque at rest, decrypts back to the original under the
// matching identity, and any single-byte tamper fails the AEAD.
func TestRecordingCiphertextRoundTrip(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte(`{"version":2,"width":80,"height":24,"geneza":{"session_id":"s-1"}}` + "\n" +
		`[0.1,"o","secret output"]` + "\n")

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	cipher := buf.Bytes()

	if bytes.Contains(cipher, []byte("secret output")) || bytes.Contains(cipher, []byte(`"version"`)) {
		t.Fatalf("ciphertext leaks plaintext")
	}

	dr, err := age.Decrypt(bytes.NewReader(cipher), identity)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	got, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch")
	}

	// Flip a byte well past the age header so we hit the encrypted payload's AEAD.
	tampered := append([]byte(nil), cipher...)
	tampered[len(tampered)-1] ^= 0x01
	if dr2, err := age.Decrypt(bytes.NewReader(tampered), identity); err == nil {
		if _, err := io.ReadAll(dr2); err == nil {
			t.Fatalf("tampered ciphertext decrypted without error")
		}
	}

	// A different identity cannot decrypt at all.
	other, _ := age.GenerateX25519Identity()
	if _, err := age.Decrypt(bytes.NewReader(cipher), other); err == nil {
		t.Fatalf("wrong identity decrypted the cast")
	}
}

// TestRecordingManifestSignature proves the node attestation: a signature over the
// canonical digest verifies against the node cert, and a wrong key or a tampered
// field fails.
func TestRecordingManifestSignature(t *testing.T) {
	nodeKey := mustECDSA(t)
	cert := certFor(t, &nodeKey.PublicKey)

	const sessionID = "s-aaaaaaaaaaaa"
	cipher := []byte("ciphertext-blob")
	sum := sha256.Sum256(cipher)
	shaHex := hex.EncodeToString(sum[:])
	size := int64(len(cipher))
	const ended = int64(1700)

	digest := types.RecordingManifestDigest(sessionID, shaHex, size, ended)
	sig, err := ecdsa.SignASN1(rand.Reader, nodeKey, digest)
	if err != nil {
		t.Fatal(err)
	}
	man := &genezav1.RecordingManifest{Sha256: sum[:], SizeBytes: size, NodeSig: sig, EndedUnix: ended}

	if err := verifyRecordingSig(cert, sessionID, shaHex, size, man); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	// Wrong key: a signature by a different node fails against this cert.
	otherKey := mustECDSA(t)
	badSig, _ := ecdsa.SignASN1(rand.Reader, otherKey, digest)
	badMan := &genezav1.RecordingManifest{Sha256: sum[:], SizeBytes: size, NodeSig: badSig, EndedUnix: ended}
	if err := verifyRecordingSig(cert, sessionID, shaHex, size, badMan); err == nil {
		t.Fatalf("signature by a different key verified")
	}

	// Tampered hash: the digest changes, so the original signature no longer matches.
	if err := verifyRecordingSig(cert, sessionID, strings.Repeat("0", 64), size, man); err == nil {
		t.Fatalf("signature verified over a tampered hash")
	}
	// Tampered finish time likewise.
	manT := &genezav1.RecordingManifest{Sha256: sum[:], SizeBytes: size, NodeSig: sig, EndedUnix: ended + 1}
	if err := verifyRecordingSig(cert, sessionID, shaHex, size, manT); err == nil {
		t.Fatalf("signature verified over a tampered finish time")
	}
}
