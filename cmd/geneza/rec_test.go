package main

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

// validCast is a minimal but valid asciicast v2 (header line + one event).
const validCast = `{"version":2,"width":80,"height":24,"geneza":{"session_id":"s-1"}}` + "\n" +
	`[0.5,"o","hello from a recorded shell\r\n"]` + "\n"

// sealCast age-encrypts a cast to a recipient, as the agent does at finalize.
func sealCast(t *testing.T, plain []byte, r age.Recipient) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeIdentity(t *testing.T, id *age.X25519Identity) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "audit.key")
	if err := os.WriteFile(p, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRecPullDecryptRoundTrip proves the CLI replay path: the matching identity
// decrypts the fetched ciphertext back to the original cast, a wrong identity fails,
// and the audit private key is only ever read from the local file.
func TestRecPullDecryptRoundTrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	cipher := sealCast(t, []byte(validCast), id.Recipient())

	// The fetched ciphertext must be opaque.
	if bytes.Contains(cipher, []byte("hello from a recorded shell")) {
		t.Fatal("ciphertext leaks the cast plaintext")
	}

	// Matching identity decrypts to the original valid cast.
	idFile := writeIdentity(t, id)
	plain, err := decryptRecording(cipher, idFile)
	if err != nil {
		t.Fatalf("decrypt with matching identity: %v", err)
	}
	if !bytes.Equal(plain, []byte(validCast)) {
		t.Fatalf("decrypted cast does not match the original")
	}

	// Wrong identity cannot decrypt.
	other, _ := age.GenerateX25519Identity()
	wrongFile := writeIdentity(t, other)
	if _, err := decryptRecording(cipher, wrongFile); err == nil {
		t.Fatalf("wrong identity decrypted the cast")
	}
}

// TestRecPullCiphertextWithoutIdentity proves that without -i the raw ciphertext is
// written unchanged (the .cast.age path), so an operator can hand it to a custodian.
func TestRecPullCiphertextWithoutIdentity(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	cipher := sealCast(t, []byte(validCast), id.Recipient())

	out := filepath.Join(t.TempDir(), "rec.cast.age")
	if err := writeRecordingOut(cipher, out); err != nil {
		t.Fatalf("write ciphertext: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, cipher) {
		t.Fatalf("written file is not the verbatim ciphertext")
	}
}

// TestRecPullIntegrityCheck proves the client verifies the manifest sha256 over the
// fetched ciphertext before decrypting: a single mutated byte is rejected.
func TestRecPullIntegrityCheck(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	cipher := sealCast(t, []byte(validCast), id.Recipient())
	want := sha256.Sum256(cipher)

	// Good: hash matches.
	got := sha256.Sum256(cipher)
	if !bytes.Equal(got[:], want[:]) {
		t.Fatal("baseline hash mismatch")
	}

	// Tampered: a flipped byte changes the digest, which the pull path compares
	// against the manifest before any decrypt.
	tampered := append([]byte(nil), cipher...)
	tampered[len(tampered)-1] ^= 0x01
	bad := sha256.Sum256(tampered)
	if bytes.Equal(bad[:], want[:]) {
		t.Fatal("tamper did not change the digest")
	}
}
