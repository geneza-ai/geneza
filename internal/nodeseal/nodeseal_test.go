package nodeseal

import (
	"bytes"
	"crypto/rand"
	"testing"

	"filippo.io/age"
	"golang.org/x/crypto/curve25519"
)

// nodeKeypair mimics how the Noise/WireGuard layers mint an X25519 keypair: a
// random 32-byte scalar, public = scalar·basepoint. Proving seal/open works on
// such a pair proves it works on the node's real Noise static key.
func nodeKeypair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv = make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestSealOpenRoundTrip(t *testing.T) {
	priv, pub := nodeKeypair(t)
	msg := []byte("-----BEGIN CERTIFICATE----- ... a managed wildcard bundle ...")
	ct, err := Seal(msg, pub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(ct, msg) {
		t.Fatal("ciphertext must not contain the plaintext")
	}
	pt, err := Open(ct, priv)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("round-trip mismatch: %q", pt)
	}
}

func TestOpenWithWrongKeyFails(t *testing.T) {
	_, pub := nodeKeypair(t)
	otherPriv, _ := nodeKeypair(t)
	ct, err := Seal([]byte("secret"), pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ct, otherPriv); err == nil {
		t.Fatal("opening with the wrong key must fail")
	}
}

// TestEncodingMatchesAge is the definitive cross-check: the recipient we derive
// from the raw public key must equal the recipient age itself derives from the
// matching private key. If these agree, our bech32 encoding is byte-compatible
// with age and the Noise key is a valid age X25519 identity.
func TestEncodingMatchesAge(t *testing.T) {
	priv, pub := nodeKeypair(t)
	rs, err := recipientString(pub)
	if err != nil {
		t.Fatal(err)
	}
	is, err := identityString(priv)
	if err != nil {
		t.Fatal(err)
	}
	id, err := age.ParseX25519Identity(is)
	if err != nil {
		t.Fatalf("age rejected our identity encoding: %v", err)
	}
	if got := id.Recipient().String(); got != rs {
		t.Fatalf("recipient mismatch:\n ours: %s\n age:  %s", rs, got)
	}
	if _, err := age.ParseX25519Recipient(rs); err != nil {
		t.Fatalf("age rejected our recipient encoding: %v", err)
	}
}

func TestBadKeyLengths(t *testing.T) {
	if _, err := Seal([]byte("x"), make([]byte, 31)); err == nil {
		t.Error("31-byte pub should fail")
	}
	if _, err := Open([]byte("x"), make([]byte, 33)); err == nil {
		t.Error("33-byte priv should fail")
	}
}
