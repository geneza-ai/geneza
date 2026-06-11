package types

import (
	"crypto/ed25519"
	"testing"
)

// VerifyOne must fail closed (not panic) on a wrong-size public key or
// signature, since ed25519.Verify panics on a bad key length.
func TestVerifyOneRejectsBadKeySizeWithoutPanic(t *testing.T) {
	pub, priv, keyID, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := Sign(priv, keyID, "manifest", map[string]string{"v": "1"})
	if err != nil {
		t.Fatal(err)
	}
	// Truncated key: must return an error, not panic.
	if err := VerifyOne(ed25519.PublicKey(pub[:10]), "", "manifest", s, nil); err == nil {
		t.Fatal("expected error for short public key")
	}
	// Truncated signature: must return an error, not panic.
	bad := &Signed{Payload: s.Payload, Sig: s.Sig[:10], KeyID: s.KeyID}
	if err := VerifyOne(pub, "", "manifest", bad, nil); err == nil {
		t.Fatal("expected error for short signature")
	}
	// Good key + sig still verifies.
	if err := VerifyOne(pub, keyID, "manifest", s, nil); err != nil {
		t.Fatalf("valid envelope should verify: %v", err)
	}
}
