package agentd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
)

func TestPinRelayCert(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(pub)

	// A leaf whose key is in the map is accepted.
	if err := pinRelayCert([][]byte{spki})([][]byte{der}, nil); err != nil {
		t.Fatalf("relay cert in the map should be accepted: %v", err)
	}
	// A leaf whose key is NOT in the map is rejected (the rogue-relay gate).
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	otherSPKI, _ := x509.MarshalPKIXPublicKey(otherPub)
	if err := pinRelayCert([][]byte{otherSPKI})([][]byte{der}, nil); err == nil {
		t.Fatal("a relay cert not in the signed map must be rejected")
	}
	// No certificate is rejected.
	if err := pinRelayCert([][]byte{spki})(nil, nil); err == nil {
		t.Fatal("a relay presenting no certificate must be rejected")
	}
}
