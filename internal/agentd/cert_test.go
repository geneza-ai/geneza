package agentd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"geneza.io/internal/nodeseal"
	genezav1 "geneza.io/internal/pb/geneza/v1"
)

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

// makeBundle builds a self-signed cert (key first, then chain) for the given SANs.
func makeBundle(t *testing.T, names ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     names,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return append(keyPEM, certPEM...)
}

func sealedCert(t *testing.T, pub []byte, zone string, epoch int64, names ...string) *genezav1.SealedCert {
	t.Helper()
	sealed, err := nodeseal.Seal(makeBundle(t, names...), pub)
	if err != nil {
		t.Fatal(err)
	}
	return &genezav1.SealedCert{Zone: zone, Sealed: sealed, Epoch: epoch}
}

func TestCertManagerReconcile(t *testing.T) {
	priv, pub := nodeKeypair(t)
	dir := t.TempDir()
	m := newCertManager(slog.Default(), dir, priv)

	zone := "acme.geneza.app"
	m.reconcile(&genezav1.CertBundle{Version: 1, Certs: []*genezav1.SealedCert{
		sealedCert(t, pub, zone, 1, "*."+zone, zone),
	}})

	if zs := m.zones(); len(zs) != 1 || zs[0] != zone {
		t.Fatalf("zones = %v", zs)
	}
	// The bundle is written to disk.
	if _, err := os.Stat(m.bundlePath(zone)); err != nil {
		t.Fatalf("bundle not persisted: %v", err)
	}

	// SNI matching: apex and one-label-below hit; two-labels-below and a foreign
	// name miss.
	for _, sni := range []string{zone, "app." + zone} {
		if _, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: sni}); err != nil {
			t.Errorf("GetCertificate(%q): %v", sni, err)
		}
	}
	for _, sni := range []string{"a.b." + zone, "other.com"} {
		if _, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: sni}); err == nil {
			t.Errorf("GetCertificate(%q) should miss", sni)
		}
	}
}

func TestCertManagerDeclarativeDrop(t *testing.T) {
	priv, pub := nodeKeypair(t)
	m := newCertManager(slog.Default(), t.TempDir(), priv)
	z1, z2 := "a.geneza.app", "b.geneza.app"
	m.reconcile(&genezav1.CertBundle{Certs: []*genezav1.SealedCert{
		sealedCert(t, pub, z1, 1, "*."+z1, z1),
		sealedCert(t, pub, z2, 1, "*."+z2, z2),
	}})
	if len(m.zones()) != 2 {
		t.Fatalf("want 2 zones, got %v", m.zones())
	}
	// A push that omits z2 drops it (release), and its file is removed.
	m.reconcile(&genezav1.CertBundle{Certs: []*genezav1.SealedCert{
		sealedCert(t, pub, z1, 1, "*."+z1, z1),
	}})
	if zs := m.zones(); len(zs) != 1 || zs[0] != z1 {
		t.Fatalf("after drop, zones = %v", zs)
	}
	if _, err := os.Stat(m.bundlePath(z2)); !os.IsNotExist(err) {
		t.Errorf("dropped cert's file should be gone, stat err = %v", err)
	}
}

func TestCertManagerWrongKeyIgnored(t *testing.T) {
	priv, _ := nodeKeypair(t)
	_, otherPub := nodeKeypair(t)
	m := newCertManager(slog.Default(), t.TempDir(), priv)
	zone := "x.geneza.app"
	// Sealed to a DIFFERENT node's key: this node can't unseal it, so nothing is
	// installed (and no panic).
	m.reconcile(&genezav1.CertBundle{Certs: []*genezav1.SealedCert{
		sealedCert(t, otherPub, zone, 1, "*."+zone, zone),
	}})
	if len(m.zones()) != 0 {
		t.Fatalf("a cert we cannot unseal must not install: %v", m.zones())
	}
}
