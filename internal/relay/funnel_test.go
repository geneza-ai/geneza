package relay

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
	"testing"
	"time"

	"geneza.io/internal/nodeseal"
	genezav1 "geneza.io/internal/pb/geneza/v1"
)

func makeBundle(t *testing.T, host string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{host},
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

func sealedFor(t *testing.T, f *funnelCerts, host string, epoch int64) *genezav1.SealedCert {
	t.Helper()
	sealed, err := nodeseal.Seal(makeBundle(t, host), f.sealPub())
	if err != nil {
		t.Fatal(err)
	}
	return &genezav1.SealedCert{Zone: host, Sealed: sealed, Epoch: epoch}
}

func TestFunnelCertsApplyAndServe(t *testing.T) {
	f, err := newFunnelCerts(slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.sealPub()) != 32 {
		t.Fatalf("seal pub must be 32 bytes, got %d", len(f.sealPub()))
	}

	host := "app.acme.geneza.app"
	f.apply([]*genezav1.SealedCert{sealedFor(t, f, host, 1)})
	if hs := f.hosts(); len(hs) != 1 || hs[0] != host {
		t.Fatalf("hosts = %v", hs)
	}
	// Exact-SNI match hits; anything else misses (narrow leaf).
	if _, err := f.GetCertificate(&tls.ClientHelloInfo{ServerName: host}); err != nil {
		t.Errorf("GetCertificate(%q): %v", host, err)
	}
	for _, sni := range []string{"other.acme.geneza.app", "acme.geneza.app", "evil.com"} {
		if _, err := f.GetCertificate(&tls.ClientHelloInfo{ServerName: sni}); err == nil {
			t.Errorf("GetCertificate(%q) should miss (narrow leaf)", sni)
		}
	}

	// Declarative: a push omitting the host drops it.
	f.apply(nil)
	if hs := f.hosts(); len(hs) != 0 {
		t.Fatalf("empty push should clear, got %v", hs)
	}
}

func TestFunnelCertsWrongKeyIgnored(t *testing.T) {
	f, _ := newFunnelCerts(slog.Default())
	other, _ := newFunnelCerts(slog.Default())
	// Sealed to a DIFFERENT relay's key: this relay can't unseal, installs nothing.
	f.apply([]*genezav1.SealedCert{sealedFor(t, other, "x.geneza.app", 1)})
	if hs := f.hosts(); len(hs) != 0 {
		t.Fatalf("a cert we cannot unseal must not install: %v", hs)
	}
}
