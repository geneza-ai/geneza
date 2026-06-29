package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"geneza.io/internal/ca"
)

// newTestCA initializes a throwaway CA and returns it.
func newTestCA(t *testing.T) *ca.CA {
	t.Helper()
	dir := t.TempDir()
	if err := ca.Init(dir, "test"); err != nil {
		t.Fatalf("ca init: %v", err)
	}
	c, err := ca.Load(dir)
	if err != nil {
		t.Fatalf("ca load: %v", err)
	}
	return c
}

// relayWithCert builds a Relay whose identity cert (TTL ttl) is on disk and loaded.
func relayWithCert(t *testing.T, c *ca.CA, id string, ttl time.Duration) (*Relay, string) {
	t.Helper()
	certPEM, keyPEM, err := c.IssueServerKeypair(ca.Profile{Kind: ca.KindRelay, Name: id, TTL: ttl})
	if err != nil {
		t.Fatalf("issue relay keypair: %v", err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "relay.crt"), filepath.Join(dir, "relay.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	r := New(Config{RelayID: id, CertFile: certFile, KeyFile: keyFile}, nil)
	if err := r.ensureIDCert(); err != nil {
		t.Fatalf("ensureIDCert: %v", err)
	}
	return r, certFile
}

func TestRenewalCSRThreshold(t *testing.T) {
	c := newTestCA(t)

	fresh, _ := relayWithCert(t, c, "relay-fresh", 2*365*24*time.Hour)
	if fresh.renewalCSR() != nil {
		t.Error("a fresh (2y) cert must not request renewal")
	}

	near, _ := relayWithCert(t, c, "relay-near", 30*time.Second) // already past 2/3 of its short life
	if near.renewalCSR() == nil {
		t.Error("a near-expiry cert must request renewal")
	}
}

func TestInstallRenewedCertHotSwapsSameKey(t *testing.T) {
	c := newTestCA(t)
	r, certFile := relayWithCert(t, c, "relay-1", 30*time.Second)

	before := r.idCert.Load()
	oldPubDER, _ := x509.MarshalPKIXPublicKey(before.Leaf.PublicKey)

	csr := r.renewalCSR()
	if csr == nil {
		t.Fatal("expected a renewal CSR")
	}
	renewed, err := c.IssueFromCSR(csr, ca.Profile{Kind: ca.KindRelay, Name: "relay-1", TTL: 2 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("sign renewal: %v", err)
	}
	r.installRenewedCert(renewed, c.RootsPEM)

	after := r.idCert.Load()
	if !after.Leaf.NotAfter.After(before.Leaf.NotAfter) {
		t.Error("renewed cert should extend NotAfter")
	}
	newPubDER, _ := x509.MarshalPKIXPublicKey(after.Leaf.PublicKey)
	if string(oldPubDER) != string(newPubDER) {
		t.Error("renewal must keep the same key (agent pins are SPKI-based)")
	}
	if after.PrivateKey != before.PrivateKey {
		t.Error("private key object should be reused, not replaced")
	}
	// Persisted, so a restart keeps the renewal.
	onDisk, _ := os.ReadFile(certFile)
	if blk, _ := pem.Decode(onDisk); blk == nil {
		t.Error("renewed cert was not persisted to disk")
	}
}

// TestInstallRejectsKeyMismatch proves a renewed cert that does NOT bind the held
// key is refused (defense against a controller bug), keeping the current cert live.
func TestInstallRejectsKeyMismatch(t *testing.T) {
	c := newTestCA(t)
	r, _ := relayWithCert(t, c, "relay-1", 2*365*24*time.Hour)
	before := r.idCert.Load()

	// A cert minted over a DIFFERENT key (CSR from a stranger key).
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	foreignCSR, _ := ca.MakeCSR(otherKey, "relay-1")
	foreign, err := c.IssueFromCSR(foreignCSR, ca.Profile{Kind: ca.KindRelay, Name: "relay-1", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	r.installRenewedCert(foreign, c.RootsPEM)

	if r.idCert.Load() != before {
		t.Error("a key-mismatched cert must not replace the held cert")
	}
}

// TestRenewalIgnoresCSRSubject is the security crux: the renewed cert's identity
// comes from the controller-assigned profile, never the CSR subject, so a relay
// cannot rename itself to another relay's identity via renewal.
func TestRenewalIgnoresCSRSubject(t *testing.T) {
	c := newTestCA(t)
	attackerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	forged, err := ca.MakeCSR(attackerKey, "victim-relay") // CSR claims a different identity
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := c.IssueFromCSR(forged, ca.Profile{Kind: ca.KindRelay, Name: "caller-relay", TTL: time.Hour})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	blk, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := leaf.URIs[0].String(); got != "geneza://relay/caller-relay" {
		t.Errorf("identity must be the assigned caller-relay, got %q", got)
	}
}
