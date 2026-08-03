package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"geneza.io/internal/ca"
	"geneza.io/internal/types"
)

// The cross-controller web-shell hop mints a user cert for the console user. The
// pin it carries is what stops the owning controller from re-classifying the
// session as native — without it, a require_native target would be reachable
// over the web path whenever the load balancer landed on a non-owner controller.
func TestWebProxyCertCarriesTheWebPathPin(t *testing.T) {
	srv, _, _ := buildLaunchServer(t, EmbedConfig{})
	u := &consoleUser{
		Name: "alice", Provider: providerKeystone, Subject: "ks-alice",
		Workspace: defaultWorkspace, Roles: []string{"ws-viewer"},
	}
	pair, err := srv.mintWebProxyCert(u)
	if err != nil {
		t.Fatalf("mint proxy cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	id, err := ca.PeerIdentity(leaf)
	if err != nil {
		t.Fatalf("peer identity: %v", err)
	}
	if id.ClientPath != types.PathWeb {
		t.Fatalf("proxy cert must pin the web path, got %q", id.ClientPath)
	}
	// It must still be the console user, not the controller: the owner authorizes
	// the human, and the audit trail names them.
	if id.Kind != ca.KindUser || id.Name != "alice" || id.Subject != "ks-alice" {
		t.Fatalf("proxy cert must carry the console user's identity: %+v", id)
	}
	if id.Workspace != defaultWorkspace {
		t.Fatalf("proxy cert workspace = %q", id.Workspace)
	}
	// Short-lived by construction — it only has to survive one re-broker.
	if d := leaf.NotAfter.Sub(leaf.NotBefore); d > 2*webRedirectCertTTL {
		t.Fatalf("proxy cert TTL %s is too long for a single re-broker", d)
	}
}

// An ORDINARY user cert (the CLI's) must carry no pin, so it keeps being brokered
// as native. The pin is opt-in and only ever narrows.
func TestOrdinaryUserCertHasNoPathPin(t *testing.T) {
	srv, _, _ := buildLaunchServer(t, EmbedConfig{})
	u := &consoleUser{
		Name: "bob", Provider: providerLocal, Subject: "bob",
		Workspace: defaultWorkspace, Roles: []string{"ws-viewer"},
	}
	certPEM, _, err := srv.issueUserCert(u.Provider, u.Name, u.Subject, u.Workspace, u.Roles, freshCSR(t, u.Name), 0)
	if err != nil {
		t.Fatalf("issue ordinary user cert: %v", err)
	}
	blk, _ := pem.Decode(certPEM)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	id, err := ca.PeerIdentity(c)
	if err != nil {
		t.Fatal(err)
	}
	if id.ClientPath != "" {
		t.Fatalf("an ordinary user cert must carry no client-path pin, got %q", id.ClientPath)
	}
}

func freshCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
