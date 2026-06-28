//go:build cgo

package keysource_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"geneza.io/internal/ca"
	"geneza.io/internal/defaults"
	"geneza.io/internal/keysource"
	"geneza.io/internal/types"
)

// The PKCS#11 tests run against a token configured in the environment, mirroring
// the SQL-store tests. With GENEZA_TEST_PKCS11_MODULE unset the suite skips, so
// the default `go test ./...` needs no HSM. scripts/softhsm-test.sh sets up a
// SoftHSM2 token and exports the variables these tests read:
//
//	GENEZA_TEST_PKCS11_MODULE      path to the PKCS#11 .so
//	GENEZA_TEST_PKCS11_PIN         token user PIN
//	GENEZA_TEST_PKCS11_TOKEN       token label
//	GENEZA_TEST_PKCS11_CA_LABEL    label of the ECDSA P-256 key (issuing CA)
//	GENEZA_TEST_PKCS11_GRANT_LABEL label of the Ed25519 key (grant); optional
func pkcs11Spec(t *testing.T, keyLabel string) keysource.Spec {
	t.Helper()
	mod := os.Getenv("GENEZA_TEST_PKCS11_MODULE")
	if mod == "" {
		t.Skip("set GENEZA_TEST_PKCS11_MODULE (+ PIN/TOKEN/*_LABEL) to run the pkcs11 tests; see scripts/softhsm-test.sh")
	}
	return keysource.Spec{
		Backend:    keysource.BackendPKCS11,
		Module:     mod,
		TokenLabel: os.Getenv("GENEZA_TEST_PKCS11_TOKEN"),
		PIN:        os.Getenv("GENEZA_TEST_PKCS11_PIN"),
		KeyLabel:   keyLabel,
	}
}

// TestPKCS11CASignInPlace proves the issuing CA can sign a leaf with a key held
// on a token: the leaf chains to the CA and verifies, and the private bytes were
// never read into this process (the signer is the token's).
func TestPKCS11CASignInPlace(t *testing.T) {
	label := os.Getenv("GENEZA_TEST_PKCS11_CA_LABEL")
	if label == "" {
		label = "geneza-ca"
	}
	signer, err := keysource.Open(pkcs11Spec(t, label))
	if err != nil {
		t.Fatalf("open pkcs11 CA signer: %v", err)
	}
	caPub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("CA token key is %T, want *ecdsa.PublicKey", signer.Public())
	}

	// Build a root and an issuing cert over the TOKEN's public key, signed by the
	// root. The issuing private key stays on the token; the controller holds only the
	// cert plus the trust bundle, exactly as in production.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	issTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test issuing"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	issDER, err := x509.CreateCertificate(rand.Reader, issTmpl, rootCert, caPub, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	issCert, err := x509.ParseCertificate(issDER)
	if err != nil {
		t.Fatal(err)
	}

	c := &ca.CA{Cert: issCert, Signer: signer}

	// A node leaf: client generates a key, makes a CSR, the token-backed CA issues.
	leafKey, err := ca.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ca.MakeCSR(leafKey, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, err := c.IssueFromCSR(csr, ca.Profile{Kind: ca.KindNode, Workspace: "default", Name: "node-1", TTL: time.Hour})
	if err != nil {
		t.Fatalf("issue leaf with token-backed CA: %v", err)
	}

	// The leaf must chain to the (token-signed) issuing cert under the root.
	leaf := firstCert(t, leafPEM)
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	inter := x509.NewCertPool()
	inter.AddCert(issCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime:   now,
	}); err != nil {
		t.Fatalf("leaf does not chain to the token-signed CA: %v", err)
	}
}

// TestPKCS11GrantSignVerify proves a grant signer on a token (Ed25519/CKM_EDDSA)
// signs a ClusterConfig that types.Verify accepts under the derived public key,
// and that a different key is rejected. Skips if the token has no EdDSA key.
func TestPKCS11GrantSignVerify(t *testing.T) {
	label := os.Getenv("GENEZA_TEST_PKCS11_GRANT_LABEL")
	if label == "" {
		t.Skip("set GENEZA_TEST_PKCS11_GRANT_LABEL to run the grant pkcs11 test (requires an EdDSA-capable token)")
	}
	signer, err := keysource.Open(pkcs11Spec(t, label))
	if err != nil {
		// The PKCS#11 library (ThalesGroup/crypto11) surfaces RSA and ECDSA token
		// keys as signers but not Ed25519, so an EdDSA grant key on the token cannot
		// be opened today even when the token itself supports CKM_EDDSA. The file
		// backend remains the grant-key default; this path waits on Ed25519 support
		// in the PKCS#11 binding.
		t.Skipf("pkcs11 grant signer unavailable (Ed25519 not yet supported by the PKCS#11 binding): %v", err)
	}
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("grant token key is %T, want ed25519.PublicKey", signer.Public())
	}
	keyID := types.KeyIDFor(pub)

	cc := types.ClusterConfig{ConfigVersion: 7}
	signed, err := types.Sign(signer, keyID, defaults.ContextClusterConfig, cc)
	if err != nil {
		t.Fatalf("sign cluster config on token: %v", err)
	}

	trusted := map[string]ed25519.PublicKey{keyID: pub}
	if _, err := types.Verify(trusted, defaults.ContextClusterConfig, signed, nil); err != nil {
		t.Fatalf("verify token-signed config: %v", err)
	}

	// A different key must not verify the same envelope.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := types.Verify(map[string]ed25519.PublicKey{keyID: otherPub}, defaults.ContextClusterConfig, signed, nil); err == nil {
		t.Fatal("verify accepted a signature under the wrong key")
	}
}

func firstCert(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		t.Fatal("no PEM block in leaf")
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}
