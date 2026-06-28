package agentd

import (
	"crypto"
	"crypto/ecdsa"
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
	"geneza.io/internal/keysource"
	"geneza.io/internal/types"
)

// The node-key pkcs11 test runs against a token configured in the environment,
// mirroring the keysource suite. With GENEZA_TEST_PKCS11_MODULE unset it skips,
// so the default `go test ./...` needs no HSM. scripts/softhsm-test.sh provisions
// a SoftHSM2 token with an ECDSA P-256 key (the node key is ECDSA, fully
// supported on every PKCS#11 token) and exports the variables read here.
func nodeKeyPKCS11Spec(t *testing.T) keysource.Spec {
	t.Helper()
	mod := os.Getenv("GENEZA_TEST_PKCS11_MODULE")
	if mod == "" {
		t.Skip("set GENEZA_TEST_PKCS11_MODULE (+ PIN/TOKEN/NODE_LABEL) to run the node-key pkcs11 test; see scripts/softhsm-test.sh")
	}
	label := os.Getenv("GENEZA_TEST_PKCS11_NODE_LABEL")
	if label == "" {
		// Fall back to the CA key label: both are ECDSA P-256, so the CA key
		// doubles as a node key when no dedicated node key is provisioned.
		label = os.Getenv("GENEZA_TEST_PKCS11_CA_LABEL")
	}
	if label == "" {
		label = "geneza-node"
	}
	return keysource.Spec{
		Backend:    keysource.BackendPKCS11,
		Module:     mod,
		TokenLabel: os.Getenv("GENEZA_TEST_PKCS11_TOKEN"),
		PIN:        os.Getenv("GENEZA_TEST_PKCS11_PIN"),
		KeyLabel:   label,
	}
}

// TestNodeKeyPKCS11SignInPlace proves the agent's node identity key can live on a
// PKCS#11 token: the enrollment CSR is built from the token signer and the issued
// cert's public key matches the token key; a recording-manifest digest signed by
// the token signer verifies against that cert exactly as the controller verifies it;
// and the private key is never read into the process.
func TestNodeKeyPKCS11SignInPlace(t *testing.T) {
	spec := nodeKeyPKCS11Spec(t)

	signer, err := keysource.Open(spec)
	if err != nil {
		t.Fatalf("open pkcs11 node signer: %v", err)
	}
	tokenPub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("node token key is %T, want *ecdsa.PublicKey", signer.Public())
	}

	// (c) Non-extractability: a token signer surfaces only crypto.Signer; it must
	// not expose the raw private scalar. *ecdsa.PrivateKey is the file backend's
	// type — its presence here would mean the private bytes were loaded.
	if _, isFileKey := signer.(*ecdsa.PrivateKey); isFileKey {
		t.Fatal("pkcs11 node signer is an *ecdsa.PrivateKey: private bytes entered the process")
	}

	// No software fallback: a pkcs11 spec whose key is absent must be a hard error,
	// never a silent fall-through to an on-disk key.
	missing := spec
	missing.KeyLabel = "no-such-node-key"
	missing.KeyID = ""
	if _, err := keysource.Open(missing); err == nil {
		t.Fatal("pkcs11 open with a missing key label must fail, not fall back")
	}

	// (a) Enrollment: build the CSR from the token signer (as Enroll does) and have
	// a throwaway CA issue a node leaf from it. The issued cert's public key must
	// match the token key — the identity is bound to the on-token key.
	csrPEM, err := ca.MakeCSR(signer, "node-pkcs11")
	if err != nil {
		t.Fatalf("make CSR from token signer: %v", err)
	}
	testCA := newTestCA(t)
	leafPEM, err := testCA.IssueFromCSR(csrPEM, ca.Profile{
		Kind: ca.KindNode, Workspace: "default", Name: "node-pkcs11", TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("issue node cert from token CSR: %v", err)
	}
	leaf := firstNodeCert(t, leafPEM)
	leafPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("issued cert key is %T, want *ecdsa.PublicKey", leaf.PublicKey)
	}
	if !tokenPub.Equal(leafPub) {
		t.Fatal("issued cert public key does not match the token key")
	}

	// (b) Manifest signing: sign a recording-manifest digest with the token signer
	// (the path signRecordingManifest takes) and verify it against the cert public
	// key with the controller's verification primitive.
	digest := types.RecordingManifestDigest("sess-1", hexSHA(t), 4096, 1_700_000_000)
	sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("token sign of manifest digest: %v", err)
	}
	if !ecdsa.VerifyASN1(leafPub, digest, sig) {
		t.Fatal("token-signed manifest does not verify against the node cert key")
	}

	// A tampered digest must NOT verify under the same signature.
	bad := append([]byte(nil), digest...)
	bad[0] ^= 0xff
	if ecdsa.VerifyASN1(leafPub, bad, sig) {
		t.Fatal("manifest signature verified over a tampered digest")
	}
}

// newTestCA builds a throwaway file-backed issuing CA for the node-cert test (the
// CA key is unrelated to the node key under test).
func newTestCA(t *testing.T) *ca.CA {
	t.Helper()
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
	issDER, err := x509.CreateCertificate(rand.Reader, issTmpl, rootCert, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	issCert, err := x509.ParseCertificate(issDER)
	if err != nil {
		t.Fatal(err)
	}
	return &ca.CA{Cert: issCert, Signer: rootKey}
}

func firstNodeCert(t *testing.T, pemBytes []byte) *x509.Certificate {
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
