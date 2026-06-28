package agentd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"testing"
	"time"

	"geneza.io/internal/ca"
	"geneza.io/internal/keysource"
	"geneza.io/internal/types"
)

// TestTLSCertificateFileKey proves the file-backed node key (an *ecdsa.PrivateKey
// satisfying crypto.Signer) still assembles a usable mTLS client certificate: the
// chain parses, the leaf is set, and a key/cert mismatch is rejected.
func TestTLSCertificateFileKey(t *testing.T) {
	key, err := ca.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	certPEM := issueNodeLeaf(t, key)

	st := &State{Key: key, NodeCertPEM: certPEM}
	cert, err := st.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}
	if cert.PrivateKey == nil || len(cert.Certificate) == 0 || cert.Leaf == nil {
		t.Fatal("assembled certificate is missing key, chain, or leaf")
	}
	// The assembled material must drive a real TLS config without re-parsing.
	if _, err := tls.X509KeyPair(certPEM, marshalKey(t, key)); err != nil {
		t.Fatalf("control X509KeyPair: %v", err)
	}

	// A mismatched key must be rejected (the safety check tls.X509KeyPair makes).
	other, err := ca.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&State{Key: other, NodeCertPEM: certPEM}).TLSCertificate(); err == nil {
		t.Fatal("TLSCertificate accepted a key that does not match the cert")
	}
}

// TestManifestSignFileKey proves the file-backed signer path produces a
// recording-manifest signature that verifies against the node cert, matching the
// controller's ecdsa.VerifyASN1 check.
func TestManifestSignFileKey(t *testing.T) {
	key, err := ca.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	var signer crypto.Signer = key

	digest := types.RecordingManifestDigest("sess-1", hexSHA(t), 4096, 1_700_000_000)
	sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest, sig) {
		t.Fatal("file-key manifest signature does not verify")
	}
}

// TestNodeKeySourceSpecDefault proves the default (empty) node key_source resolves
// to node.key under the state dir — the file backend, byte-for-byte.
func TestNodeKeySourceSpecDefault(t *testing.T) {
	cfg := &Config{StateDir: "/var/lib/geneza/agent"}
	spec := cfg.nodeKeySource()
	if spec.Backend != "" {
		t.Fatalf("default backend = %q, want empty (file)", spec.Backend)
	}
	if want := "/var/lib/geneza/agent/" + fileNodeKey; spec.Path != want {
		t.Fatalf("default path = %q, want %q", spec.Path, want)
	}
}

// TestNodeKeySourceValidate covers the pkcs11 config guardrails.
func TestNodeKeySourceValidate(t *testing.T) {
	if err := (KeySourceConfig{}).validate(); err != nil {
		t.Fatalf("empty (file) must validate: %v", err)
	}
	if err := (KeySourceConfig{Backend: keysource.BackendPKCS11}).validate(); err == nil {
		t.Fatal("pkcs11 without a module must fail validation")
	}
	good := KeySourceConfig{
		Backend: keysource.BackendPKCS11, Module: "/x.so", TokenLabel: "tok", KeyLabel: "node",
	}
	if err := good.validate(); err != nil {
		t.Fatalf("complete pkcs11 block must validate: %v", err)
	}
}

func issueNodeLeaf(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	csr, err := ca.MakeCSR(key, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	c := newTestCA(t)
	leafPEM, err := c.IssueFromCSR(csr, ca.Profile{
		Kind: ca.KindNode, Workspace: "default", Name: "node-1", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return leafPEM
}

func marshalKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := ca.MarshalKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
