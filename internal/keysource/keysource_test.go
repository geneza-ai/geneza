package keysource_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"geneza.io/internal/keysource"
)

// The file backend must parse both encodings Geneza writes: the issuing CA's
// SEC1 "EC PRIVATE KEY" and the grant key's PKCS#8 Ed25519 "PRIVATE KEY".
func TestFileBackendECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := writePEM(t, "EC PRIVATE KEY", der)

	signer, err := keysource.Open(keysource.Spec{Path: path})
	if err != nil {
		t.Fatalf("open file ECDSA: %v", err)
	}
	if _, ok := signer.Public().(*ecdsa.PublicKey); !ok {
		t.Fatalf("got %T, want *ecdsa.PublicKey", signer.Public())
	}
	if !key.PublicKey.Equal(signer.Public()) {
		t.Fatal("loaded key does not match")
	}
}

func TestFileBackendEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	path := writePEM(t, "PRIVATE KEY", der)

	// An explicit file backend resolves the same way as the empty default.
	signer, err := keysource.Open(keysource.Spec{Backend: keysource.BackendFile, Path: path})
	if err != nil {
		t.Fatalf("open file Ed25519: %v", err)
	}
	got, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("got %T, want ed25519.PublicKey", signer.Public())
	}
	if !pub.Equal(got) {
		t.Fatal("loaded key does not match")
	}
}

func TestUnknownBackend(t *testing.T) {
	if _, err := keysource.Open(keysource.Spec{Backend: "vault"}); err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestFileBackendMissingPath(t *testing.T) {
	if _, err := keysource.Open(keysource.Spec{}); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func writePEM(t *testing.T, typ string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
