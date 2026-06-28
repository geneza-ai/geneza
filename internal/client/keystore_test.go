package client

import (
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"testing"
)

func TestFileKeyStoreCreates0600AndIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user.key")
	ks := &FileKeyStore{Path: path}

	k1, err := ks.EnsureKey()
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %o, want 0600", fi.Mode().Perm())
	}

	k2, err := ks.EnsureKey()
	if err != nil {
		t.Fatal(err)
	}
	p1, ok1 := k1.Public().(*ecdsa.PublicKey)
	p2, ok2 := k2.Public().(*ecdsa.PublicKey)
	if !ok1 || !ok2 {
		t.Fatal("expected ECDSA keys")
	}
	if !p1.Equal(p2) {
		t.Fatal("EnsureKey is not idempotent: second call returned a different key")
	}
}

func TestFileKeyStoreRepairsLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user.key")
	ks := &FileKeyStore{Path: path}
	if _, err := ks.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode after repair = %o, want 0600", fi.Mode().Perm())
	}
}

func TestFileKeyStoreRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user.key")
	ks := &FileKeyStore{Path: path}
	if _, err := ks.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	if err := ks.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("key file still present after Remove")
	}
	// Remove on a missing key is not an error (logout is idempotent).
	if err := ks.Remove(); err != nil {
		t.Fatal(err)
	}
}
