package client

import (
	"crypto"
	"errors"
	"fmt"
	"os"

	"osie.cloud/geneza/internal/ca"
)

// KeyStore abstracts custody of the operator's private key. The contract is
// deliberately a crypto.Signer so that hardware-bound backends — TPM 2.0 on
// Linux, Secure Enclave/Keychain on macOS, CNG/TPM on Windows later — can be
// dropped in without the rest of the client noticing: those backends return
// a Signer whose private key material never leaves the hardware, and the CSR
// + TLS client-cert paths only ever need Sign(). The file implementation is
// the v1 software fallback.
type KeyStore interface {
	// EnsureKey returns the operator key, generating it if absent. Idempotent:
	// a second call returns the same key.
	EnsureKey() (crypto.Signer, error)
	// Remove destroys the key (logout). Missing key is not an error.
	Remove() error
}

// FileKeyStore stores a P-256 key as a 0600 PEM file.
type FileKeyStore struct {
	Path string
}

var _ KeyStore = (*FileKeyStore)(nil)

func (f *FileKeyStore) EnsureKey() (crypto.Signer, error) {
	b, err := os.ReadFile(f.Path)
	switch {
	case err == nil:
		// Key files hold secrets: repair permissions on legacy/loose files.
		if err := os.Chmod(f.Path, 0o600); err != nil {
			return nil, err
		}
		k, err := ca.ParseKeyPEM(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Path, err)
		}
		return k, nil
	case errors.Is(err, os.ErrNotExist):
		k, err := ca.GenerateKey()
		if err != nil {
			return nil, err
		}
		pemBytes, err := ca.MarshalKeyPEM(k)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(f.Path, pemBytes, 0o600); err != nil {
			return nil, err
		}
		return k, nil
	default:
		return nil, err
	}
}

func (f *FileKeyStore) Remove() error {
	err := os.Remove(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
