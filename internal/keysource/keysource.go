// Package keysource produces a crypto.Signer for one of Geneza's online
// crown-jewel keys (the issuing-CA key and the grant key) from a configured
// backend. The point of the indirection is that the caller only ever asks the
// source to SIGN: with a token backend the private bytes never enter process
// memory, so a host compromise cannot exfiltrate the key.
//
// Two backends:
//
//	file   — parse a private-key PEM from disk (today's behavior). The returned
//	         signer is an in-memory key.
//	pkcs11 — open a PKCS#11 module, log into the token, and hand back a signer
//	         that performs the signature ON the token. The key never leaves it.
//
// An empty backend means "file", so a deployment with no key-source config
// behaves exactly as it did before this seam existed.
package keysource

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Backend names.
const (
	BackendFile   = "file"
	BackendPKCS11 = "pkcs11"
)

// Spec selects a key-source backend and its parameters. The zero Spec (or one
// with an empty Backend) is the file backend reading Path.
type Spec struct {
	// Backend is "file" (default) or "pkcs11".
	Backend string

	// Path is the private-key PEM file for the file backend.
	Path string

	// PKCS#11 parameters (backend == "pkcs11").

	// Module is the path to the PKCS#11 shared library (.so/.dll), e.g.
	// /usr/lib/softhsm/libsofthsm2.so.
	Module string
	// TokenLabel selects the token by its label; if empty, Slot is used.
	TokenLabel string
	// Slot selects the token by slot number; used only when TokenLabel is empty.
	Slot *int
	// PIN is the user PIN for the token.
	PIN string
	// KeyLabel finds the private key object by its CKA_LABEL.
	KeyLabel string
	// KeyID finds the private key object by its CKA_ID (hex string, optional —
	// combine with or use instead of KeyLabel).
	KeyID string
}

// Open returns a crypto.Signer for the configured backend.
func Open(spec Spec) (crypto.Signer, error) {
	switch spec.Backend {
	case "", BackendFile:
		return openFile(spec.Path)
	case BackendPKCS11:
		return openPKCS11(spec)
	default:
		return nil, fmt.Errorf("keysource: unknown backend %q (want %q or %q)", spec.Backend, BackendFile, BackendPKCS11)
	}
}

// openFile parses a private-key PEM and returns it as a crypto.Signer. It
// accepts the encodings Geneza writes: SEC1 "EC PRIVATE KEY" (the issuing CA
// key) and PKCS#8 "PRIVATE KEY" (the grant key, an Ed25519 key). The parsed
// value is returned as-is so a caller can type-assert the concrete key type it
// expects.
func openFile(path string) (crypto.Signer, error) {
	if path == "" {
		return nil, errors.New("keysource: file backend requires a path")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	key, err := parsePrivateKey(blk)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s: key type %T does not implement crypto.Signer", path, key)
	}
	return signer, nil
}

func parsePrivateKey(blk *pem.Block) (any, error) {
	switch blk.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(blk.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(blk.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(blk.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", blk.Type)
	}
}
