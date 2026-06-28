//go:build !cgo

package keysource

import (
	"crypto"
	"errors"
)

// openPKCS11 is unavailable without cgo: the PKCS#11 binding wraps a C library
// (libpkcs11), so token-backed keys compile only in a cgo build. Static and
// cross-compiled binaries therefore use the file backend; an operator who needs
// an HSM-backed key builds with CGO enabled.
func openPKCS11(Spec) (crypto.Signer, error) {
	return nil, errors.New("keysource: pkcs11 backend requires a cgo-enabled build")
}
