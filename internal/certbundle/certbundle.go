// Package certbundle handles the concatenated PEM bundle (private key + cert
// chain) that Geneza stores and distributes for managed-domain certificates. The
// controller writes it, and agents and relays parse it back into a tls.Certificate.
package certbundle

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"strings"
)

// Split separates a bundle into the cert chain and the private key (each may
// appear in any order). Private-key blocks (type ending in "PRIVATE KEY") go to
// keyPEM; CERTIFICATE blocks go to chainPEM, preserving order.
func Split(bundle []byte) (chainPEM, keyPEM []byte, err error) {
	rest := bundle
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		enc := pem.EncodeToMemory(blk)
		switch {
		case strings.HasSuffix(blk.Type, "PRIVATE KEY"):
			keyPEM = append(keyPEM, enc...)
		case blk.Type == "CERTIFICATE":
			chainPEM = append(chainPEM, enc...)
		}
	}
	if len(chainPEM) == 0 || len(keyPEM) == 0 {
		return nil, nil, errors.New("certbundle: missing chain or key")
	}
	return chainPEM, keyPEM, nil
}

// TLSCertificate parses a bundle into a usable tls.Certificate.
func TLSCertificate(bundle []byte) (*tls.Certificate, error) {
	chain, key, err := Split(bundle)
	if err != nil {
		return nil, err
	}
	crt, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return nil, err
	}
	return &crt, nil
}
