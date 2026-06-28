//go:build cgo

package keysource

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ThalesGroup/crypto11"
)

// openPKCS11 opens the configured PKCS#11 module, logs into the token, and
// returns a crypto.Signer bound to the private key object identified by KeyLabel
// and/or KeyID. The signing operation runs on the token, so the private key is
// never read into this process.
//
// ECDSA keys (the issuing-CA key) work on every PKCS#11 token. Ed25519 (the
// grant key) needs both a token with CKM_EDDSA AND a PKCS#11 binding that
// surfaces an Edwards key as a crypto.Signer; the binding used here exposes RSA
// and ECDSA but not yet Ed25519, so a token-backed grant key is not available
// today and the grant key's file backend stays the default.
func openPKCS11(spec Spec) (crypto.Signer, error) {
	if spec.Module == "" {
		return nil, errors.New("keysource: pkcs11 backend requires a module path")
	}
	if spec.TokenLabel == "" && spec.Slot == nil {
		return nil, errors.New("keysource: pkcs11 backend requires token_label or slot")
	}
	if spec.KeyLabel == "" && spec.KeyID == "" {
		return nil, errors.New("keysource: pkcs11 backend requires key_label or key_id")
	}

	cfg := &crypto11.Config{
		Path:       spec.Module,
		TokenLabel: spec.TokenLabel,
		SlotNumber: spec.Slot,
		Pin:        spec.PIN,
	}
	ctx, err := crypto11.Configure(cfg)
	if err != nil {
		return nil, fmt.Errorf("keysource: open pkcs11 module %q: %w", spec.Module, err)
	}

	var id []byte
	if spec.KeyID != "" {
		id, err = hex.DecodeString(spec.KeyID)
		if err != nil {
			ctx.Close()
			return nil, fmt.Errorf("keysource: pkcs11 key_id %q is not hex: %w", spec.KeyID, err)
		}
	}
	var label []byte
	if spec.KeyLabel != "" {
		label = []byte(spec.KeyLabel)
	}

	signer, err := ctx.FindKeyPair(id, label)
	if err != nil {
		ctx.Close()
		return nil, fmt.Errorf("keysource: find pkcs11 key (label=%q id=%q): %w", spec.KeyLabel, spec.KeyID, err)
	}
	if signer == nil {
		ctx.Close()
		return nil, fmt.Errorf("keysource: no pkcs11 key matches label=%q id=%q", spec.KeyLabel, spec.KeyID)
	}
	return signer, nil
}
