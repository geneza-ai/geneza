// Package types defines Geneza's signed wire documents: session grants,
// cluster config, and artifact manifests. All are JSON payloads wrapped in a
// detached-signature envelope (ed25519, domain-separated by context string).
// Verification is always over the exact payload bytes that were signed.
package types

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
)

// Signed is the universal detached-signature envelope.
type Signed struct {
	Payload []byte `json:"payload"` // exact JSON bytes that were signed
	Sig     []byte `json:"sig"`
	KeyID   string `json:"key_id"`
}

var (
	ErrUnknownKey   = errors.New("signature by unknown key id")
	ErrBadSignature = errors.New("signature verification failed")
)

func signingInput(context string, payload []byte) []byte {
	prefix := []byte("geneza:" + context + ":")
	return append(prefix, payload...)
}

// Sign marshals payloadObj to JSON and signs it under the given context. The
// signer holds an Ed25519 private key — either an in-memory ed25519.PrivateKey
// or a token-backed signer (HSM/KMS) that never exports the key. Ed25519 signs
// the message directly, so the signer is invoked with the zero hash (pre-hash
// NONE); a signer reporting a different opts is rejected so we never silently
// emit a signature over a digest the verifier will not reconstruct.
func Sign(signer crypto.Signer, keyID, context string, payloadObj any) (*Signed, error) {
	payload, err := json.Marshal(payloadObj)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	sig, err := signer.Sign(rand.Reader, signingInput(context, payload), crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("sign payload: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signer produced a %d-byte signature, want %d (not an Ed25519 signer)", len(sig), ed25519.SignatureSize)
	}
	return &Signed{Payload: payload, Sig: sig, KeyID: keyID}, nil
}

// Verify checks the envelope against the trusted key set and, on success,
// unmarshals the payload into out (which may be nil). Returns the key id
// that verified.
func Verify(trusted map[string]ed25519.PublicKey, context string, s *Signed, out any) (string, error) {
	if s == nil {
		return "", errors.New("nil signed envelope")
	}
	pub, ok := trusted[s.KeyID]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownKey, s.KeyID)
	}
	if len(pub) != ed25519.PublicKeySize || len(s.Sig) != ed25519.SignatureSize {
		return "", ErrBadSignature
	}
	if !ed25519.Verify(pub, signingInput(context, s.Payload), s.Sig) {
		return "", ErrBadSignature
	}
	if out != nil {
		if err := json.Unmarshal(s.Payload, out); err != nil {
			return "", fmt.Errorf("unmarshal verified payload: %w", err)
		}
	}
	return s.KeyID, nil
}

// VerifyOne is Verify for a single pinned key (e.g. the bootstrap's pinned
// artifact key); it ignores KeyID matching beyond requiring the same id when
// keyID is non-empty.
func VerifyOne(pub ed25519.PublicKey, keyID, context string, s *Signed, out any) error {
	if s == nil {
		return errors.New("nil signed envelope")
	}
	// ed25519.Verify panics on a wrong-size key; guard so a malformed pinned key
	// (or signature) fails closed instead of crashing the bootstrap/verifier.
	if len(pub) != ed25519.PublicKeySize || len(s.Sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	if keyID != "" && s.KeyID != keyID {
		return fmt.Errorf("%w: %q (want %q)", ErrUnknownKey, s.KeyID, keyID)
	}
	if !ed25519.Verify(pub, signingInput(context, s.Payload), s.Sig) {
		return ErrBadSignature
	}
	if out != nil {
		if err := json.Unmarshal(s.Payload, out); err != nil {
			return fmt.Errorf("unmarshal verified payload: %w", err)
		}
	}
	return nil
}

// Encode/Decode helpers for transporting envelopes as opaque bytes.

func (s *Signed) Encode() ([]byte, error) { return json.Marshal(s) }

func DecodeSigned(b []byte) (*Signed, error) {
	var s Signed
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("decode signed envelope: %w", err)
	}
	return &s, nil
}
