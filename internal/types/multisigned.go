package types

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
)

// MultiSigned is a detached-signature envelope carrying ONE OR MORE signatures
// over the SAME payload bytes — the threshold form of Signed. Each signature is
// verified independently against the pinned signer set; an accept requires at
// least Threshold valid signatures from DISTINCT pinned key ids. A single-signer
// document is just one entry in Sigs (Threshold 0 or 1). Like Signed,
// verification is always over the exact payload bytes that were signed.
type MultiSigned struct {
	Payload []byte   `json:"payload"`
	Sigs    []OneSig `json:"sigs"`
}

// OneSig is one (key id, signature) pair over a MultiSigned payload.
type OneSig struct {
	KeyID string `json:"key_id"`
	Sig   []byte `json:"sig"`
}

// SignOne produces a single OneSig over payload under the given context, using a
// crypto.Signer (an in-memory key or a token-backed signer that never exports
// the key). The signer only ever sees these payload bytes — never a routine map.
// Ed25519 signs the message directly, so the signer is invoked with the zero
// hash (pre-hash NONE); a signer reporting a different size is rejected so we
// never emit a signature a verifier cannot reconstruct.
func SignOne(signer crypto.Signer, keyID, context string, payload []byte) (OneSig, error) {
	sig, err := signer.Sign(rand.Reader, signingInput(context, payload), crypto.Hash(0))
	if err != nil {
		return OneSig{}, fmt.Errorf("sign payload: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return OneSig{}, fmt.Errorf("signer produced a %d-byte signature, want %d (not an Ed25519 signer)", len(sig), ed25519.SignatureSize)
	}
	return OneSig{KeyID: keyID, Sig: sig}, nil
}

// VerifyMultiSig checks a MultiSigned envelope against the pinned signer set
// and, on success, unmarshals the payload into out (which may be nil). It
// accepts only if at least threshold signatures are valid from DISTINCT pinned
// key ids — a duplicate key id counts once, so the same key signing twice cannot
// manufacture a quorum. A threshold of 0 or 1 is the single-signer case. The
// payload bytes returned are the exact bytes that were verified, so a caller can
// digest them for binding (e.g. a routine map's AnchorDigest).
func VerifyMultiSig(trusted map[string]ed25519.PublicKey, threshold int, context string, s *MultiSigned, out any) ([]byte, error) {
	if s == nil {
		return nil, errors.New("nil multi-signed envelope")
	}
	want := threshold
	if want < 1 {
		want = 1
	}
	input := signingInput(context, s.Payload)
	seen := make(map[string]bool, len(s.Sigs))
	valid := 0
	for _, one := range s.Sigs {
		if seen[one.KeyID] {
			continue // a repeated key id contributes at most once
		}
		pub, ok := trusted[one.KeyID]
		if !ok {
			continue
		}
		if len(pub) != ed25519.PublicKeySize || len(one.Sig) != ed25519.SignatureSize {
			continue
		}
		if !ed25519.Verify(pub, input, one.Sig) {
			continue
		}
		seen[one.KeyID] = true
		valid++
	}
	if valid < want {
		return nil, fmt.Errorf("%w: %d of %d required distinct valid signatures", ErrBadSignature, valid, want)
	}
	if out != nil {
		if err := json.Unmarshal(s.Payload, out); err != nil {
			return nil, fmt.Errorf("unmarshal verified payload: %w", err)
		}
	}
	return s.Payload, nil
}

// Encode/Decode helpers for transporting envelopes as opaque bytes.

func (s *MultiSigned) Encode() ([]byte, error) { return json.Marshal(s) }

// DecodeMultiSigned parses a MultiSigned envelope from its opaque bytes.
func DecodeMultiSigned(b []byte) (*MultiSigned, error) {
	var s MultiSigned
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("decode multi-signed envelope: %w", err)
	}
	return &s, nil
}
