package main

import (
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"geneza.io/internal/defaults"
	"geneza.io/internal/keysource"
	"geneza.io/internal/types"
)

// The anchor flow signs the offline/threshold TrustAnchors document — the fleet
// trust ROOT that authorizes the online grant keys. It is deliberately a separate
// document from the routine map: a grant-key-only controller re-signs the routine map
// online but can never author trust anchors. The flow is three steps so M officers
// can each sign offline from their own key custody:
//
//	propose  — turn a TrustAnchors JSON into the canonical bytes everyone signs,
//	           plus a human diff vs the currently-held anchors.
//	sign     — one officer produces one detached signature over those bytes (file
//	           key or HSM/YubiKey via the keysource seam; the signer only ever sees
//	           the anchor payload, never the routine map).
//	assemble — collect the signatures into a MultiSigned, refusing to emit unless
//	           at least Threshold DISTINCT valid signatures are present.
func anchorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "anchors",
		Short: "Offline/threshold signing of the fleet TrustAnchors document",
	}
	cmd.AddCommand(newAnchorProposeCmd(), newAnchorSignCmd(), newAnchorAssembleCmd())
	return cmd
}

// canonicalAnchorPayload marshals a TrustAnchors to the exact bytes that will be
// signed. encoding/json emits struct fields in declaration order and is
// deterministic for these types, so every officer signing the same proposed
// document signs identical bytes.
func canonicalAnchorPayload(a *types.TrustAnchors) ([]byte, error) {
	return json.Marshal(a)
}

// newAnchorProposeCmd reads a candidate TrustAnchors JSON and writes the canonical
// payload bytes officers will sign, plus a diff against the currently-held anchors
// (when one is supplied) so a reviewer sees exactly what is changing.
func newAnchorProposeCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "propose", Short: "Produce the canonical TrustAnchors payload + a human diff"}
	in := cmd.Flags().String("in", "", "candidate TrustAnchors JSON")
	out := cmd.Flags().String("out", "anchors.payload", "output path for the canonical payload bytes")
	current := cmd.Flags().String("current", "", "currently-held signed anchors (MultiSigned) to diff against (optional)")
	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		if *in == "" {
			return fmt.Errorf("--in is required")
		}
		raw, err := os.ReadFile(*in)
		if err != nil {
			return err
		}
		var anchors types.TrustAnchors
		if err := json.Unmarshal(raw, &anchors); err != nil {
			return fmt.Errorf("parse candidate anchors: %w", err)
		}
		// Refuse a proposal a fleet would reject: the threshold can never be met if
		// fewer trust keys are listed than required, and a node fails closed on an
		// empty trust-key set.
		if len(anchors.TrustKeys) == 0 {
			return fmt.Errorf("candidate lists no trust_keys; nodes would reject it")
		}
		if anchors.Threshold > len(anchors.TrustKeys) {
			return fmt.Errorf("threshold %d exceeds the %d listed trust_keys; it could never be met", anchors.Threshold, len(anchors.TrustKeys))
		}
		if len(anchors.TrustKeys) > 1 && anchors.Threshold < 2 {
			fmt.Printf("WARNING: %d trust_keys listed but threshold is %d — any single officer can sign a trust change; set threshold>=2 for N-of-M custody\n", len(anchors.TrustKeys), anchors.Threshold)
		}
		payload, err := canonicalAnchorPayload(&anchors)
		if err != nil {
			return err
		}
		if err := os.WriteFile(*out, payload, 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote canonical anchor payload (anchor_version %d) -> %s\n", anchors.AnchorVersion, *out)
		printAnchorSummary("proposed", &anchors)
		if *current != "" {
			prev, perr := decodeHeldAnchors(*current)
			if perr != nil {
				return fmt.Errorf("read --current: %w", perr)
			}
			fmt.Println("--- diff vs currently-held anchors ---")
			printAnchorSummary("current ", prev)
			if anchors.AnchorVersion <= prev.AnchorVersion {
				fmt.Printf("WARNING: proposed anchor_version %d is not greater than current %d; nodes will reject it as a rollback\n", anchors.AnchorVersion, prev.AnchorVersion)
			}
		}
		return nil
	}
	return cmd
}

// decodeHeldAnchors extracts the TrustAnchors payload from a MultiSigned envelope
// file without verifying it (this is local human review, not a trust decision).
func decodeHeldAnchors(path string) (*types.TrustAnchors, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ms, err := types.DecodeMultiSigned(b)
	if err != nil {
		return nil, err
	}
	var a types.TrustAnchors
	if err := json.Unmarshal(ms.Payload, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

func printAnchorSummary(label string, a *types.TrustAnchors) {
	grantIDs := make([]string, 0, len(a.GrantKeys))
	for _, k := range a.GrantKeys {
		grantIDs = append(grantIDs, k.KeyID)
	}
	trustIDs := make([]string, 0, len(a.TrustKeys))
	for _, k := range a.TrustKeys {
		trustIDs = append(trustIDs, k.KeyID)
	}
	sort.Strings(grantIDs)
	sort.Strings(trustIDs)
	fmt.Printf("  [%s] anchor_version=%d threshold=%d grant_keys=%v trust_keys=%v ca_roots=%dB forbid_detach=%v audit=%q audit_recipients=%d\n",
		label, a.AnchorVersion, a.Threshold, grantIDs, trustIDs, len(a.CARootsPEM), a.AgentPolicy.ForbidDetach,
		a.AuditRecipient, len(a.EffectiveAuditRecipients()))
}

// newAnchorSignCmd produces one detached signature over a proposed anchor payload.
// The signing key is opened through the keysource seam, so it works with an
// on-disk PEM or a token (HSM/YubiKey) that never exports the key.
func newAnchorSignCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "sign", Short: "Produce one signature over a proposed anchor payload (file or HSM key)"}
	payloadPath := cmd.Flags().String("payload", "anchors.payload", "canonical anchor payload from `propose`")
	out := cmd.Flags().String("out", "", "output path for the OneSig JSON")
	// File-key flags (the default backend, matching `keygen` output).
	keyPath := cmd.Flags().String("key", "trust.key", "offline trust private key (PEM) for the file backend")
	keyIDPath := cmd.Flags().String("keyid", "trust.keyid", "file holding the trust key id")
	// Token (HSM/YubiKey) flags.
	backend := cmd.Flags().String("backend", "", "key backend: file (default) or pkcs11")
	module := cmd.Flags().String("pkcs11-module", "", "PKCS#11 module path (pkcs11 backend)")
	tokenLabel := cmd.Flags().String("pkcs11-token", "", "PKCS#11 token label")
	pin := cmd.Flags().String("pkcs11-pin", "", "PKCS#11 user PIN")
	keyLabel := cmd.Flags().String("pkcs11-key", "", "PKCS#11 key label")
	keyIDFlag := cmd.Flags().String("keyid-value", "", "the key id to record in the signature (required for the pkcs11 backend)")
	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		if *out == "" {
			return fmt.Errorf("--out is required")
		}
		payload, err := os.ReadFile(*payloadPath)
		if err != nil {
			return err
		}
		keyID, signer, err := openTrustSigner(*backend, *keyPath, *keyIDPath, *keyIDFlag, keysource.Spec{
			Backend: *backend, Module: *module, TokenLabel: *tokenLabel, PIN: *pin, KeyLabel: *keyLabel,
		})
		if err != nil {
			return err
		}
		one, err := types.SignOne(signer, keyID, defaults.ContextTrustAnchors, payload)
		if err != nil {
			return err
		}
		b, err := json.Marshal(one)
		if err != nil {
			return err
		}
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			return err
		}
		fmt.Printf("signed anchor payload with key %s -> %s\n", keyID, *out)
		return nil
	}
	return cmd
}

// openTrustSigner returns the signer + its key id for the chosen backend. The file
// backend reads the key id from keyIDPath (the `keygen` layout); the token backend
// requires an explicit key id since a token object carries no Geneza key id. The
// file backend additionally derives the key id from the key and rejects a mismatch
// with the recorded id, so a swapped key file cannot sign under the wrong identity.
func openTrustSigner(backend, keyPath, keyIDPath, keyIDValue string, spec keysource.Spec) (string, crypto.Signer, error) {
	if backend == keysource.BackendPKCS11 {
		if keyIDValue == "" {
			return "", nil, fmt.Errorf("--keyid-value is required for the pkcs11 backend")
		}
		signer, err := keysource.Open(spec)
		if err != nil {
			return "", nil, err
		}
		return keyIDValue, signer, nil
	}
	// File backend (default).
	keyIDBytes, err := os.ReadFile(keyIDPath)
	if err != nil {
		return "", nil, err
	}
	recordedID := trim(string(keyIDBytes))
	signer, err := keysource.Open(keysource.Spec{Backend: keysource.BackendFile, Path: keyPath})
	if err != nil {
		return "", nil, err
	}
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		return "", nil, fmt.Errorf("%s: not an ed25519 trust key", keyPath)
	}
	derived := types.KeyIDFor(pub)
	if recordedID != "" && recordedID != derived {
		return "", nil, fmt.Errorf("key id mismatch: %s says %s but %s derives %s", keyIDPath, recordedID, keyPath, derived)
	}
	return derived, signer, nil
}

// newAnchorAssembleCmd collects OneSig files into a MultiSigned envelope and
// refuses to emit unless at least Threshold DISTINCT signatures verify against the
// candidate's own trust_keys — the same dead-on-arrival guard the single-signer
// path applies, so an operator never hands a controller an envelope the fleet will
// reject.
func newAnchorAssembleCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "assemble", Short: "Collect signatures into a MultiSigned anchor envelope"}
	payloadPath := cmd.Flags().String("payload", "anchors.payload", "canonical anchor payload from `propose`")
	out := cmd.Flags().String("out", "", "output path for the assembled MultiSigned envelope")
	var sigPaths []string
	cmd.Flags().StringArrayVar(&sigPaths, "sig", nil, "a OneSig file from `sign` (repeatable)")
	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		if *out == "" || len(sigPaths) == 0 {
			return fmt.Errorf("--out and at least one --sig are required")
		}
		payload, err := os.ReadFile(*payloadPath)
		if err != nil {
			return err
		}
		var anchors types.TrustAnchors
		if err := json.Unmarshal(payload, &anchors); err != nil {
			return fmt.Errorf("payload is not a TrustAnchors document: %w", err)
		}
		ms := &types.MultiSigned{Payload: payload}
		for _, p := range sigPaths {
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			var one types.OneSig
			if err := json.Unmarshal(b, &one); err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			ms.Sigs = append(ms.Sigs, one)
		}
		// Validate ≥Threshold distinct valid signatures against the candidate's own
		// trust keys BEFORE emitting (refuse-to-emit-DOA).
		pinned, err := anchors.PinnedTrustKeys()
		if err != nil {
			return err
		}
		if _, err := types.VerifyMultiSig(pinned, anchors.Threshold, defaults.ContextTrustAnchors, ms, nil); err != nil {
			return fmt.Errorf("assembled signatures do not meet the threshold of %d: %w", anchors.Threshold, err)
		}
		env, err := ms.Encode()
		if err != nil {
			return err
		}
		if err := os.WriteFile(*out, env, 0o644); err != nil {
			return err
		}
		fmt.Printf("assembled %d signatures over anchor_version %d (threshold %d) -> %s\n", len(ms.Sigs), anchors.AnchorVersion, anchors.Threshold, *out)
		return nil
	}
	return cmd
}
