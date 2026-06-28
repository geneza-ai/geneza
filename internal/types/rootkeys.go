package types

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

// contextRootKeys domain-separates root-keys signatures. Kept as a literal here
// (like the "grant"/"cluster-config" contexts) to avoid a types->defaults import;
// it must equal defaults.ContextRootKeys.
const contextRootKeys = "artifact-root"

// ArtifactKey is one trusted artifact-signing public key.
type ArtifactKey struct {
	KeyID     string `json:"key_id"`
	PublicKey []byte `json:"public_key"` // 32-byte ed25519
}

// RootKeys is the artifact-signing trust ROOT (TUF-style): a document signed
// OFFLINE by the long-lived root key — whose PUBLIC half is pinned on every
// node — that names the CURRENT set of release-signing keys. It is:
//   - monotonically Versioned (rollback protection: a node never downgrades to
//     an older key set, so a retired/compromised signing key cannot be revived);
//   - Expiring (freeze protection: a stale root-keys doc cannot be replayed
//     forever to keep a node trusting keys that should have rotated out);
//   - overlap-friendly (list new + old keys during a rotation, then drop old).
//
// The root key authorizes signing keys but never signs release manifests
// itself — that role separation means a single online signing-key leak is
// recoverable (root signs a new RootKeys without the bad key; nodes pick it up)
// while the high-value root stays offline and is touched ~never.
type RootKeys struct {
	Version   int64         `json:"version"`
	Keys      []ArtifactKey `json:"keys"`
	ExpiresAt time.Time     `json:"expires_at"`
}

// SigningKeys converts Keys into the map form Verify expects (and rejects an
// empty set, which would otherwise mean "trust no one" — fail closed loudly).
func (r *RootKeys) SigningKeys() (map[string]ed25519.PublicKey, error) {
	m := make(map[string]ed25519.PublicKey, len(r.Keys))
	for _, k := range r.Keys {
		if len(k.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("artifact key %q: bad key size %d", k.KeyID, len(k.PublicKey))
		}
		m[k.KeyID] = ed25519.PublicKey(k.PublicKey)
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("root-keys lists no signing keys")
	}
	return m, nil
}

// VerifyRootKeys verifies a root-keys envelope against the PINNED root key set,
// enforcing monotonic version (rollback) and expiry (freeze). currentVersion is
// the highest root-keys version the node has accepted (0 on a fresh node).
func VerifyRootKeys(rootTrusted map[string]ed25519.PublicKey, s *Signed, currentVersion int64, now time.Time) (*RootKeys, error) {
	var r RootKeys
	if _, err := Verify(rootTrusted, contextRootKeys, s, &r); err != nil {
		return nil, err
	}
	if r.Version < currentVersion {
		return nil, fmt.Errorf("root-keys rollback: got v%d, have v%d", r.Version, currentVersion)
	}
	if !r.ExpiresAt.IsZero() && now.After(r.ExpiresAt) {
		return nil, fmt.Errorf("root-keys expired at %s", r.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return &r, nil
}

// VerifyArtifactChain is the agent's complete trust decision for an update:
// verify the root-keys doc against the PINNED root, derive the current
// signing-key set, then verify the release manifest against THAT set. Because
// the manifest is checked against the signing keys (never the root), a manifest
// signed by the root key id is rejected unless the root is also a listed
// signing key — enforcing root/signing role separation. Anti-rollback on the
// manifest itself (CreatedAt floor) and the blob hash are checked by the caller
// (the Installer) after this returns.
func VerifyArtifactChain(rootTrusted map[string]ed25519.PublicKey, rootKeys, manifest *Signed, rootVersion int64, now time.Time) (*RootKeys, *Manifest, error) {
	rk, err := VerifyRootKeys(rootTrusted, rootKeys, rootVersion, now)
	if err != nil {
		return nil, nil, fmt.Errorf("root-keys: %w", err)
	}
	signers, err := rk.SigningKeys()
	if err != nil {
		return nil, nil, err
	}
	var m Manifest
	if _, err := Verify(signers, contextManifestForChain, manifest, &m); err != nil {
		return nil, nil, fmt.Errorf("manifest: %w", err)
	}
	return rk, &m, nil
}

// contextManifestForChain must equal defaults.ContextManifest; literal to keep
// types dependency-free.
const contextManifestForChain = "artifact-manifest"
