package types

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"time"
)

// TrustAnchors is the fleet trust ROOT document: it names WHO is trusted (the
// grant keys that may sign the routine map and mint grants, the CA roots leaf
// certs chain to, the host guardrail policy, the audit recipient) and is signed
// OFFLINE — or by an N-of-M threshold of offline keys — so no single online
// compromise can rewrite it. Its PUBLIC signer set (TrustKeys + Threshold) is
// PINNED on every node at enrollment. It is monotonically versioned (rollback
// protection) and may carry the next-level TrustKeys (rotation overlap),
// mirroring RootKeys for artifact updates.
//
// A single stolen online grant key can therefore forge a routine map but cannot
// produce a TrustAnchors a node accepts: it does not hold a pinned trust key.
type TrustAnchors struct {
	AnchorVersion  int64       `json:"anchor_version"`
	GrantKeys      []GrantKey  `json:"grant_keys"`   // who may sign RoutineMap + grants
	CARootsPEM     []byte      `json:"ca_roots_pem"` // which CA roots leaf certs chain to
	AgentPolicy    AgentPolicy `json:"agent_policy"` // host guardrails (trust-class)
	AuditRecipient string      `json:"audit_recipient,omitempty"`
	// AuditRecipients is the full audit-key set recordings are sealed to (security
	// team key + break-glass escrow, say), so losing one custodian key does not
	// orphan recordings — any one of them decrypts. When set it supersedes
	// AuditRecipient; empty leaves the single AuditRecipient standing alone, so an
	// anchors document that names only the single recipient is unchanged.
	AuditRecipients []string   `json:"audit_recipients,omitempty"`
	TrustKeys       []TrustKey `json:"trust_keys"`          // who may sign THIS doc (the pinned set)
	Threshold       int        `json:"threshold,omitempty"` // N in N-of-M; 0/1 = single-signer
	// ExpiresAt is OPTIONAL freeze protection: when set, a node refuses anchors
	// past their expiry so a stale trust set cannot be replayed forever. The zero
	// value means "never expires" — the default, trading freeze-resistance for
	// availability of the trust set (grant-key rotation is the faster lever and a
	// fleet that cannot reach its offline officers should not fail closed on the
	// rarely-changing anchors). An operator that wants expiry sets it explicitly.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// EffectiveAuditRecipients is the recipient SET a recording is sealed to: the
// explicit list when present, otherwise the legacy single recipient as a
// one-element set (and an empty set when neither is configured).
func (a *TrustAnchors) EffectiveAuditRecipients() []string {
	return effectiveAuditRecipients(a.AuditRecipient, a.AuditRecipients)
}

// TrustedGrantKeys converts the anchors' GrantKeys into the map form Verify
// expects (and the routine map is verified against). It is the set the anchors
// AUTHORIZE to sign the routine map; an empty set is rejected (fail closed).
func (a *TrustAnchors) TrustedGrantKeys() (map[string]ed25519.PublicKey, error) {
	m := make(map[string]ed25519.PublicKey, len(a.GrantKeys))
	for _, k := range a.GrantKeys {
		if len(k.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("grant key %q: bad key size %d", k.KeyID, len(k.PublicKey))
		}
		m[k.KeyID] = ed25519.PublicKey(k.PublicKey)
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("trust anchors authorize no grant keys")
	}
	return m, nil
}

// PinnedTrustKeys converts the anchors' TrustKeys into the map form
// VerifyMultiSig expects — the signer set a node PINS and verifies the next
// anchors against. An empty set is rejected (fail closed: "trust no one").
func (a *TrustAnchors) PinnedTrustKeys() (map[string]ed25519.PublicKey, error) {
	m := make(map[string]ed25519.PublicKey, len(a.TrustKeys))
	for _, k := range a.TrustKeys {
		if len(k.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trust key %q: bad key size %d", k.KeyID, len(k.PublicKey))
		}
		m[k.KeyID] = ed25519.PublicKey(k.PublicKey)
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("trust anchors list no trust keys")
	}
	return m, nil
}

// KeyScopes maps each authorized grant key id to its workspace scope (empty
// slice = all-workspaces), used by the agent to enforce the scoped-grant floor.
func (a *TrustAnchors) KeyScopes() map[string][]string {
	m := make(map[string][]string, len(a.GrantKeys))
	for _, k := range a.GrantKeys {
		m[k.KeyID] = k.Workspaces
	}
	return m
}

// RoutineMap is the high-churn, low-stakes routing view: relay fleet, controller
// discovery set, relay addrs. Signed ONLINE by a grant key. It BINDS to a
// specific TrustAnchors version (AnchorVersion + AnchorDigest) so a routine map
// can never be paired with a stale or forged trust set — a verifier rejects it
// unless both match the anchors it holds. Verified against the GrantKeys the
// CURRENT pinned TrustAnchors authorizes.
type RoutineMap struct {
	ConfigVersion    int64             `json:"config_version"`
	AnchorVersion    int64             `json:"anchor_version"` // the TrustAnchors version this map was built against
	AnchorDigest     []byte            `json:"anchor_digest"`  // SHA-256 of the canonical TrustAnchors payload bytes
	RelayAddrs       []string          `json:"relay_addrs,omitempty"`
	Relays           []RelayNode       `json:"relays,omitempty"`
	ControllerEndpoints []ControllerEndpoint `json:"controller_endpoints,omitempty"`
}

// AnchorDigestOf is the SHA-256 of the exact signed TrustAnchors payload bytes —
// the value a RoutineMap carries in AnchorDigest to pin itself to one trust set.
func AnchorDigestOf(anchorPayload []byte) []byte {
	h := sha256.Sum256(anchorPayload)
	return h[:]
}

// FleetState is the verified pair a node holds after a two-step verify: the
// trust anchors and the routine map bound to them, plus the exact anchor payload
// bytes (so a node can re-derive the pinned trust set and the binding digest).
type FleetState struct {
	Anchors       *TrustAnchors
	Map           *RoutineMap
	AnchorPayload []byte
}

// VerifyFleetState is the split-mode trust decision, mirroring VerifyArtifactChain
// for the fleet trust set. Step 1 verifies the anchors against the PINNED trust
// keys + threshold and enforces the anchor rollback (and optional expiry) floor.
// Step 2 verifies the routine map against the grant keys THOSE anchors authorize,
// enforces the map rollback floor, and requires the map to bind to exactly these
// anchors (version AND digest). A rotation may carry a new TrustKeys/Threshold in
// the anchors — it was just verified against the held (old) pinned set, so the
// caller re-pins to anchors.PinnedTrustKeys() for the next round (the
// "verified against the old, authorizes the new" overlap RootKeys uses).
//
// pinnedTrustKeys/pinnedThreshold are the HELD pinned set, never the incoming
// document's own. heldAnchorVersion/heldConfigVersion are the rollback floors.
func VerifyFleetState(
	pinnedTrustKeys map[string]ed25519.PublicKey, pinnedThreshold int,
	heldAnchorVersion, heldConfigVersion int64,
	anchorEnv *MultiSigned, mapEnv *Signed, now time.Time,
) (*FleetState, error) {
	var anchors TrustAnchors
	anchorPayload, err := VerifyMultiSig(pinnedTrustKeys, pinnedThreshold, contextTrustAnchors, anchorEnv, &anchors)
	if err != nil {
		return nil, fmt.Errorf("trust anchors: %w", err)
	}
	if anchors.AnchorVersion < heldAnchorVersion {
		return nil, fmt.Errorf("trust anchors rollback: got v%d, have v%d", anchors.AnchorVersion, heldAnchorVersion)
	}
	if !anchors.ExpiresAt.IsZero() && now.After(anchors.ExpiresAt) {
		return nil, fmt.Errorf("trust anchors expired at %s", anchors.ExpiresAt.UTC().Format(time.RFC3339))
	}
	grantKeys, err := anchors.TrustedGrantKeys()
	if err != nil {
		return nil, err
	}

	var rm RoutineMap
	if _, err := Verify(grantKeys, contextRoutineMap, mapEnv, &rm); err != nil {
		return nil, fmt.Errorf("routine map: %w", err)
	}
	if rm.ConfigVersion < heldConfigVersion {
		return nil, fmt.Errorf("routine map rollback: got v%d, have v%d", rm.ConfigVersion, heldConfigVersion)
	}
	if rm.AnchorVersion != anchors.AnchorVersion {
		return nil, fmt.Errorf("routine map bound to anchor v%d, anchors are v%d", rm.AnchorVersion, anchors.AnchorVersion)
	}
	if !bytesEqual(rm.AnchorDigest, AnchorDigestOf(anchorPayload)) {
		return nil, fmt.Errorf("routine map anchor digest does not match the held trust anchors")
	}
	return &FleetState{Anchors: &anchors, Map: &rm, AnchorPayload: anchorPayload}, nil
}

// bytesEqual is a length-and-content compare; the inputs are public digests, so
// a constant-time compare is not required.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// contextTrustAnchors / contextRoutineMap must equal defaults.ContextTrustAnchors
// / defaults.ContextRoutineMap; kept as literals here to avoid a types->defaults
// import, exactly as contextRootKeys does for the artifact chain.
const (
	contextTrustAnchors = "trust-anchors"
	contextRoutineMap   = "routine-map"
)
