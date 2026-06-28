package types

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
)

// GrantKey is a trusted controller signing key (grant + cluster-config signing).
// Multiple keys may be trusted simultaneously to allow rotation with overlap.
type GrantKey struct {
	KeyID     string `json:"key_id"`
	PublicKey []byte `json:"public_key"` // 32-byte ed25519
	// Workspaces scopes the AUTHORITY of this signing key: when non-empty, the
	// agent accepts a grant signed by this key ONLY for one of these workspaces.
	// Empty = all-workspaces (single-node / a global key). This is the
	// scoped-grant floor: a compromised per-cell controller key cannot mint grants
	// outside its scope, beyond what the agent already enforces (a grant must be
	// for the agent's own enrolled workspace).
	Workspaces []string `json:"workspaces,omitempty"`
}

// TrustKey is a key trusted to sign the ClusterConfig ENVELOPE itself — the
// fleet trust root, distinct from the per-controller GrantKeys that sign session
// grants. Separating the two means a single running controller (which holds only its
// grant key) cannot rewrite the fleet trust set: a config it signs with its grant
// key fails an agent's TrustKeys check. Multiple entries give a rotation overlap.
type TrustKey struct {
	KeyID     string `json:"key_id"`
	PublicKey []byte `json:"public_key"` // 32-byte ed25519
}

// AgentPolicy carries the session-host guardrail knobs pushed from the
// controller. Zero values mean "use built-in default".
type AgentPolicy struct {
	ForbidDetach    bool   `json:"forbid_detach,omitempty"`
	MaxSessions     uint32 `json:"max_sessions,omitempty"`      // default 64
	MaxDetached     uint32 `json:"max_detached,omitempty"`      // default 16
	RingBufferBytes uint32 `json:"ring_buffer_bytes,omitempty"` // default 262144
	DetachedTTLSec  uint32 `json:"detached_ttl_sec,omitempty"`  // default 86400
	IdleReapSec     uint32 `json:"idle_reap_sec,omitempty"`     // 0 = never
}

// ClusterConfig is desired-state distributed to every agent: trust anchors,
// grant keys (with overlap for rotation) and agent policy. It is wrapped in a
// Signed envelope; agents accept an update only if it is signed by a key in
// their *currently trusted* GrantKeys set and its version is not lower than
// what they hold (rollback protection). The first config is accepted over the
// enrollment channel (mTLS to a pinned CA).
type ClusterConfig struct {
	ConfigVersion int64       `json:"config_version"`
	CARootsPEM    []byte      `json:"ca_roots_pem"`
	GrantKeys     []GrantKey  `json:"grant_keys"`
	AgentPolicy   AgentPolicy `json:"agent_policy"`
	RelayAddrs    []string    `json:"relay_addrs,omitempty"`
	// Relays is the signed relay fleet: each entry names a relay's region,
	// identity, addresses and ports, and its server-cert public key. It rides the
	// same signed envelope as the rest of the config, so a tampered relay list
	// fails verification exactly like a forged config — no new trust root. A
	// single-node deployment has one entry in the default region.
	Relays []RelayNode `json:"relays,omitempty"`
	// ControllerEndpoints is the signed fleet view of controllers — the discovery set an
	// agent/relay/client re-homes across when its controller dies. Empty on single-node.
	ControllerEndpoints []ControllerEndpoint `json:"controller_endpoints,omitempty"`
	// TrustKeys are the keys trusted to sign THIS envelope (the fleet trust root),
	// separate from GrantKeys which sign session grants. Empty = back-compat: the
	// GrantKeys double as the trust set (a pre-split config, and the single-node
	// default where one key fills both roles). Agents verify an incoming config
	// against the TrustKeys they ALREADY hold, never the incoming config's own.
	TrustKeys []TrustKey `json:"trust_keys,omitempty"`
	// AuditRecipient is the per-workspace age X25519 PUBLIC recipient that session
	// recordings are encrypted to at the agent. Only the public half travels here;
	// the private key lives with the auditor/custodian, never the controller. Empty
	// means no audit key is configured, so recording-authorized sessions fail
	// closed rather than spool plaintext.
	AuditRecipient string `json:"audit_recipient,omitempty"`
	// AuditRecipients is the full set a workspace may seal each recording to (e.g.
	// the security team's key plus a break-glass escrow key), so losing one
	// identity does not orphan recordings — any one of them decrypts. When set it
	// supersedes AuditRecipient; when empty the single AuditRecipient stands alone,
	// keeping a config that names only the single recipient byte-for-byte as before.
	AuditRecipients []string `json:"audit_recipients,omitempty"`
}

// EffectiveAuditRecipients is the recipient SET a recording is sealed to: the
// explicit list when present, otherwise the legacy single recipient as a
// one-element set (and an empty set when neither is configured). Callers seal to
// every entry so any one matching identity can later decrypt.
func (c *ClusterConfig) EffectiveAuditRecipients() []string {
	return effectiveAuditRecipients(c.AuditRecipient, c.AuditRecipients)
}

// AuditKeyID derives a stable, order-independent id for the recipient SET a
// recording is sealed to: a short SHA-256 fingerprint that labels which key set
// decrypts the cast (so an auditor can tell, and a key rotation leaves old rows
// pointing at the retired set) without copying every recipient into a row. A
// single recipient hashes the recipient string alone, so a recording sealed to
// one key keeps the exact id it had before sets existed; several recipients are
// sorted and newline-joined first so the id does not depend on listing order. An
// empty set yields an empty id.
func AuditKeyID(recipients []string) string {
	switch len(recipients) {
	case 0:
		return ""
	case 1:
		sum := sha256.Sum256([]byte(recipients[0]))
		return "age-sha256:" + hex.EncodeToString(sum[:8])
	default:
		sorted := append([]string(nil), recipients...)
		sort.Strings(sorted)
		sum := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
		return "age-set-sha256:" + hex.EncodeToString(sum[:8])
	}
}

// effectiveAuditRecipients collapses the (single, list) audit-recipient pair into
// the one set the agent seals to: the list wins when non-empty, else the single
// recipient as a one-element set, preserving the pre-list single-recipient
// behavior exactly. Empty entries are dropped so a sparse list never yields a
// blank recipient.
func effectiveAuditRecipients(single string, list []string) []string {
	if len(list) > 0 {
		out := make([]string, 0, len(list))
		for _, r := range list {
			if r != "" {
				out = append(out, r)
			}
		}
		return out
	}
	if single != "" {
		return []string{single}
	}
	return nil
}

// RelayNode is one relay in the signed fleet map. The signature over the
// enclosing ClusterConfig is what makes the addresses and cert key trustworthy;
// an agent or client picks a relay only from this signed list.
type RelayNode struct {
	RegionID     string   `json:"region_id"`
	RelayID      string   `json:"relay_id"`
	Addrs        []string `json:"addrs"`
	STUNPort     int      `json:"stun_port,omitempty"`
	TURNPort     int      `json:"turn_port,omitempty"`
	RelayCertPub []byte   `json:"relay_cert_pub,omitempty"` // ed25519 SPKI of the relay's server cert
	// ControlMux reports that this relay accepts persistent control muxes — an
	// agent may home its control stream through it to a controller. Off unless the
	// relay advertises the capability (and holds a signed controller set to route
	// against), so a single-node map never carries it and agents keep dialing the
	// controller directly. Signed with the rest of the envelope, so a flipped bit
	// fails verification.
	ControlMux bool `json:"control_mux,omitempty"`
	// ControlAddr is the relay's TCP rendezvous host:port — where an agent dials to
	// home a control mux, and where the controller's fleet-aware TCP-floor pick is dialed.
	// Distinct from Addrs, which is the UDP TURN/STUN data endpoint.
	ControlAddr string `json:"control_addr,omitempty"`
	// Draining marks a relay that is shedding traffic for a swap: it still serves its
	// in-flight flows (so an agent keeps pinning its cert from this signed entry) but
	// refuses NEW rendezvous, so the controller leaves it VISIBLE in the signed map yet
	// excludes it from the selectable set new sessions are minted against.
	Draining bool `json:"draining,omitempty"`
}

// ControllerEndpoint is one controller in the signed fleet view. Agents, relays and
// clients seed from any controller, read this set from the signed map, and re-home to
// another endpoint when their current controller dies — the discovery + failover view.
// The signature over the enclosing ClusterConfig is what makes a dialed endpoint
// trustworthy, so a spoofed DNS answer outside this set is refused.
type ControllerEndpoint struct {
	ControllerID string   `json:"controller_id"`
	Addrs     []string `json:"addrs"` // dialable gRPC addresses (host:port) — the client/agent redirect target
	RegionID  string   `json:"region_id,omitempty"`
	// ControlAddrs are the addresses serving the controller↔relay control plane (the
	// relay registrar). They differ from Addrs only when an operator splits the
	// cluster-control listener onto its own port; a relay dials these to register and
	// fail over. Empty means the registrar shares the gRPC listener, so a relay falls
	// back to Addrs.
	ControlAddrs []string `json:"control_addrs,omitempty"`
}

// FailoverAddrs flattens a controller set into the dial order an agent or relay should
// use to fail over. It interleaves across controllers — one address from each controller,
// then the next from each — so consecutive candidates are DIFFERENT controllers: a hung
// controller (one whose process is frozen but whose port still accepts TCP, so each of
// its addresses costs a full keepalive timeout to give up on) costs a single
// failover step instead of one per advertised address. Within a controller, IP
// addresses come before hostnames so an unresolvable name never stalls reaching a
// live controller. control selects the relay-registrar addresses (ControlAddrs,
// falling back to Addrs) over the client/agent gRPC addresses (Addrs).
func FailoverAddrs(gws []ControllerEndpoint, control bool) []string {
	cols := make([][]string, 0, len(gws))
	maxLen := 0
	for _, gw := range gws {
		addrs := gw.Addrs
		if control && len(gw.ControlAddrs) > 0 {
			addrs = gw.ControlAddrs
		}
		c := ipFirstAddrs(addrs)
		cols = append(cols, c)
		if len(c) > maxLen {
			maxLen = len(c)
		}
	}
	var out []string
	for i := 0; i < maxLen; i++ {
		for _, col := range cols {
			if i < len(col) {
				out = append(out, col[i])
			}
		}
	}
	return out
}

func ipFirstAddrs(addrs []string) []string {
	ips := make([]string, 0, len(addrs))
	var names []string
	for _, a := range addrs {
		if host, _, err := net.SplitHostPort(a); err == nil && net.ParseIP(host) != nil {
			ips = append(ips, a)
		} else {
			names = append(names, a)
		}
	}
	return append(ips, names...)
}

// RelayCandidate is one entry in the signed per-session relay candidate list the
// broker puts in a grant: a region-tagged relay plus the minted TURN
// credentials. The client/agent STUN-probe the candidates and pick the lowest
// latency working one; the list rides inside the signed grant.
type RelayCandidate struct {
	RegionID string `json:"region_id"`
	RelayID  string `json:"relay_id"`
	TurnURL  string `json:"turn_url"`
	TurnUser string `json:"turn_user"`
	TurnPass string `json:"turn_pass"`
	Realm    string `json:"realm,omitempty"`
}

// RelaysByRegion groups the signed relay fleet by region id.
func (c *ClusterConfig) RelaysByRegion() map[string][]RelayNode {
	m := map[string][]RelayNode{}
	for _, r := range c.Relays {
		m[r.RegionID] = append(m[r.RegionID], r)
	}
	return m
}

// RelayByID returns the fleet entry with the given relay id.
func (c *ClusterConfig) RelayByID(relayID string) (RelayNode, bool) {
	for _, r := range c.Relays {
		if r.RelayID == relayID {
			return r, true
		}
	}
	return RelayNode{}, false
}

// TrustedKeys converts GrantKeys into the map form Verify expects.
func (c *ClusterConfig) TrustedKeys() (map[string]ed25519.PublicKey, error) {
	m := make(map[string]ed25519.PublicKey, len(c.GrantKeys))
	for _, k := range c.GrantKeys {
		if len(k.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("grant key %q: bad key size %d", k.KeyID, len(k.PublicKey))
		}
		m[k.KeyID] = ed25519.PublicKey(k.PublicKey)
	}
	return m, nil
}

// TrustedConfigKeys returns the keys that may sign the ClusterConfig envelope:
// the TrustKeys set, or — when TrustKeys is absent (a pre-split or single-node
// config) — the GrantKeys, which then double as the trust root. The fallback is
// taken ONLY when TrustKeys is empty, never when it is present-but-non-matching,
// so once an operator splits the roles a grant-key-only signature is rejected.
func (c *ClusterConfig) TrustedConfigKeys() (map[string]ed25519.PublicKey, error) {
	if len(c.TrustKeys) == 0 {
		return c.TrustedKeys()
	}
	m := make(map[string]ed25519.PublicKey, len(c.TrustKeys))
	for _, k := range c.TrustKeys {
		if len(k.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trust key %q: bad key size %d", k.KeyID, len(k.PublicKey))
		}
		m[k.KeyID] = ed25519.PublicKey(k.PublicKey)
	}
	return m, nil
}

// KeyScopes maps each signing key id to its workspace scope (empty slice = the
// key is all-workspaces). Used by the agent to enforce the scoped-grant floor.
func (c *ClusterConfig) KeyScopes() map[string][]string {
	m := make(map[string][]string, len(c.GrantKeys))
	for _, k := range c.GrantKeys {
		m[k.KeyID] = k.Workspaces
	}
	return m
}

// WorkspaceInScope reports whether ws is covered by a key scope (empty scope =
// all workspaces).
func WorkspaceInScope(scope []string, ws string) bool {
	if len(scope) == 0 {
		return true
	}
	for _, s := range scope {
		if s == ws {
			return true
		}
	}
	return false
}

// VerifyClusterConfig verifies a signed cluster config envelope against the
// currently trusted keys and enforces monotonic versions.
func VerifyClusterConfig(trusted map[string]ed25519.PublicKey, s *Signed, currentVersion int64) (*ClusterConfig, error) {
	var c ClusterConfig
	if _, err := Verify(trusted, "cluster-config", s, &c); err != nil {
		return nil, err
	}
	if c.ConfigVersion < currentVersion {
		return nil, fmt.Errorf("cluster config rollback: got v%d, have v%d", c.ConfigVersion, currentVersion)
	}
	return &c, nil
}
