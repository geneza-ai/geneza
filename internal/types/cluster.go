package types

import (
	"crypto/ed25519"
	"fmt"
)

// GrantKey is a trusted gateway signing key (grant + cluster-config signing).
// Multiple keys may be trusted simultaneously to allow rotation with overlap.
type GrantKey struct {
	KeyID     string `json:"key_id"`
	PublicKey []byte `json:"public_key"` // 32-byte ed25519
}

// AgentPolicy carries the session-host guardrail knobs pushed from the
// gateway. Zero values mean "use built-in default".
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
