package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	bbolt "go.etcd.io/bbolt"
)

// Store is the gateway's persistent state in bbolt. Single-writer semantics
// from bbolt are sufficient: the gateway is a single node today, and the
// store interface is small enough to re-back with Postgres/etcd for HA later.
type Store struct {
	db *bbolt.DB
}

var (
	bucketNodes    = []byte("nodes")
	bucketTokens   = []byte("tokens")
	bucketSessions = []byte("sessions")
	bucketSettings = []byte("settings")
	bucketArtifact = []byte("artifacts")
	bucketModules  = []byte("node_modules")
)

var ErrNotFound = errors.New("not found")

// Join token failure modes are distinguished internally (for logs/audit) but
// callers must collapse them to one opaque error toward the enrollee.
var (
	ErrTokenUnknown   = errors.New("unknown join token")
	ErrTokenExpired   = errors.New("join token expired")
	ErrTokenExhausted = errors.New("join token exhausted")
)

// Settings keys.
const (
	settingStableVersion        = "stable_version"
	settingCanaryVersion        = "canary_version"
	settingCanaryNodes          = "canary_nodes"
	settingClusterConfigVersion = "cluster_config_version"
	settingSignedClusterConfig  = "signed_cluster_config"
)

// PlatformRecord is the enrolled node's reported platform.
type PlatformRecord struct {
	OS           string `json:"os,omitempty"`
	Arch         string `json:"arch,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
}

type NodeRecord struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Labels      map[string]string `json:"labels,omitempty"`
	NoisePub    []byte            `json:"noise_pub"`
	Platform    PlatformRecord    `json:"platform"`
	CreatedUnix int64             `json:"created_unix"`
	// Approved is the zero-trust admission gate: an enrolled node has an identity
	// (node cert) but the broker refuses to open any session to it until an admin
	// approves it. Token enrollment lands here Approved=false unless the token was
	// minted --auto-approve; cryptographic-identity providers approve on enroll.
	Approved       bool   `json:"approved,omitempty"`
	ApprovedBy     string `json:"approved_by,omitempty"` // admin name, or "auto:<provider>"
	ApprovedAtUnix int64  `json:"approved_at_unix,omitempty"`
}

type TokenRecord struct {
	Labels      map[string]string `json:"labels,omitempty"`
	ExpiresUnix int64             `json:"expires_unix"`
	MaxUses     int32             `json:"max_uses"`
	Uses        int32             `json:"uses"`
	// AutoApprove enrolls nodes already approved (skip the pending gate). Set by
	// `admin tokens new --auto-approve`. A leaked auto-approve token yields a
	// usable node with no human check, so it is opt-in, not the default.
	AutoApprove bool `json:"auto_approve,omitempty"`
}

// Session states.
const (
	SessionPending  = "pending"
	SessionActive   = "active"
	SessionDetached = "detached"
	SessionEnded    = "ended"
	SessionRevoked  = "revoked"
)

type SessionRecord struct {
	ID            string `json:"id"`
	User          string `json:"user"`
	NodeID        string `json:"node_id"`
	NodeName      string `json:"node_name"`
	Action        string `json:"action"`
	State         string `json:"state"`
	HostSessionID string `json:"host_session_id,omitempty"`
	StartedUnix   int64  `json:"started_unix"`
	EndedUnix     int64  `json:"ended_unix,omitempty"`
	ExitCode      int32  `json:"exit_code,omitempty"`
	Detachable    bool   `json:"detachable,omitempty"`
	// Captured for continuous re-authorization (re-evaluating a live session
	// against current policy) and the audit trail.
	Roles         []string          `json:"roles,omitempty"`
	Service       string            `json:"service,omitempty"`
	ServiceKind   string            `json:"service_kind,omitempty"`
	ServiceLabels map[string]string `json:"service_labels,omitempty"`
	ClientPath    string            `json:"client_path,omitempty"`
	OverlayIP     string            `json:"overlay_ip,omitempty"`
}

func OpenStore(path string) (*Store, error) {
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open state db %s: %w", path, err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		for _, b := range [][]byte{bucketNodes, bucketTokens, bucketSessions, bucketSettings, bucketArtifact, bucketModules} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func putJSON(tx *bbolt.Tx, bucket []byte, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return tx.Bucket(bucket).Put([]byte(key), b)
}

func getJSON(tx *bbolt.Tx, bucket []byte, key string, out any) error {
	raw := tx.Bucket(bucket).Get([]byte(key))
	if raw == nil {
		return ErrNotFound
	}
	return json.Unmarshal(raw, out)
}

// --- nodes ---

func (s *Store) PutNode(n *NodeRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error { return putJSON(tx, bucketNodes, n.ID, n) })
}

// NodeModule is one enabled/disabled agent module for a node (monitoring, future
// exporters). Persisted per node and pushed to the agent in realtime.
type NodeModule struct {
	Name     string            `json:"name"`
	Enabled  bool              `json:"enabled"`
	Settings map[string]string `json:"settings,omitempty"`
}

// NodeModulesRecord is the desired module set for a node plus a monotonic
// version so the agent ignores stale pushes.
type NodeModulesRecord struct {
	Version int64        `json:"version"`
	Modules []NodeModule `json:"modules"`
}

// GetNodeModules returns the node's desired module set (empty record if none).
func (s *Store) GetNodeModules(nodeID string) (*NodeModulesRecord, error) {
	var rec NodeModulesRecord
	err := s.db.View(func(tx *bbolt.Tx) error { return getJSON(tx, bucketModules, nodeID, &rec) })
	if errors.Is(err, ErrNotFound) {
		return &NodeModulesRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// SetNodeModules replaces a node's desired module set, bumping the version, and
// returns the stored record.
func (s *Store) SetNodeModules(nodeID string, modules []NodeModule) (*NodeModulesRecord, error) {
	var rec NodeModulesRecord
	err := s.db.Update(func(tx *bbolt.Tx) error {
		_ = getJSON(tx, bucketModules, nodeID, &rec) // ignore ErrNotFound: start at 0
		rec.Version++
		rec.Modules = modules
		return putJSON(tx, bucketModules, nodeID, &rec)
	})
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *Store) GetNode(id string) (*NodeRecord, error) {
	var n NodeRecord
	err := s.db.View(func(tx *bbolt.Tx) error { return getJSON(tx, bucketNodes, id, &n) })
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// DeleteNode removes a node record (decommission). Also drops its module set.
// Sessions are left as historical records. Returns ErrNotFound if absent.
func (s *Store) DeleteNode(id string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		if tx.Bucket(bucketNodes).Get([]byte(id)) == nil {
			return ErrNotFound
		}
		if err := tx.Bucket(bucketNodes).Delete([]byte(id)); err != nil {
			return err
		}
		return tx.Bucket(bucketModules).Delete([]byte(id))
	})
}

// SetNodeApproval flips a node's admission gate transactionally and returns the
// updated record. by is the admin name (or "auto:<provider>") recorded for audit.
func (s *Store) SetNodeApproval(id string, approve bool, by string, now time.Time) (*NodeRecord, error) {
	var n NodeRecord
	err := s.db.Update(func(tx *bbolt.Tx) error {
		if err := getJSON(tx, bucketNodes, id, &n); err != nil {
			return err
		}
		n.Approved = approve
		if approve {
			n.ApprovedBy = by
			n.ApprovedAtUnix = now.Unix()
		} else {
			n.ApprovedBy = ""
			n.ApprovedAtUnix = 0
		}
		return putJSON(tx, bucketNodes, id, &n)
	})
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// FindNode resolves a node by id first, then by unique name. Ambiguous names
// fail closed rather than picking one.
func (s *Store) FindNode(idOrName string) (*NodeRecord, error) {
	if n, err := s.GetNode(idOrName); err == nil {
		return n, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	var matches []*NodeRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketNodes).ForEach(func(_, v []byte) error {
			var n NodeRecord
			if err := json.Unmarshal(v, &n); err != nil {
				return err
			}
			if n.Name == idOrName {
				matches = append(matches, &n)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	switch len(matches) {
	case 0:
		return nil, ErrNotFound
	case 1:
		return matches[0], nil
	default:
		return nil, fmt.Errorf("node name %q is ambiguous (%d matches); use the node id", idOrName, len(matches))
	}
}

func (s *Store) ListNodes() ([]*NodeRecord, error) {
	var out []*NodeRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketNodes).ForEach(func(_, v []byte) error {
			var n NodeRecord
			if err := json.Unmarshal(v, &n); err != nil {
				return err
			}
			out = append(out, &n)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// --- join tokens ---

func (s *Store) PutToken(token string, rec *TokenRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error { return putJSON(tx, bucketTokens, token, rec) })
}

// UseToken transactionally consumes one use of a join token. The expiry and
// use-count checks happen inside the write transaction so concurrent enrolls
// cannot double-spend a single-use token.
func (s *Store) UseToken(token string, now time.Time) (*TokenRecord, error) {
	var rec TokenRecord
	err := s.db.Update(func(tx *bbolt.Tx) error {
		if err := getJSON(tx, bucketTokens, token, &rec); err != nil {
			if errors.Is(err, ErrNotFound) {
				return ErrTokenUnknown
			}
			return err
		}
		if now.Unix() > rec.ExpiresUnix {
			return ErrTokenExpired
		}
		if rec.Uses >= rec.MaxUses {
			return ErrTokenExhausted
		}
		rec.Uses++
		return putJSON(tx, bucketTokens, token, &rec)
	})
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// --- sessions ---

func (s *Store) PutSession(rec *SessionRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error { return putJSON(tx, bucketSessions, rec.ID, rec) })
}

func (s *Store) GetSession(id string) (*SessionRecord, error) {
	var rec SessionRecord
	err := s.db.View(func(tx *bbolt.Tx) error { return getJSON(tx, bucketSessions, id, &rec) })
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// UpdateSession applies fn to the stored record inside one transaction.
func (s *Store) UpdateSession(id string, fn func(*SessionRecord)) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		var rec SessionRecord
		if err := getJSON(tx, bucketSessions, id, &rec); err != nil {
			return err
		}
		fn(&rec)
		return putJSON(tx, bucketSessions, id, &rec)
	})
}

func (s *Store) ListSessions() ([]*SessionRecord, error) {
	var out []*SessionRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketSessions).ForEach(func(_, v []byte) error {
			var rec SessionRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			out = append(out, &rec)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedUnix < out[j].StartedUnix })
	return out, nil
}

// --- settings ---

func (s *Store) SetSetting(key string, val []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketSettings).Put([]byte(key), val)
	})
}

func (s *Store) GetSetting(key string) ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bucketSettings).Get([]byte(key))
		if v != nil {
			out = append([]byte(nil), v...)
		}
		return nil
	})
	return out, err
}

func (s *Store) getStringSetting(key string) (string, error) {
	b, err := s.GetSetting(key)
	return string(b), err
}

func (s *Store) StableVersion() (string, error) { return s.getStringSetting(settingStableVersion) }
func (s *Store) CanaryVersion() (string, error) { return s.getStringSetting(settingCanaryVersion) }

func (s *Store) SetStableVersion(v string) error {
	return s.SetSetting(settingStableVersion, []byte(v))
}

func (s *Store) SetCanaryVersion(v string) error {
	return s.SetSetting(settingCanaryVersion, []byte(v))
}

func (s *Store) CanaryNodes() ([]string, error) {
	b, err := s.GetSetting(settingCanaryNodes)
	if err != nil || len(b) == 0 {
		return nil, err
	}
	var out []string
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("settings %s: %w", settingCanaryNodes, err)
	}
	return out, nil
}

func (s *Store) SetCanaryNodes(nodes []string) error {
	b, err := json.Marshal(nodes)
	if err != nil {
		return err
	}
	return s.SetSetting(settingCanaryNodes, b)
}

func (s *Store) ClusterConfigVersion() (int64, error) {
	b, err := s.GetSetting(settingClusterConfigVersion)
	if err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, nil
	}
	return strconv.ParseInt(string(b), 10, 64)
}

func (s *Store) SetSignedClusterConfig(version int64, signed []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSettings)
		if err := b.Put([]byte(settingClusterConfigVersion), []byte(strconv.FormatInt(version, 10))); err != nil {
			return err
		}
		return b.Put([]byte(settingSignedClusterConfig), signed)
	})
}

func (s *Store) SignedClusterConfig() ([]byte, error) {
	return s.GetSetting(settingSignedClusterConfig)
}

// --- artifact manifests ---

// ManifestKey builds the artifacts bucket key.
func ManifestKey(product, osName, arch, version string) string {
	return product + "/" + osName + "/" + arch + "/" + version
}

func (s *Store) PutManifest(key string, signed []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketArtifact).Put([]byte(key), signed)
	})
}

func (s *Store) GetManifest(key string) ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bucketArtifact).Get([]byte(key))
		if v == nil {
			return ErrNotFound
		}
		out = append([]byte(nil), v...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
