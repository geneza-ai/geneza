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
//
// Multi-tenancy layout: per-workspace records live in nested sub-buckets under
// `ws/<workspaceID>/<child>` so a read is STRUCTURALLY scoped to one workspace
// (cross-tenant access is NotFound, not a filter that can be forgotten).
// Cross-cutting records stay global: the workspace registry, a node->workspace
// index (for the unauthenticated update path), join tokens (each carries its
// workspace), settings (rollout/cluster-config) and artifacts (signed, identical
// for all tenants).
type Store struct {
	db *bbolt.DB
}

var (
	bucketWS         = []byte("ws")         // parent of per-workspace sub-buckets
	bucketWorkspaces = []byte("workspaces") // global: wsID -> WorkspaceRecord
	bucketNodeWS     = []byte("node_ws")    // global index: nodeID -> wsID
	bucketTokens     = []byte("tokens")     // global: token -> TokenRecord (carries WorkspaceID)
	bucketSettings   = []byte("settings")   // global: rollout + cluster config
	bucketArtifact   = []byte("artifacts")  // global: signed manifests
)

// Per-workspace child sub-bucket names (under ws/<wsID>/).
const (
	childNodes      = "nodes"
	childSessions   = "sessions"
	childModules    = "node_modules"
	childNetworks   = "networks"
	childSubnets    = "subnets"
	childRoutes     = "routes"
	childBindings   = "bindings"
	childRelayPaths = "relaypaths"
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

// --- tenancy records (workspace -> network(VNI) -> subnet -> route) ---

// WorkspaceRecord is a tenant: the isolation boundary owning machines, sessions,
// networks, an overlay address space, and a policy.
type WorkspaceRecord struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	OverlayCIDR string `json:"overlay_cidr"` // per-tenant overlay space, e.g. 100.64.0.0/24
	CreatedUnix int64  `json:"created_unix"`
}

// NetworkRecord is one tenant Network: a VXLAN-width (24-bit) VNI naming a
// routing/broadcast scope that carries N subnets. Membership is TAG-GATED:
// a node/user is in this Network iff policy.LabelsMatch(Selector, its labels)
// (empty Selector = all = default-open). L2 is reserved for the future L2 mode.
type NetworkRecord struct {
	WorkspaceID string            `json:"workspace_id"`
	ID          string            `json:"id"`
	VNI         uint32            `json:"vni"` // 24-bit
	Name        string            `json:"name,omitempty"`
	Selector    map[string]string `json:"selector,omitempty"` // tag selector; empty = all
	L2          bool              `json:"l2,omitempty"`       // RESERVED; always false in Phase 1
}

// SubnetRecord is an address range inside a Network. Overlapping CIDRs across
// Networks/Workspaces are first-class (they are VNI-qualified, never share a wire).
type SubnetRecord struct {
	WorkspaceID string `json:"workspace_id"`
	NetworkID   string `json:"network_id"`
	ID          string `json:"id"`
	CIDR        string `json:"cidr"`
}

// RouteRecord is a RIB entry compiled into signed grants later (server-derived,
// never client-chosen). Defined now so the future routing data plane is drop-in.
type RouteRecord struct {
	WorkspaceID string `json:"workspace_id"`
	NetworkID   string `json:"network_id"`
	ID          string `json:"id"`
	Dest        string `json:"dest"` // CIDR
	ViaNodeID   string `json:"via_node_id,omitempty"`
}

// BindingRecord is the future FIB (VNI,node->overlay IP). Type defined for
// forward-compat; NOT written in Phase 1.
type BindingRecord struct {
	WorkspaceID string `json:"workspace_id"`
	NetworkID   string `json:"network_id"`
	VNI         uint32 `json:"vni"`
	NodeID      string `json:"node_id"`
	OverlayIP   string `json:"overlay_ip"`
}

// RelayPathRecord persists the blind-relay coordinates for an unordered peer
// pair in a Network: each node's 48-bit mailbox rid (lo registers RidLo and
// receives the peer's traffic on it; hi registers RidHi) plus a shared per-flow
// secret. Node ids are sorted so the record is order-independent.
type RelayPathRecord struct {
	WorkspaceID string `json:"workspace_id"`
	VNI         uint32 `json:"vni"`
	NodeLo      string `json:"node_lo"`
	NodeHi      string `json:"node_hi"`
	RidLo       uint64 `json:"rid_lo"`
	RidHi       uint64 `json:"rid_hi"`
	FlowSecret  []byte `json:"flow_secret"`
}

// PlatformRecord is the enrolled node's reported platform.
type PlatformRecord struct {
	OS           string `json:"os,omitempty"`
	Arch         string `json:"arch,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
}

type NodeRecord struct {
	WorkspaceID string            `json:"workspace_id"`
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
	// OverlayIP is the machine's STABLE overlay address within its workspace's
	// overlay space, assigned at approval. DNS resolves <machine> -> this.
	OverlayIP string `json:"overlay_ip,omitempty"`
	// WGPub is the node's dedicated WireGuard static public key (Curve25519, 32
	// bytes), generated at enroll and distributed to co-members as a peer key by
	// the per-Network data plane. Additive: old records decode nil and are
	// skipped as data-plane peers until they re-enroll with a key.
	WGPub []byte `json:"wg_pub,omitempty"`
}

type TokenRecord struct {
	WorkspaceID string            `json:"workspace_id"` // the tenant this token enrolls into
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
	WorkspaceID   string `json:"workspace_id"`
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

func OpenStore(path string) (*Store, error) {
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open state db %s: %w", path, err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		for _, b := range [][]byte{bucketWS, bucketWorkspaces, bucketNodeWS, bucketTokens, bucketSettings, bucketArtifact} {
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

// --- bucket + json helpers ---

// wsChildW returns (creating if needed) the per-workspace child sub-bucket
// ws/<wsID>/<child> for writes.
func wsChildW(tx *bbolt.Tx, wsID, child string) (*bbolt.Bucket, error) {
	wsb, err := tx.Bucket(bucketWS).CreateBucketIfNotExists([]byte(wsID))
	if err != nil {
		return nil, err
	}
	return wsb.CreateBucketIfNotExists([]byte(child))
}

// wsChildR returns the per-workspace child sub-bucket for reads, or nil if the
// workspace or child does not exist yet (treated as empty).
func wsChildR(tx *bbolt.Tx, wsID, child string) *bbolt.Bucket {
	wsb := tx.Bucket(bucketWS).Bucket([]byte(wsID))
	if wsb == nil {
		return nil
	}
	return wsb.Bucket([]byte(child))
}

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

func putJSONB(b *bbolt.Bucket, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put([]byte(key), raw)
}

func getJSONB(b *bbolt.Bucket, key string, out any) error {
	if b == nil {
		return ErrNotFound
	}
	raw := b.Get([]byte(key))
	if raw == nil {
		return ErrNotFound
	}
	return json.Unmarshal(raw, out)
}

// forEachWS iterates every workspace sub-bucket, calling fn with its child
// sub-bucket (which may be nil if that workspace has no records of that kind).
func forEachWS(tx *bbolt.Tx, child string, fn func(wsID string, b *bbolt.Bucket) error) error {
	parent := tx.Bucket(bucketWS)
	return parent.ForEach(func(name, v []byte) error {
		if v != nil { // a key, not a sub-bucket
			return nil
		}
		wsb := parent.Bucket(name)
		if wsb == nil {
			return nil
		}
		return fn(string(name), wsb.Bucket([]byte(child)))
	})
}

// --- workspaces (global registry) ---

func (s *Store) PutWorkspace(rec *WorkspaceRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error { return putJSON(tx, bucketWorkspaces, rec.ID, rec) })
}

func (s *Store) GetWorkspace(id string) (*WorkspaceRecord, error) {
	var rec WorkspaceRecord
	err := s.db.View(func(tx *bbolt.Tx) error { return getJSON(tx, bucketWorkspaces, id, &rec) })
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *Store) ListWorkspaces() ([]*WorkspaceRecord, error) {
	var out []*WorkspaceRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketWorkspaces).ForEach(func(_, v []byte) error {
			var w WorkspaceRecord
			if err := json.Unmarshal(v, &w); err != nil {
				return err
			}
			out = append(out, &w)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// --- networks / subnets / routes (per-workspace) ---

func (s *Store) PutNetwork(rec *NetworkRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, rec.WorkspaceID, childNetworks)
		if err != nil {
			return err
		}
		return putJSONB(b, rec.ID, rec)
	})
}

func (s *Store) ListNetworks(ws string) ([]*NetworkRecord, error) {
	var out []*NetworkRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childNetworks)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var n NetworkRecord
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

func (s *Store) PutSubnet(rec *SubnetRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, rec.WorkspaceID, childSubnets)
		if err != nil {
			return err
		}
		return putJSONB(b, rec.ID, rec)
	})
}

func (s *Store) ListSubnets(ws string) ([]*SubnetRecord, error) {
	var out []*SubnetRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childSubnets)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var sn SubnetRecord
			if err := json.Unmarshal(v, &sn); err != nil {
				return err
			}
			out = append(out, &sn)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// --- bindings (FIB: per-(VNI,node) stable overlay IP, per-workspace) ---

// bindingKey is the VNI-qualified key so the same node holds an independent IP
// per Network (overlapping CIDRs across Networks never collide).
func bindingKey(vni uint32, nodeID string) string {
	return fmt.Sprintf("%d/%s", vni, nodeID)
}

func (s *Store) PutBinding(rec *BindingRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, rec.WorkspaceID, childBindings)
		if err != nil {
			return err
		}
		return putJSONB(b, bindingKey(rec.VNI, rec.NodeID), rec)
	})
}

func (s *Store) GetBinding(ws string, vni uint32, nodeID string) (*BindingRecord, error) {
	var rec BindingRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		return getJSONB(wsChildR(tx, ws, childBindings), bindingKey(vni, nodeID), &rec)
	})
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// ListBindings returns every binding for a Network (used to compute the in-use
// IP set when allocating a new per-Network address).
func (s *Store) ListBindings(ws string, vni uint32) ([]*BindingRecord, error) {
	var out []*BindingRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childBindings)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var r BindingRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			if r.VNI == vni {
				out = append(out, &r)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out, nil
}

// --- relay paths (blind-relay rid pairs, per-workspace) ---

func relayPathKey(vni uint32, lo, hi string) string {
	return fmt.Sprintf("%d/%s/%s", vni, lo, hi)
}

func (s *Store) GetRelayPath(ws string, vni uint32, lo, hi string) (*RelayPathRecord, error) {
	var rec RelayPathRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		return getJSONB(wsChildR(tx, ws, childRelayPaths), relayPathKey(vni, lo, hi), &rec)
	})
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *Store) PutRelayPath(rec *RelayPathRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, rec.WorkspaceID, childRelayPaths)
		if err != nil {
			return err
		}
		return putJSONB(b, relayPathKey(rec.VNI, rec.NodeLo, rec.NodeHi), rec)
	})
}

// --- nodes (per-workspace) ---

func (s *Store) PutNode(ws string, n *NodeRecord) error {
	n.WorkspaceID = ws
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, ws, childNodes)
		if err != nil {
			return err
		}
		if err := putJSONB(b, n.ID, n); err != nil {
			return err
		}
		// Maintain the global node->workspace index in the same txn so it cannot
		// drift from the record.
		return tx.Bucket(bucketNodeWS).Put([]byte(n.ID), []byte(ws))
	})
}

func (s *Store) GetNode(ws, id string) (*NodeRecord, error) {
	var n NodeRecord
	err := s.db.View(func(tx *bbolt.Tx) error { return getJSONB(wsChildR(tx, ws, childNodes), id, &n) })
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// WorkspaceForNode resolves a node's workspace via the global index. Used by the
// UNAUTHENTICATED desired-version path, which has no caller identity to derive
// the workspace from. Returns ErrNotFound for an unknown node.
func (s *Store) WorkspaceForNode(id string) (string, error) {
	var ws string
	err := s.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bucketNodeWS).Get([]byte(id))
		if v == nil {
			return ErrNotFound
		}
		ws = string(v)
		return nil
	})
	return ws, err
}

// GetNodeModules returns the node's desired module set (empty record if none).
func (s *Store) GetNodeModules(ws, nodeID string) (*NodeModulesRecord, error) {
	var rec NodeModulesRecord
	err := s.db.View(func(tx *bbolt.Tx) error { return getJSONB(wsChildR(tx, ws, childModules), nodeID, &rec) })
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
func (s *Store) SetNodeModules(ws, nodeID string, modules []NodeModule) (*NodeModulesRecord, error) {
	var rec NodeModulesRecord
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, ws, childModules)
		if err != nil {
			return err
		}
		_ = getJSONB(b, nodeID, &rec) // ignore ErrNotFound: start at 0
		rec.Version++
		rec.Modules = modules
		return putJSONB(b, nodeID, &rec)
	})
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// DeleteNode removes a node record (decommission). Also drops its module set and
// the index entry. Sessions are left as historical records. ErrNotFound if absent.
func (s *Store) DeleteNode(ws, id string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childNodes)
		if b == nil || b.Get([]byte(id)) == nil {
			return ErrNotFound
		}
		if err := b.Delete([]byte(id)); err != nil {
			return err
		}
		if mb := wsChildR(tx, ws, childModules); mb != nil {
			_ = mb.Delete([]byte(id))
		}
		return tx.Bucket(bucketNodeWS).Delete([]byte(id))
	})
}

// SetNodeApproval flips a node's admission gate transactionally and returns the
// updated record. by is the admin name (or "auto:<provider>") recorded for audit.
func (s *Store) SetNodeApproval(ws, id string, approve bool, by string, now time.Time) (*NodeRecord, error) {
	var n NodeRecord
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, ws, childNodes)
		if err != nil {
			return err
		}
		if err := getJSONB(b, id, &n); err != nil {
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
		return putJSONB(b, id, &n)
	})
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// FindNode resolves a node by id first, then by unique name, WITHIN a workspace.
// Ambiguous names fail closed. A node in another workspace is not found.
func (s *Store) FindNode(ws, idOrName string) (*NodeRecord, error) {
	if n, err := s.GetNode(ws, idOrName); err == nil {
		return n, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	var matches []*NodeRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childNodes)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
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

func (s *Store) ListNodes(ws string) ([]*NodeRecord, error) {
	var out []*NodeRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childNodes)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
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

// ListAllNodes returns nodes across ALL workspaces (operator/global views only —
// e.g. the desired-version reconcile loop is per-node by id, not this).
func (s *Store) ListAllNodes() ([]*NodeRecord, error) {
	var out []*NodeRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		return forEachWS(tx, childNodes, func(_ string, b *bbolt.Bucket) error {
			if b == nil {
				return nil
			}
			return b.ForEach(func(_, v []byte) error {
				var n NodeRecord
				if err := json.Unmarshal(v, &n); err != nil {
					return err
				}
				out = append(out, &n)
				return nil
			})
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// --- join tokens (global; each carries its workspace) ---

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

// --- sessions (per-workspace) ---

func (s *Store) PutSession(ws string, rec *SessionRecord) error {
	rec.WorkspaceID = ws
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, ws, childSessions)
		if err != nil {
			return err
		}
		return putJSONB(b, rec.ID, rec)
	})
}

func (s *Store) GetSession(ws, id string) (*SessionRecord, error) {
	var rec SessionRecord
	err := s.db.View(func(tx *bbolt.Tx) error { return getJSONB(wsChildR(tx, ws, childSessions), id, &rec) })
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// UpdateSession applies fn to the stored record inside one transaction.
func (s *Store) UpdateSession(ws, id string, fn func(*SessionRecord)) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, ws, childSessions)
		if err != nil {
			return err
		}
		var rec SessionRecord
		if err := getJSONB(b, id, &rec); err != nil {
			return err
		}
		fn(&rec)
		return putJSONB(b, id, &rec)
	})
}

func (s *Store) ListSessions(ws string) ([]*SessionRecord, error) {
	var out []*SessionRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childSessions)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
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

// ListAllSessions returns sessions across ALL workspaces (the continuous-authz
// sweep, which re-evaluates each against its own workspace's policy).
func (s *Store) ListAllSessions() ([]*SessionRecord, error) {
	var out []*SessionRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		return forEachWS(tx, childSessions, func(_ string, b *bbolt.Bucket) error {
			if b == nil {
				return nil
			}
			return b.ForEach(func(_, v []byte) error {
				var rec SessionRecord
				if err := json.Unmarshal(v, &rec); err != nil {
					return err
				}
				out = append(out, &rec)
				return nil
			})
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedUnix < out[j].StartedUnix })
	return out, nil
}

// --- settings (global) ---

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

// --- artifact manifests (global) ---

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
