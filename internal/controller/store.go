package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"geneza.io/internal/types"
	bbolt "go.etcd.io/bbolt"
)

// Store is the controller's persistent state in bbolt. Single-writer semantics
// from bbolt are sufficient: the controller is a single node today, and the
// store interface is small enough to re-back with Postgres/etcd for HA later.
//
// Multi-tenancy layout: per-workspace records live in nested sub-buckets under
// `ws/<workspaceID>/<child>` so a read is STRUCTURALLY scoped to one workspace
// (cross-tenant access is NotFound, not a filter that can be forgotten).
// Cross-cutting records stay global: the workspace registry, a node->workspace
// index (for the unauthenticated update path), join tokens (each carries its
// workspace), settings (rollout/cluster-config) and artifacts (signed, identical
// for all tenants).
type bboltStore struct {
	db *bbolt.DB
}

var (
	bucketWS         = []byte("ws")         // parent of per-workspace sub-buckets
	bucketWorkspaces = []byte("workspaces") // global: wsID -> WorkspaceRecord
	bucketNodeWS     = []byte("node_ws")    // global index: nodeID -> wsID
	bucketTokens     = []byte("tokens")     // global: token -> TokenRecord (carries WorkspaceID)
	bucketSettings   = []byte("settings")   // global: rollout + cluster config
	bucketArtifact   = []byte("artifacts")  // global: signed manifests
	// bucketSrcBindings maps a cloud-qualified SOURCE binding (e.g.
	// "openstack:project:<service-uid>:<project-uuid>", "idp:group:<realm>:<g>")
	// to a workspace id (the workspace is the hub; sources bind onto it).
	// Global because a binding is the routing key from an external identity to a
	// tenant; it carries its own workspace, like tokens.
	bucketSrcBindings = []byte("src_bindings")
	// bucketOSEnroll dedupes OpenStack vendordata enrollments by
	// "<service-uid>#<instance-uuid>": Nova hits
	// the endpoint ~5x per boot, so the minted join token is recorded here and
	// re-served atomically rather than minting a fresh token per hit.
	bucketOSEnroll = []byte("os_enroll")
	// bucketRevokedCerts is the leaf-cert revocation denylist:
	// serial-hex -> RevokedCert. Checked on every authenticated RPC so a leaked
	// node/user/admin cert can be killed before its TTL without a fleet-wide CA
	// re-key. Survives restart (persisted), unlike a TTL-only model.
	bucketRevokedCerts = []byte("revoked_certs")
	// bucketAdvisories holds vuln advisories keyed by id, global like tokens: an
	// advisory is the same fact for every tenant. Any feed writes here through the
	// same store method; the by-package resolve scans this bucket.
	bucketAdvisories = []byte("advisories")
	// bucketImageComponents holds a container image's flattened component set keyed by
	// content digest, stored ONCE no matter how many nodes (across any tenant) run it.
	// Global because a sha256 digest is content-addressable: the same image bytes
	// everywhere. Reached only through a workspace-scoped node->digest association, so
	// the global keying never leaks one tenant's findings to another.
	bucketImageComponents = []byte("image_components")
	// bucketImageCVE holds the computed verdicts for an image digest, matched ONCE per
	// digest and fanned out to associated nodes on read. Global for the same reason as
	// bucketImageComponents and reached the same ws-scoped way.
	bucketImageCVE = []byte("image_cve")
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
	childRecordings = "recordings"
	childSBOMs      = "node_sboms"
	childComponents = "node_components"
	childNodeCVE    = "node_cve"
	// childNodeImages is the per-workspace node->digest association: which image
	// digests a node currently runs. The image components and verdicts themselves are
	// stored ONCE per digest in the global buckets below; this association is the only
	// workspace-scoped link, so a per-node read fans a digest's findings to its nodes
	// without re-storing the image set.
	childNodeImages = "node_images"
)

var ErrNotFound = errors.New("not found")

// sha256Len is the byte length of a node's self-measured binary hash. A heartbeat
// carrying any other length is rejected rather than pinned, so a malformed or
// malicious short hash cannot poison the baseline.
const sha256Len = 32

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
	// Relay rollout ring, kept on its own keys so a relay rollout never disturbs
	// the agent ring (the two products roll independently). Same generic settings
	// KV — no DDL, works byte-for-byte on bbolt and both SQL engines.
	settingRelayStableVersion   = "relay_stable_version"
	settingRelayCanaryVersion   = "relay_canary_version"
	settingRelayCanaryNodes     = "relay_canary_nodes"
	settingClusterConfigVersion = "cluster_config_version"
	settingSignedClusterConfig  = "signed_cluster_config"
	// Split-mode trust anchors, stored alongside the routine map so both advance
	// under one bbolt write transaction. Absent on a legacy (un-split) store.
	settingAnchorVersion = "trust_anchor_version"
	settingSignedAnchor  = "signed_trust_anchor"
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
	L2          bool              `json:"l2,omitempty"`       // RESERVED; always false for now
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
// forward-compat; NOT written yet.
type BindingRecord struct {
	WorkspaceID string `json:"workspace_id"`
	NetworkID   string `json:"network_id"`
	VNI         uint32 `json:"vni"`
	NodeID      string `json:"node_id"`
	OverlayIP   string `json:"overlay_ip"`
}

// PlatformRecord is the enrolled node's reported platform.
type PlatformRecord struct {
	OS           string `json:"os,omitempty"`
	Arch         string `json:"arch,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
	// Cross-platform OS identity probed by the agent at enroll: a normalized
	// distro id ("ubuntu", "macos", "windows"), its release, and a human label.
	Distro        string `json:"distro,omitempty"`
	DistroVersion string `json:"distro_version,omitempty"`
	OSPretty      string `json:"os_pretty,omitempty"`
	// HostUUID is the machine's stable hardware identifier (the DMI product UUID on
	// Linux, best-effort and empty when unreadable). It is the one host attribute
	// stable across an OS re-image, so it anchors the quarantine re-enroll gate: a
	// quarantined host that wipes its state and re-enrolls with a fresh node id is
	// still recognized and held for admin review. Advisory only — a clone copies it
	// trivially, so it never proves single-host residency, it only keeps a known-bad
	// host from laundering its quarantine away.
	HostUUID string `json:"host_uuid,omitempty"`
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
	// Region is the agent's STUN-RTT closest relay region, reported in its hello.
	// The broker uses it to pick the session's relay candidate set. Empty = the
	// default region (single-node and un-upgraded agents).
	Region string `json:"region,omitempty"`
	// ApprovedBinaryHash is the blessed self-measurement baseline: the SHA-256 the
	// agent reports for its own running executable, pinned from the FIRST heartbeat
	// after the node is approved. A later heartbeat reporting a different hash is
	// drift (the agent binary was swapped) and quarantines the node unless the new
	// hash is a release the controller published at/above the floor below. The baseline
	// is PRESERVED across re-approval (never cleared): a node re-approved while still
	// running a tampered binary keeps the old baseline and re-quarantines on its next
	// beat, so an admin click cannot launder a still-bad binary.
	ApprovedBinaryHash []byte `json:"approved_binary_hash,omitempty"`
	// ApprovedBinaryCreatedUnix is the publish time (manifest CreatedAt) of the
	// blessed release, the anti-rollback floor: a drift to an OLDER published release
	// is a downgrade (e.g. to a known-vulnerable signed build), not a sanctioned
	// update. Zero when the baseline is an unpublished/custom build (no version
	// ordering to enforce).
	ApprovedBinaryCreatedUnix int64 `json:"approved_binary_created_unix,omitempty"`
	// LastBinaryHash / LastMeasuredUnix are the latest reported self-measurement and
	// the controller's receipt time for it (never the agent's clock), shown to the admin
	// at re-approval and used to tell a frozen agent from an offline one.
	LastBinaryHash   []byte `json:"last_binary_hash,omitempty"`
	LastMeasuredUnix int64  `json:"last_measured_unix,omitempty"`
}

type TokenRecord struct {
	WorkspaceID string            `json:"workspace_id"` // the tenant this token enrolls into
	Labels      map[string]string `json:"labels,omitempty"`
	ExpiresUnix int64             `json:"expires_unix"`
	MaxUses     int32             `json:"max_uses"`
	Uses        int32             `json:"uses"`
	// AutoApprove enrolls nodes already approved (skip the pending gate). Set by
	// `geneza node enroll --auto-approve`. A leaked auto-approve token yields a
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
	WorkspaceID string `json:"workspace_id"`
	ID          string `json:"id"`
	User        string `json:"user"`
	// Provider + Subject are the durable authorization principal (suspension key);
	// captured from the verified cert at broker time. Subject is stable; User is
	// display-only. Empty on legacy records => treated as unkeyable.
	Provider      string `json:"provider,omitempty"`
	Subject       string `json:"subject,omitempty"`
	NodeID        string `json:"node_id"`
	NodeName      string `json:"node_name"`
	Action        string `json:"action"`
	State         string `json:"state"`
	HostSessionID string `json:"host_session_id,omitempty"`
	StartedUnix   int64  `json:"started_unix"`
	EndedUnix     int64  `json:"ended_unix,omitempty"`
	ExitCode      int32  `json:"exit_code,omitempty"`
	Detachable    bool   `json:"detachable,omitempty"`
	// Recorded is set true once the encrypted recording for this session has been
	// uploaded and indexed, so the sessions list can show a replay badge without
	// joining the recordings table.
	Recorded bool `json:"recorded,omitempty"`
	// Captured for continuous re-authorization (re-evaluating a live session
	// against current policy) and the audit trail.
	Roles         []string          `json:"roles,omitempty"`
	Service       string            `json:"service,omitempty"`
	ServiceKind   string            `json:"service_kind,omitempty"`
	ServiceLabels map[string]string `json:"service_labels,omitempty"`
	ClientPath    string            `json:"client_path,omitempty"`
	OverlayIP     string            `json:"overlay_ip,omitempty"`
	// ClientNoisePub is the client's Noise static key from the grant; the controller
	// binds it into every signed lease/delta/revoke so a signature minted for one
	// session cannot be replayed onto another. Direct sessions only.
	ClientNoisePub []byte `json:"client_noise_pub,omitempty"`
	// Grant ceiling captured at create-time, so the sweep can tell a policy TIGHTEN
	// (e.g. now read-only while the grant allowed input) from a no-change and push a
	// downgrade SessionPolicyDelta that stays within the grant.
	GrantAllowPTY       bool     `json:"grant_allow_pty,omitempty"`
	GrantForwardTargets []string `json:"grant_forward_targets,omitempty"`
	// EnforcementEpoch is the strictly-monotonic counter stamped into every signed
	// lease/delta/revoke for this session. It lives on the durable record (not in a
	// controller's memory) so any controller that takes over the session — after a
	// restart or a control-stream re-home — continues the sequence the agent has
	// already seen, instead of restarting at 1 and having the agent reject every
	// enforcement message as a replay.
	EnforcementEpoch int64 `json:"enforcement_epoch,omitempty"`
	// RehomeEpoch is the strictly-monotonic in-session relay re-home generation. The
	// controller bumps it once per fresh grant it re-issues for a relay that drained or
	// died, so two ends requesting re-home at once converge on ONE re-issued grant
	// (a request naming an already-applied epoch mints nothing) and a duplicate or
	// out-of-order re-home push is dropped by the endpoints.
	RehomeEpoch int64 `json:"rehome_epoch,omitempty"`
	// GrantScope is the originally-issued signed grant for this session. The re-home
	// re-issue path decodes it for the session's exact verified scope (action,
	// command, forward target, routes, noise keys) and swaps ONLY the rendezvous
	// fields, rather than re-deriving scope from scattered record fields. It is the
	// grant as signed; a re-issue re-signs a copy with fresh rendezvous coordinates.
	GrantScope []byte `json:"grant_scope,omitempty"`
	// Revoke-delivery tracking, set when the record is marked SessionRevoked.
	// RevokeDelivered records whether the agent acknowledged the teardown. Because
	// a node's session host survives the agent reconnecting, an offline agent does
	// NOT mean the PTY is gone; a false flag means the teardown is still owed and
	// must be redelivered (next sweep tick, or when the agent reconnects) before
	// the session is truly down.
	RevokeReason    string `json:"revoke_reason,omitempty"`
	RevokeDelivered bool   `json:"revoke_delivered,omitempty"`
	// Continuous presence. RequirePresence is set from the policy
	// decision at create; LastPresenceUnix is stamped on every verified heartbeat
	// (seeded = StartedUnix for the first-beat grace); PresenceChallenge is the
	// current single-use challenge the client must echo, rotated each beat. The
	// Prev* pair backs a one-heartbeat-interval grace so a single lost response
	// does not falsely stale a session. Zero values = presence-off.
	RequirePresence       bool   `json:"require_presence,omitempty"`
	LastPresenceUnix      int64  `json:"last_presence_unix,omitempty"`
	LastPresenceCounter   uint32 `json:"last_presence_counter,omitempty"` // monotonic-nonce anti-replay
	PresenceChallenge     []byte `json:"presence_challenge,omitempty"`
	PrevPresenceChallenge []byte `json:"prev_presence_challenge,omitempty"`
	PrevChallengeUnix     int64  `json:"prev_challenge_unix,omitempty"`
}

// RecordingRecord is the metadata index row for one stored session recording.
// The blob it points at (BlobRef) is age ciphertext the controller cannot read; this
// row is the searchable, integrity-checked descriptor. SHA256 is over the
// ciphertext and NodeSig is the node's attestation over the manifest, both
// verified at upload. Keyed (WorkspaceID, SessionID).
type RecordingRecord struct {
	WorkspaceID string `json:"workspace_id"`
	SessionID   string `json:"session_id"`
	NodeID      string `json:"node_id,omitempty"`
	// Principal is the durable subject the recording is attributed to (not the
	// mutable display name), for the audit list filter.
	Principal   string `json:"principal,omitempty"`
	Action      string `json:"action,omitempty"`
	StartedUnix int64  `json:"started_unix,omitempty"`
	EndedUnix   int64  `json:"ended_unix,omitempty"`
	SizeBytes   int64  `json:"size_bytes,omitempty"`
	SHA256      string `json:"sha256,omitempty"`       // hex, over the ciphertext
	NodeSig     []byte `json:"node_sig,omitempty"`     // ECDSA-P256 over the manifest digest
	AuditKeyID  string `json:"audit_key_id,omitempty"` // the audit recipient the cast was sealed to
	BlobRef     string `json:"blob_ref,omitempty"`     // "local:<id>.cast.age" | "s3://…"
	Truncated   bool   `json:"truncated,omitempty"`
	StoredUnix  int64  `json:"stored_unix,omitempty"`
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

// NodeSBOMRecord is a node's whole software inventory: one CycloneDX SBOM kept as
// the zstd-compressed bytes the agent shipped (SBOM), preserved verbatim so it
// stays the canonical artifact and is never reparsed for storage. ContentHash is
// the agent's hash of the uncompressed document — the same value the heartbeat
// carries, so an unchanged node never re-uploads the blob. Keyed (WorkspaceID, NodeID).
type NodeSBOMRecord struct {
	WorkspaceID   string `json:"workspace_id"`
	NodeID        string `json:"node_id"`
	Format        string `json:"format,omitempty"`
	ContentHash   string `json:"content_hash,omitempty"`
	CollectedUnix int64  `json:"collected_unix,omitempty"`
	SBOM          []byte `json:"sbom,omitempty"` // zstd-compressed CycloneDX bytes
}

// ComponentRecord is one entry of the flattened component index a node's SBOM
// expands into: the granularity the matcher joins against. A node's full set is
// replaced atomically on re-index. Source distinguishes two origins of the same
// purl (e.g. an OS package vs a component of a nested container image), so it is
// part of the identity. Keyed (WorkspaceID, NodeID, Purl, Source).
type ComponentRecord struct {
	WorkspaceID string `json:"workspace_id"`
	NodeID      string `json:"node_id"`
	Purl        string `json:"purl"`
	Source      string `json:"source"`
	Ecosystem   string `json:"ecosystem,omitempty"`
	Name        string `json:"name,omitempty"`
	Version     string `json:"version,omitempty"`
	// Distro qualifies the version so a backported fix is compared against the
	// distro's own patched version, never an upstream one.
	Distro string `json:"distro,omitempty"`
}

// AdvisoryRecord is one vuln advisory as a feed delivered it. Doc is the full
// advisory (it carries its own upstream source's license, which the resolve path
// surfaces per-record); the promoted fields back the by-package lookup the matcher
// performs. Global, not per-workspace: the same advisory is a fact for every
// tenant. Keyed by ID.
type AdvisoryRecord struct {
	ID           string          `json:"id"`
	Source       string          `json:"source,omitempty"`
	Ecosystem    string          `json:"ecosystem,omitempty"`
	PackageName  string          `json:"package_name,omitempty"`
	Doc          json.RawMessage `json:"doc,omitempty"`
	ModifiedUnix int64           `json:"modified_unix,omitempty"`
}

// NodeCVERecord is one computed answer row: a (node, component, cve) verdict.
// Status is the matcher's result (affected | not_affected | fixed |
// under_investigation); the prioritization fields and the VEX justification ride
// the row so a list view needs no second lookup. FixedVersion is the DISTRO's
// patched version. Keyed (WorkspaceID, NodeID, CVE, Purl).
type NodeCVERecord struct {
	WorkspaceID      string  `json:"workspace_id"`
	NodeID           string  `json:"node_id"`
	CVE              string  `json:"cve"`
	Purl             string  `json:"purl"`
	Status           string  `json:"status,omitempty"`
	Severity         string  `json:"severity,omitempty"`
	KEV              bool    `json:"kev,omitempty"`
	EPSS             float64 `json:"epss,omitempty"`
	VEXJustification string  `json:"vex_justification,omitempty"`
	FixedVersion     string  `json:"fixed_version,omitempty"`
	MatchedUnix      int64   `json:"matched_unix,omitempty"`
}

// CVEEnrichment is the per-CVE prioritization signal the KEV/EPSS feeds overlay on
// a verdict row: KEV membership and the EPSS score. It is the same fact for every
// tenant, so EnrichNodeCVEs applies it fleet-wide by CVE.
type CVEEnrichment struct {
	KEV  bool
	EPSS float64
}

// ImageComponentRecord is one entry of a container image's flattened component set,
// keyed by the image's content Digest ("sha256:<hex>"). It mirrors ComponentRecord
// minus the node id: an image's components are a property of the digest, identical
// for every node and tenant running it, so they are stored ONCE here rather than
// copied per node. Source is the digest-pinned image source string the agent
// reported ("image:<ref>@sha256:<hex>"), kept verbatim so a verdict points at the
// exact image. Keyed (Digest, Purl, Source).
type ImageComponentRecord struct {
	Digest    string `json:"digest"`
	Purl      string `json:"purl"`
	Source    string `json:"source"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	Distro    string `json:"distro,omitempty"`
}

// ImageCVERecord is one computed verdict for an image digest: a (digest, cve, purl)
// answer, matched ONCE per digest and fanned to every associated node on read. It
// carries the same supporting detail as NodeCVERecord minus the node id; the node id
// is supplied at fan-out time from the node->digest association. Keyed (Digest, CVE,
// Purl).
type ImageCVERecord struct {
	Digest           string  `json:"digest"`
	CVE              string  `json:"cve"`
	Purl             string  `json:"purl"`
	Status           string  `json:"status,omitempty"`
	Severity         string  `json:"severity,omitempty"`
	KEV              bool    `json:"kev,omitempty"`
	EPSS             float64 `json:"epss,omitempty"`
	VEXJustification string  `json:"vex_justification,omitempty"`
	FixedVersion     string  `json:"fixed_version,omitempty"`
	MatchedUnix      int64   `json:"matched_unix,omitempty"`
}

// NodeImageAssoc is one (node, digest) row of a workspace's node->image association
// set, the unit the by-cve fan-out enumerates to resolve which nodes run a digest.
type NodeImageAssoc struct {
	NodeID string
	Digest string
}

// cveNodeRow is one (cve, node) verdict the workspace rollup aggregates, carrying
// the supporting fields the representative pick uses. Both stores resolve the
// host+image union into these rows, then the shared aggregator collapses them into
// the per-CVE rollup so the distinct-node counting and the representative status/
// severity/fix selection are identical across engines.
type cveNodeRow struct {
	CVE          string
	NodeID       string
	Status       string
	Severity     string
	FixedVersion string
}

// WorkspaceCVERollup is one row of the fleet-wide vulnerability listing: a CVE that
// affects at least one node in the workspace, with the representative severity and
// status, the version that fixes it, and the distinct nodes it touches. NodeCount is
// the count of distinct nodes (so a node carrying the CVE from both its host and a
// container image counts once, and two nodes sharing an affected image count twice).
// Nodes is the distinct node-id list backing that count.
type WorkspaceCVERollup struct {
	CVE          string   `json:"cve"`
	Severity     string   `json:"severity,omitempty"`
	Status       string   `json:"status,omitempty"`
	FixedVersion string   `json:"fixed_version,omitempty"`
	NodeCount    int      `json:"node_count"`
	Nodes        []string `json:"nodes,omitempty"`
}

// OpenStoreFor opens the persistence backend the config selects: the default
// bbolt file, or the pgx-backed SQL store when store is postgres. Everything
// downstream holds the Store interface, so the choice is invisible past this
// point.
func OpenStoreFor(cfg *Config) (Store, error) {
	switch cfg.StoreBackend {
	case "", "bbolt":
		return OpenStore(cfg.StatePath())
	case "postgres", "mariadb", "mysql":
		if cfg.StoreDSN == "" {
			return nil, fmt.Errorf("store=%q requires store_dsn", cfg.StoreBackend)
		}
		return OpenSQLStore(context.Background(), cfg.StoreBackend, cfg.StoreDSN)
	default:
		return nil, fmt.Errorf("unknown store backend %q", cfg.StoreBackend)
	}
}

func OpenStore(path string) (Store, error) {
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open state db %s: %w", path, err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		for _, b := range [][]byte{bucketWS, bucketWorkspaces, bucketNodeWS, bucketTokens, bucketSettings, bucketArtifact, bucketSrcBindings, bucketOSEnroll, bucketRevokedCerts, bucketAuthSessions, bucketDeviceCodes, bucketUserCodes, bucketHandoffCodes, bucketWSTickets, bucketSuspensions, bucketQuarantines, bucketAgentAffinity, bucketRelays, bucketAgentPresence, bucketControllers, bucketAdvisories, bucketImageComponents, bucketImageCVE, bucketManagedCerts, bucketSubdomains, bucketFunnels} {
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
	return &bboltStore{db: db}, nil
}

func (s *bboltStore) Close() error { return s.db.Close() }

// TryReconcileLock: a single-node bbolt controller is the only writer, so it always
// grants the rebuild lock and the release is a no-op.
func (s *bboltStore) TryReconcileLock(context.Context) (bool, func(), error) {
	return true, func() {}, nil
}

// TryVulnSyncLock: a single-node bbolt controller is the only writer, so it always
// grants the feed-sync lock and the release is a no-op.
func (s *bboltStore) TryVulnSyncLock(context.Context) (bool, func(), error) {
	return true, func() {}, nil
}

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

func (s *bboltStore) PutWorkspace(rec *WorkspaceRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error { return putJSON(tx, bucketWorkspaces, rec.ID, rec) })
}

func (s *bboltStore) GetWorkspace(id string) (*WorkspaceRecord, error) {
	var rec WorkspaceRecord
	err := s.db.View(func(tx *bbolt.Tx) error { return getJSON(tx, bucketWorkspaces, id, &rec) })
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *bboltStore) ListWorkspaces() ([]*WorkspaceRecord, error) {
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

func (s *bboltStore) PutNetwork(rec *NetworkRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, rec.WorkspaceID, childNetworks)
		if err != nil {
			return err
		}
		return putJSONB(b, rec.ID, rec)
	})
}

func (s *bboltStore) ListNetworks(ws string) ([]*NetworkRecord, error) {
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

func (s *bboltStore) PutSubnet(rec *SubnetRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, rec.WorkspaceID, childSubnets)
		if err != nil {
			return err
		}
		return putJSONB(b, rec.ID, rec)
	})
}

func (s *bboltStore) ListSubnets(ws string) ([]*SubnetRecord, error) {
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

func (s *bboltStore) PutBinding(rec *BindingRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, rec.WorkspaceID, childBindings)
		if err != nil {
			return err
		}
		return putJSONB(b, bindingKey(rec.VNI, rec.NodeID), rec)
	})
}

func (s *bboltStore) GetBinding(ws string, vni uint32, nodeID string) (*BindingRecord, error) {
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
func (s *bboltStore) ListBindings(ws string, vni uint32) ([]*BindingRecord, error) {
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

// --- nodes (per-workspace) ---

func (s *bboltStore) PutNode(ws string, n *NodeRecord) error {
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

func (s *bboltStore) GetNode(ws, id string) (*NodeRecord, error) {
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
func (s *bboltStore) WorkspaceForNode(id string) (string, error) {
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
func (s *bboltStore) GetNodeModules(ws, nodeID string) (*NodeModulesRecord, error) {
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
func (s *bboltStore) SetNodeModules(ws, nodeID string, modules []NodeModule) (*NodeModulesRecord, error) {
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
func (s *bboltStore) DeleteNode(ws, id string) error {
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
		if sb := wsChildR(tx, ws, childSBOMs); sb != nil {
			_ = sb.Delete([]byte(id))
		}
		if cb := wsChildR(tx, ws, childComponents); cb != nil {
			if err := deletePrefix(cb, nodePrefix(id)); err != nil {
				return err
			}
		}
		if vb := wsChildR(tx, ws, childNodeCVE); vb != nil {
			if err := deletePrefix(vb, nodePrefix(id)); err != nil {
				return err
			}
		}
		// Drop the node's image-digest associations so a deleted node no longer fans a
		// digest's verdicts to itself. The global image components/verdicts are left
		// intact: other nodes may still run the same digest.
		if ib := wsChildR(tx, ws, childNodeImages); ib != nil {
			if err := deletePrefix(ib, nodePrefix(id)); err != nil {
				return err
			}
		}
		return tx.Bucket(bucketNodeWS).Delete([]byte(id))
	})
}

// SetNodeApproval flips a node's admission gate transactionally and returns the
// updated record. by is the admin name (or "auto:<provider>") recorded for audit.
func (s *bboltStore) SetNodeApproval(ws, id string, approve bool, by string, now time.Time) (*NodeRecord, error) {
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
			// The blessed binary baseline is deliberately PRESERVED across re-approval,
			// not cleared: a node re-approved while still running a tampered (non-release)
			// binary keeps the old baseline, so its next heartbeat mismatches and it
			// re-quarantines — re-approval can't launder a still-bad binary. A genuine
			// recovery (back to the baseline, or forward to a controller-published signed
			// release) reconciles through the normal measurement verdict.
		} else {
			n.ApprovedBy = ""
			n.ApprovedAtUnix = 0
		}
		if err := putJSONB(b, id, &n); err != nil {
			return err
		}
		if approve {
			// Re-approval IS the admin's acknowledgement that a drifted node is trusted
			// again: clear any sticky quarantine in the same transaction so the deny and
			// its cause are lifted together.
			if qb := tx.Bucket(bucketQuarantines); qb != nil {
				if err := qb.Delete([]byte(quarantineKey(ws, id))); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// RecordNodeMeasurement stores the agent's latest self-measured binary hash and the
// controller's receipt time, and maintains the pinned baseline: the FIRST measurement
// seen while a node is approved becomes ApprovedBinaryHash (trust the binary the
// admin approved). It returns drift=true when an approved node reports a hash that
// differs from its pinned baseline — the caller quarantines. An unapproved node
// never pins and never drifts (it has no baseline to violate yet).
func (s *bboltStore) RecordNodeMeasurement(ws, nodeID string, binHash []byte, atUnix int64) (drift, pinned bool, n *NodeRecord, err error) {
	if len(binHash) != sha256Len {
		return false, false, nil, fmt.Errorf("binary hash must be %d bytes, got %d", sha256Len, len(binHash))
	}
	var rec NodeRecord
	uerr := s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, ws, childNodes)
		if err != nil {
			return err
		}
		if err := getJSONB(b, nodeID, &rec); err != nil {
			return err
		}
		rec.LastBinaryHash = binHash
		rec.LastMeasuredUnix = atUnix
		if rec.Approved {
			if len(rec.ApprovedBinaryHash) == 0 {
				rec.ApprovedBinaryHash = binHash
				pinned = true
			} else if !bytes.Equal(rec.ApprovedBinaryHash, binHash) {
				drift = true
			}
		}
		return putJSONB(b, nodeID, &rec)
	})
	if uerr != nil {
		return false, false, nil, uerr
	}
	return drift, pinned, &rec, nil
}

// RepinBaseline accepts a node's current self-measurement as the new blessed
// baseline and records the release's publish time as the anti-rollback floor. The
// controller calls it when a changed binary hash is in fact a sanctioned release it
// published (manual or automatic update), and when first-pinning a published
// baseline, so the upgrade re-pins instead of quarantining. createdUnix is 0 for an
// unpublished/custom binary (no rollback floor to enforce).
func (s *bboltStore) RepinBaseline(ws, nodeID string, binHash []byte, createdUnix int64) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, ws, childNodes)
		if err != nil {
			return err
		}
		var n NodeRecord
		if err := getJSONB(b, nodeID, &n); err != nil {
			return err
		}
		n.ApprovedBinaryHash = binHash
		n.ApprovedBinaryCreatedUnix = createdUnix
		n.LastBinaryHash = binHash
		return putJSONB(b, nodeID, &n)
	})
}

// FindNode resolves a node by id first, then by unique name, WITHIN a workspace.
// Ambiguous names fail closed. A node in another workspace is not found.
func (s *bboltStore) FindNode(ws, idOrName string) (*NodeRecord, error) {
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

func (s *bboltStore) ListNodes(ws string) ([]*NodeRecord, error) {
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
func (s *bboltStore) ListAllNodes() ([]*NodeRecord, error) {
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

func (s *bboltStore) PutToken(token string, rec *TokenRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error { return putJSON(tx, bucketTokens, token, rec) })
}

// UseToken transactionally consumes one use of a join token. The expiry and
// use-count checks happen inside the write transaction so concurrent enrolls
// cannot double-spend a single-use token.
func (s *bboltStore) UseToken(token string, now time.Time) (*TokenRecord, error) {
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

// --- cloud-qualified source bindings (the workspace is the hub) ---

// SourceBinding maps an external identity source onto a workspace. Key is the
// cloud-qualified binding string (openstack:project:<svc>:<uuid>, idp:group:...,
// invite:...). One binding serves both enrollment (a VM's project) and access (a
// user's project) — they resolve to the same workspace by construction.
type SourceBinding struct {
	Key             string `json:"key"`
	WorkspaceID     string `json:"workspace_id"`
	CreatedUnix     int64  `json:"created_unix"`
	CreatedBy       string `json:"created_by,omitempty"`       // admin name, or "auto:openstack"
	AutoProvisioned bool   `json:"auto_provisioned,omitempty"` // workspace was created for this binding
}

func (s *bboltStore) PutSourceBinding(rec *SourceBinding) error {
	return s.db.Update(func(tx *bbolt.Tx) error { return putJSON(tx, bucketSrcBindings, rec.Key, rec) })
}

func (s *bboltStore) GetSourceBinding(key string) (*SourceBinding, error) {
	var rec SourceBinding
	err := s.db.View(func(tx *bbolt.Tx) error { return getJSON(tx, bucketSrcBindings, key, &rec) })
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *bboltStore) ListSourceBindings() ([]*SourceBinding, error) {
	var out []*SourceBinding
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketSrcBindings).ForEach(func(_, v []byte) error {
			var rec SourceBinding
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
	return out, nil
}

func (s *bboltStore) DeleteSourceBinding(key string) error {
	return s.db.Update(func(tx *bbolt.Tx) error { return tx.Bucket(bucketSrcBindings).Delete([]byte(key)) })
}

// --- OpenStack enrollment idempotency ---

// OSEnrollRecord remembers the join token minted for one (service-uid,instance)
// so Nova's ~5 near-simultaneous vendordata hits per boot all get the SAME
// token instead of cutting five.
type OSEnrollRecord struct {
	Key         string `json:"key"` // "<service-uid>#<instance-uuid>"
	Token       string `json:"token"`
	WorkspaceID string `json:"workspace_id"`
	ProjectID   string `json:"project_id"`
	CreatedUnix int64  `json:"created_unix"`
}

// OSMintOnce atomically returns the join token for key, minting one only if none
// exists yet (or the prior one has aged past dedupeTTL). The token record and the
// dedupe entry are written in a SINGLE write transaction, so concurrent Nova
// hits cannot race to mint multiple tokens. tok is the TokenRecord to store for
// a freshly minted token; newToken generates the random token string. Returns
// the token and whether it was reused.
func (s *bboltStore) OSMintOnce(key string, now time.Time, dedupeTTL time.Duration, tok *TokenRecord, newToken func() (string, error)) (token string, reused bool, err error) {
	err = s.db.Update(func(tx *bbolt.Tx) error {
		var prev OSEnrollRecord
		if e := getJSON(tx, bucketOSEnroll, key, &prev); e == nil {
			fresh := now.Sub(time.Unix(prev.CreatedUnix, 0)) < dedupeTTL
			// Only reuse if the token still exists and has unspent uses (a node
			// already enrolled with it ⇒ mint a new one for an honest re-serve only
			// while unredeemed; a redeemed token must not be handed out again).
			var tr TokenRecord
			tokenLive := getJSON(tx, bucketTokens, prev.Token, &tr) == nil && tr.Uses < tr.MaxUses && now.Unix() <= tr.ExpiresUnix
			if fresh && tokenLive {
				token, reused = prev.Token, true
				return nil
			}
		} else if !errors.Is(e, ErrNotFound) {
			return e
		}
		t, e := newToken()
		if e != nil {
			return e
		}
		if e := putJSON(tx, bucketTokens, t, tok); e != nil {
			return e
		}
		rec := OSEnrollRecord{Key: key, Token: t, WorkspaceID: tok.WorkspaceID, ProjectID: tok.Labels["os:project"], CreatedUnix: now.Unix()}
		if e := putJSON(tx, bucketOSEnroll, key, &rec); e != nil {
			return e
		}
		token = t
		return nil
	})
	return token, reused, err
}

// --- leaf-cert revocation ---

// RevokedCert is one entry in the revocation denylist, keyed by the cert's
// serial number in lower-case hex (big.Int.Text(16)).
type RevokedCert struct {
	Serial      string `json:"serial"`
	RevokedUnix int64  `json:"revoked_unix"`
	By          string `json:"by,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Subject     string `json:"subject,omitempty"` // best-effort human hint (kind:name)
}

func (s *bboltStore) RevokeCert(rec *RevokedCert) error {
	return s.db.Update(func(tx *bbolt.Tx) error { return putJSON(tx, bucketRevokedCerts, rec.Serial, rec) })
}

// IsCertRevoked reports whether a serial-hex is on the denylist. Hot path: a
// single bbolt read per authenticated RPC. A local read error fails OPEN (a bbolt
// fault is not a partition) — this is the single-node behavior the deny cache's
// fail-open branch preserves.
func (s *bboltStore) IsCertRevoked(serialHex string) bool {
	revoked, _ := s.IsCertRevokedE(serialHex)
	return revoked
}

// IsCertRevokedE is the error-returning twin: it reports the denylist hit and any
// read error so the deny cache can distinguish "definitely not revoked" from "I
// could not tell".
func (s *bboltStore) IsCertRevokedE(serialHex string) (bool, error) {
	revoked := false
	err := s.db.View(func(tx *bbolt.Tx) error {
		revoked = tx.Bucket(bucketRevokedCerts).Get([]byte(serialHex)) != nil
		return nil
	})
	return revoked, err
}

func (s *bboltStore) ListRevokedCerts() ([]*RevokedCert, error) {
	var out []*RevokedCert
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketRevokedCerts).ForEach(func(_, v []byte) error {
			var rec RevokedCert
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
	return out, nil
}

// --- sessions (per-workspace) ---

func (s *bboltStore) PutSession(ws string, rec *SessionRecord) error {
	rec.WorkspaceID = ws
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, ws, childSessions)
		if err != nil {
			return err
		}
		return putJSONB(b, rec.ID, rec)
	})
}

func (s *bboltStore) GetSession(ws, id string) (*SessionRecord, error) {
	var rec SessionRecord
	err := s.db.View(func(tx *bbolt.Tx) error { return getJSONB(wsChildR(tx, ws, childSessions), id, &rec) })
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// UpdateSession applies fn to the stored record inside one transaction.
func (s *bboltStore) UpdateSession(ws, id string, fn func(*SessionRecord)) error {
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

func (s *bboltStore) ListSessions(ws string) ([]*SessionRecord, error) {
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

// QuerySessions filters, sorts and pages in memory (bbolt is the single-node
// store, with no secondary indexes); the SQL store does the equivalent in the
// database. The response is bounded either way.
func (s *bboltStore) QuerySessions(ws string, q SessionQuery) ([]*SessionRecord, int, error) {
	all, err := s.ListSessions(ws)
	if err != nil {
		return nil, 0, err
	}
	all = filterSessions(all, q)
	sortSessions(all, q.Sort, q.Order)
	total := len(all)
	lo, hi := q.Page.bounds(total)
	return all[lo:hi], total, nil
}

// ListAllSessions returns sessions across ALL workspaces, UNORDERED — its only
// callers (the continuous-authz sweep and the revoke fan-outs) re-evaluate every
// session independently, so an O(M log M) sort of the whole set each tick would
// be pure overhead.
func (s *bboltStore) ListAllSessions() ([]*SessionRecord, error) {
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
	return out, nil
}

// --- recordings (per-workspace) ---

func (s *bboltStore) PutRecording(ws string, rec *RecordingRecord) error {
	rec.WorkspaceID = ws
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, ws, childRecordings)
		if err != nil {
			return err
		}
		return putJSONB(b, rec.SessionID, rec)
	})
}

func (s *bboltStore) GetRecording(ws, sessionID string) (*RecordingRecord, error) {
	var rec RecordingRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		return getJSONB(wsChildR(tx, ws, childRecordings), sessionID, &rec)
	})
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *bboltStore) ListRecordings(ws string) ([]*RecordingRecord, error) {
	var out []*RecordingRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childRecordings)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var rec RecordingRecord
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

func (s *bboltStore) DeleteRecording(ws, sessionID string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childRecordings)
		if b == nil {
			return ErrNotFound
		}
		if b.Get([]byte(sessionID)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(sessionID))
	})
}

// --- software inventory (per-workspace SBOMs, components, computed cve set) ---

// keySep separates the parts of a composite bbolt key. A NUL byte cannot occur in
// a purl, node id or cve, so it is an unambiguous boundary for a prefix scan.
const keySep = "\x00"

// nodePrefix is the key prefix every component/cve row for one node shares, so a
// per-node list (or a cascade delete) is a single prefix scan.
func nodePrefix(nodeID string) []byte { return []byte(nodeID + keySep) }

func componentKey(nodeID, purl, source string) []byte {
	return []byte(nodeID + keySep + purl + keySep + source)
}

func nodeCVEKey(nodeID, cve, purl string) []byte {
	return []byte(nodeID + keySep + cve + keySep + purl)
}

// digestPrefix is the key prefix every image-component / image-cve row for one
// digest shares, so a per-digest list (or a replace-set delete) is a single prefix
// scan in the global image buckets.
func digestPrefix(digest string) []byte { return []byte(digest + keySep) }

func imageComponentKey(digest, purl, source string) []byte {
	return []byte(digest + keySep + purl + keySep + source)
}

func imageCVEKey(digest, cve, purl string) []byte {
	return []byte(digest + keySep + cve + keySep + purl)
}

// nodeImageKey is the per-workspace node->digest association key (node-first so a
// node's whole association set is one prefix scan, and a node delete is a prefix
// delete).
func nodeImageKey(nodeID, digest string) []byte {
	return []byte(nodeID + keySep + digest)
}

// deletePrefix removes every key in b that begins with prefix, using a cursor so
// the scan and the deletes share one pass.
func deletePrefix(b *bbolt.Bucket, prefix []byte) error {
	c := b.Cursor()
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
		if err := c.Delete(); err != nil {
			return err
		}
	}
	return nil
}

func (s *bboltStore) PutNodeSBOM(ws, nodeID string, rec *NodeSBOMRecord) error {
	rec.WorkspaceID = ws
	rec.NodeID = nodeID
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, ws, childSBOMs)
		if err != nil {
			return err
		}
		return putJSONB(b, nodeID, rec)
	})
}

func (s *bboltStore) GetNodeSBOM(ws, nodeID string) (*NodeSBOMRecord, error) {
	var rec NodeSBOMRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		return getJSONB(wsChildR(tx, ws, childSBOMs), nodeID, &rec)
	})
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// UpsertNodeComponents replaces a node's whole component set: the prior rows are
// dropped and the supplied set written, so a re-index never leaves a stale
// component behind. The empty set clears the node.
func (s *bboltStore) UpsertNodeComponents(ws, nodeID string, comps []ComponentRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, ws, childComponents)
		if err != nil {
			return err
		}
		if err := deletePrefix(b, nodePrefix(nodeID)); err != nil {
			return err
		}
		for i := range comps {
			c := comps[i]
			c.WorkspaceID = ws
			c.NodeID = nodeID
			if err := putJSONB(b, string(componentKey(nodeID, c.Purl, c.Source)), &c); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *bboltStore) ListNodeComponents(ws, nodeID string) ([]ComponentRecord, error) {
	var out []ComponentRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childComponents)
		if b == nil {
			return nil
		}
		prefix := nodePrefix(nodeID)
		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var rec ComponentRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListComponentsByPackage is the "who has package X" fast path: every node in the
// workspace carrying a component of (ecosystem, name). bbolt has no secondary
// index, so it scans the workspace's components and filters — the same in-memory
// filter the other bbolt list views use; the SQL store serves it from an index.
func (s *bboltStore) ListComponentsByPackage(ws, ecosystem, name string) ([]ComponentRecord, error) {
	var out []ComponentRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childComponents)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var rec ComponentRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.Ecosystem == ecosystem && rec.Name == name {
				out = append(out, rec)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *bboltStore) UpsertNodeCVE(rec *NodeCVERecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, rec.WorkspaceID, childNodeCVE)
		if err != nil {
			return err
		}
		return putJSONB(b, string(nodeCVEKey(rec.NodeID, rec.CVE, rec.Purl)), rec)
	})
}

// ClearNodeCVEs drops every verdict row for one node (a prefix delete on the
// node-first key), so a re-match writes a clean replace-set.
func (s *bboltStore) ClearNodeCVEs(ws, nodeID string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childNodeCVE)
		if b == nil {
			return nil
		}
		return deletePrefix(b, nodePrefix(nodeID))
	})
}

// CVEsForNode lists every computed cve row for one node, a prefix scan on the
// node-first key.
func (s *bboltStore) CVEsForNode(ws, nodeID string) ([]NodeCVERecord, error) {
	var out []NodeCVERecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childNodeCVE)
		if b == nil {
			return nil
		}
		prefix := nodePrefix(nodeID)
		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var rec NodeCVERecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// NodesAffectedByCVE lists every computed row for one cve within the workspace.
// The bbolt key is node-first (so CVEsForNode is a prefix scan), so this filters
// on the cve in a full workspace scan; the SQL store serves it from the (cve,
// status) index.
func (s *bboltStore) NodesAffectedByCVE(ws, cve string) ([]NodeCVERecord, error) {
	var out []NodeCVERecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childNodeCVE)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var rec NodeCVERecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.CVE == cve {
				out = append(out, rec)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// WorkspaceCVERollups builds the fleet-wide listing from the workspace's host
// node_cve rows unioned with its image_cve verdicts fanned through the node->digest
// associations, then aggregates them into one rollup per CVE. bbolt has no join, so
// it gathers the union as flat (cve, node) rows and the shared aggregator does the
// distinct-node counting and representative pick.
func (s *bboltStore) WorkspaceCVERollups(ws string) ([]WorkspaceCVERollup, error) {
	var rows []cveNodeRow
	// Host verdicts: every node_cve row in the workspace.
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childNodeCVE)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var rec NodeCVERecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			rows = append(rows, cveNodeRow{
				CVE: rec.CVE, NodeID: rec.NodeID, Status: rec.Status,
				Severity: rec.Severity, FixedVersion: rec.FixedVersion,
			})
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	// Image verdicts: each digest a node runs contributes its image_cve verdicts to
	// that node, so a shared image fans to every node carrying it.
	digestNodes, err := workspaceDigestNodes(s, ws)
	if err != nil {
		return nil, err
	}
	for digest, nodes := range digestNodes {
		ivs, err := s.ImageCVEsForDigest(digest)
		if err != nil {
			return nil, err
		}
		for _, iv := range ivs {
			for _, nodeID := range nodes {
				rows = append(rows, cveNodeRow{
					CVE: iv.CVE, NodeID: nodeID, Status: iv.Status,
					Severity: iv.Severity, FixedVersion: iv.FixedVersion,
				})
			}
		}
	}
	return rollupCVENodeRows(rows), nil
}

// EnrichNodeCVEs overlays KEV/EPSS onto every node_cve row whose CVE is in scores,
// across every workspace, in one transaction. It walks each workspace's node_cve
// child bucket and rewrites only the rows whose fields actually change, so a
// re-apply of the same scores touches nothing. Returns the number of rows updated.
func (s *bboltStore) EnrichNodeCVEs(scores map[string]CVEEnrichment) (int, error) {
	if len(scores) == 0 {
		return 0, nil
	}
	updated := 0
	err := s.db.Update(func(tx *bbolt.Tx) error {
		wsRoot := tx.Bucket(bucketWS)
		if wsRoot == nil {
			return nil
		}
		return wsRoot.ForEach(func(wsID, _ []byte) error {
			wsb := wsRoot.Bucket(wsID)
			if wsb == nil {
				return nil
			}
			cveB := wsb.Bucket([]byte(childNodeCVE))
			if cveB == nil {
				return nil
			}
			// Collect the rows to rewrite first; bbolt forbids mutating a bucket while a
			// cursor over it is open.
			type pending struct {
				key []byte
				rec NodeCVERecord
			}
			var todo []pending
			if err := cveB.ForEach(func(k, v []byte) error {
				var rec NodeCVERecord
				if err := json.Unmarshal(v, &rec); err != nil {
					return err
				}
				e, ok := scores[rec.CVE]
				if !ok || (rec.KEV == e.KEV && rec.EPSS == e.EPSS) {
					return nil
				}
				rec.KEV = e.KEV
				rec.EPSS = e.EPSS
				todo = append(todo, pending{key: append([]byte(nil), k...), rec: rec})
				return nil
			}); err != nil {
				return err
			}
			for i := range todo {
				if err := putJSONB(cveB, string(todo[i].key), &todo[i].rec); err != nil {
					return err
				}
				updated++
			}
			return nil
		})
	})
	if err != nil {
		return 0, err
	}
	return updated, nil
}

// DistinctNodeCVEs collects every CVE id present in any workspace's node_cve
// bucket. bbolt has no index for this, so it scans; the set is bounded by the
// affected fan-out, not the fleet, which is what the enrichment pass needs.
func (s *bboltStore) DistinctNodeCVEs() ([]string, error) {
	seen := map[string]struct{}{}
	err := s.db.View(func(tx *bbolt.Tx) error {
		wsRoot := tx.Bucket(bucketWS)
		if wsRoot == nil {
			return nil
		}
		return wsRoot.ForEach(func(wsID, _ []byte) error {
			wsb := wsRoot.Bucket(wsID)
			if wsb == nil {
				return nil
			}
			cveB := wsb.Bucket([]byte(childNodeCVE))
			if cveB == nil {
				return nil
			}
			return cveB.ForEach(func(_, v []byte) error {
				var rec NodeCVERecord
				if err := json.Unmarshal(v, &rec); err != nil {
					return err
				}
				if rec.CVE != "" {
					seen[rec.CVE] = struct{}{}
				}
				return nil
			})
		})
	})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	return out, nil
}

// --- image digest dedup (global image components/verdicts + per-ws association) ---

// HasImageComponents reports whether an image digest's component set is already
// stored, so an inventory commit can skip re-storing (and a first-seen detector can
// trigger the initial match) without loading the whole set.
func (s *bboltStore) HasImageComponents(digest string) (bool, error) {
	found := false
	err := s.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(bucketImageComponents).Cursor()
		k, _ := c.Seek(digestPrefix(digest))
		found = k != nil && bytes.HasPrefix(k, digestPrefix(digest))
		return nil
	})
	return found, err
}

// PutImageComponents stores a digest's image component set, replacing any prior set
// for that digest. The digest is content-addressable, so a concurrent re-store of
// the same digest writes byte-identical rows — the replace-set is idempotent. The
// empty set clears the digest.
func (s *bboltStore) PutImageComponents(digest string, comps []ImageComponentRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketImageComponents)
		if err := deletePrefix(b, digestPrefix(digest)); err != nil {
			return err
		}
		for i := range comps {
			c := comps[i]
			c.Digest = digest
			if err := putJSONB(b, string(imageComponentKey(digest, c.Purl, c.Source)), &c); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListImageComponents lists a digest's stored image component set (a prefix scan).
func (s *bboltStore) ListImageComponents(digest string) ([]ImageComponentRecord, error) {
	var out []ImageComponentRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketImageComponents)
		prefix := digestPrefix(digest)
		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var rec ImageComponentRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ImageDigestsForPackage is the image-side "who has package X" fast path: every
// digest carrying a component of (ecosystem, name). It mirrors
// ListComponentsByPackage but over the global image set, so a changed advisory
// re-matches only the digests that carry its package, never every digest.
func (s *bboltStore) ImageDigestsForPackage(ecosystem, name string) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketImageComponents).ForEach(func(_, v []byte) error {
			var rec ImageComponentRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.Ecosystem == ecosystem && rec.Name == name {
				if _, ok := seen[rec.Digest]; !ok {
					seen[rec.Digest] = struct{}{}
					out = append(out, rec.Digest)
				}
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SetNodeImages replaces a node's image-digest association set (replace-set per
// node), so a node that stops running a digest no longer fans that digest's verdicts
// to itself. The empty set clears the node's associations.
func (s *bboltStore) SetNodeImages(ws, nodeID string, digests []string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, ws, childNodeImages)
		if err != nil {
			return err
		}
		if err := deletePrefix(b, nodePrefix(nodeID)); err != nil {
			return err
		}
		for _, d := range digests {
			if err := b.Put(nodeImageKey(nodeID, d), []byte{}); err != nil {
				return err
			}
		}
		return nil
	})
}

// NodeImageDigests lists the image digests a node currently runs (a prefix scan on
// the node-first association key).
func (s *bboltStore) NodeImageDigests(ws, nodeID string) ([]string, error) {
	var out []string
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childNodeImages)
		if b == nil {
			return nil
		}
		prefix := nodePrefix(nodeID)
		c := b.Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			// key is nodeID\x00digest; the digest is the part after the separator.
			rest := k[len(prefix):]
			out = append(out, string(rest))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// WorkspaceNodeImages lists every (node, digest) association in a workspace, the
// enumeration the by-cve fan-out walks to map digests to their running nodes. It does
// not depend on a node record existing — an inventory-only node still appears.
func (s *bboltStore) WorkspaceNodeImages(ws string) ([]NodeImageAssoc, error) {
	var out []NodeImageAssoc
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childNodeImages)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, _ []byte) error {
			// key is nodeID\x00digest.
			node, digest, ok := strings.Cut(string(k), keySep)
			if !ok {
				return nil
			}
			out = append(out, NodeImageAssoc{NodeID: node, Digest: digest})
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// NodesRunningDigest lists the nodes in a workspace currently associated with a
// digest, the fan-out direction for NodesAffectedByCVE. bbolt has no secondary
// index, so it scans the workspace's associations and filters on the digest suffix.
func (s *bboltStore) NodesRunningDigest(ws, digest string) ([]string, error) {
	var out []string
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childNodeImages)
		if b == nil {
			return nil
		}
		suffix := keySep + digest
		return b.ForEach(func(k, _ []byte) error {
			ks := string(k)
			if strings.HasSuffix(ks, suffix) {
				out = append(out, ks[:len(ks)-len(suffix)])
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PutImageCVE upserts one image-digest verdict.
func (s *bboltStore) PutImageCVE(rec *ImageCVERecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return putJSONB(tx.Bucket(bucketImageCVE), string(imageCVEKey(rec.Digest, rec.CVE, rec.Purl)), rec)
	})
}

// ClearImageCVEs drops every verdict row for one digest, so a digest re-match writes
// a clean replace-set (a feed retraction leaves no stale verdict behind).
func (s *bboltStore) ClearImageCVEs(digest string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return deletePrefix(tx.Bucket(bucketImageCVE), digestPrefix(digest))
	})
}

// ImageCVEsForDigest lists every computed verdict for one digest (a prefix scan).
func (s *bboltStore) ImageCVEsForDigest(digest string) ([]ImageCVERecord, error) {
	var out []ImageCVERecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketImageCVE)
		prefix := digestPrefix(digest)
		c := b.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var rec ImageCVERecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DistinctImageCVEs returns every CVE id present in any image_cve row, so the
// enrichment pass can include image-side verdicts alongside the per-node ones.
func (s *bboltStore) DistinctImageCVEs() ([]string, error) {
	seen := map[string]struct{}{}
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketImageCVE).ForEach(func(_, v []byte) error {
			var rec ImageCVERecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.CVE != "" {
				seen[rec.CVE] = struct{}{}
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	return out, nil
}

// EnrichImageCVEs overlays KEV/EPSS onto every image_cve row whose CVE is in scores,
// the image-side twin of EnrichNodeCVEs. It rewrites only rows whose fields actually
// change, so a re-apply touches nothing. Returns the number of rows updated.
func (s *bboltStore) EnrichImageCVEs(scores map[string]CVEEnrichment) (int, error) {
	if len(scores) == 0 {
		return 0, nil
	}
	updated := 0
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketImageCVE)
		type pending struct {
			key []byte
			rec ImageCVERecord
		}
		var todo []pending
		if err := b.ForEach(func(k, v []byte) error {
			var rec ImageCVERecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			e, ok := scores[rec.CVE]
			if !ok || (rec.KEV == e.KEV && rec.EPSS == e.EPSS) {
				return nil
			}
			rec.KEV = e.KEV
			rec.EPSS = e.EPSS
			todo = append(todo, pending{key: append([]byte(nil), k...), rec: rec})
			return nil
		}); err != nil {
			return err
		}
		for i := range todo {
			if err := putJSONB(b, string(todo[i].key), &todo[i].rec); err != nil {
				return err
			}
			updated++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return updated, nil
}

// --- advisories (global) ---

// PutAdvisories upserts a batch of advisories in one transaction so a feed sync
// lands atomically.
func (s *bboltStore) PutAdvisories(recs []AdvisoryRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketAdvisories)
		for i := range recs {
			if err := putJSONB(b, recs[i].ID, &recs[i]); err != nil {
				return err
			}
		}
		return nil
	})
}

// AdvisoriesForPackage resolves the advisories filed against (ecosystem, name),
// the matcher's inner lookup. bbolt scans and filters; the SQL store uses the
// (ecosystem, package_name) index.
func (s *bboltStore) AdvisoriesForPackage(ecosystem, name string) ([]AdvisoryRecord, error) {
	var out []AdvisoryRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketAdvisories).ForEach(func(_, v []byte) error {
			var rec AdvisoryRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.Ecosystem == ecosystem && rec.PackageName == name {
				out = append(out, rec)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// --- settings (global) ---

func (s *bboltStore) SetSetting(key string, val []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketSettings).Put([]byte(key), val)
	})
}

func (s *bboltStore) GetSetting(key string) ([]byte, error) {
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

func (s *bboltStore) getStringSetting(key string) (string, error) {
	b, err := s.GetSetting(key)
	return string(b), err
}

func (s *bboltStore) StableVersion() (string, error) { return s.getStringSetting(settingStableVersion) }
func (s *bboltStore) CanaryVersion() (string, error) { return s.getStringSetting(settingCanaryVersion) }

func (s *bboltStore) SetStableVersion(v string) error {
	return s.SetSetting(settingStableVersion, []byte(v))
}

func (s *bboltStore) SetCanaryVersion(v string) error {
	return s.SetSetting(settingCanaryVersion, []byte(v))
}

func (s *bboltStore) CanaryNodes() ([]string, error) {
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

func (s *bboltStore) SetCanaryNodes(nodes []string) error {
	b, err := json.Marshal(nodes)
	if err != nil {
		return err
	}
	return s.SetSetting(settingCanaryNodes, b)
}

// Relay rollout ring: a parallel set of getters/setters keyed on the relay
// settings keys, so the relay rollout is independent of the agent ring.
func (s *bboltStore) RelayStableVersion() (string, error) {
	return s.getStringSetting(settingRelayStableVersion)
}
func (s *bboltStore) RelayCanaryVersion() (string, error) {
	return s.getStringSetting(settingRelayCanaryVersion)
}

func (s *bboltStore) SetRelayStableVersion(v string) error {
	return s.SetSetting(settingRelayStableVersion, []byte(v))
}

func (s *bboltStore) SetRelayCanaryVersion(v string) error {
	return s.SetSetting(settingRelayCanaryVersion, []byte(v))
}

func (s *bboltStore) RelayCanaryNodes() ([]string, error) {
	b, err := s.GetSetting(settingRelayCanaryNodes)
	if err != nil || len(b) == 0 {
		return nil, err
	}
	var out []string
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("settings %s: %w", settingRelayCanaryNodes, err)
	}
	return out, nil
}

func (s *bboltStore) SetRelayCanaryNodes(nodes []string) error {
	b, err := json.Marshal(nodes)
	if err != nil {
		return err
	}
	return s.SetSetting(settingRelayCanaryNodes, b)
}

func (s *bboltStore) ClusterConfigVersion() (int64, error) {
	b, err := s.GetSetting(settingClusterConfigVersion)
	if err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, nil
	}
	return strconv.ParseInt(string(b), 10, 64)
}

func (s *bboltStore) SetSignedClusterConfig(version int64, signed []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSettings)
		if err := b.Put([]byte(settingClusterConfigVersion), []byte(strconv.FormatInt(version, 10))); err != nil {
			return err
		}
		return b.Put([]byte(settingSignedClusterConfig), signed)
	})
}

func (s *bboltStore) SignedClusterConfig() ([]byte, error) {
	return s.GetSetting(settingSignedClusterConfig)
}

func (s *bboltStore) ClusterConfigSnapshot() (int64, []byte, error) {
	var v int64
	var signed []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSettings)
		if raw := b.Get([]byte(settingClusterConfigVersion)); len(raw) > 0 {
			parsed, perr := strconv.ParseInt(string(raw), 10, 64)
			if perr != nil {
				return perr
			}
			v = parsed
		}
		if raw := b.Get([]byte(settingSignedClusterConfig)); raw != nil {
			signed = append([]byte(nil), raw...)
		}
		return nil
	})
	return v, signed, err
}

func (s *bboltStore) FleetStateSnapshot() (int64, []byte, int64, []byte, error) {
	var mapV, anchorV int64
	var mapSigned, anchorSigned []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSettings)
		if raw := b.Get([]byte(settingClusterConfigVersion)); len(raw) > 0 {
			parsed, perr := strconv.ParseInt(string(raw), 10, 64)
			if perr != nil {
				return perr
			}
			mapV = parsed
		}
		if raw := b.Get([]byte(settingSignedClusterConfig)); raw != nil {
			mapSigned = append([]byte(nil), raw...)
		}
		if raw := b.Get([]byte(settingAnchorVersion)); len(raw) > 0 {
			parsed, perr := strconv.ParseInt(string(raw), 10, 64)
			if perr != nil {
				return perr
			}
			anchorV = parsed
		}
		if raw := b.Get([]byte(settingSignedAnchor)); raw != nil {
			anchorSigned = append([]byte(nil), raw...)
		}
		return nil
	})
	return mapV, mapSigned, anchorV, anchorSigned, err
}

// SetSignedFleetState writes the routine map and (optionally) the trust anchors in
// one bbolt transaction. The single-node bbolt store is the only writer, so the
// version CAS is satisfied sequentially; the cross-binding invariant — the map may
// only reference the anchor the row ends up holding — is still enforced so a
// mismatched pair can never be persisted even by a buggy caller.
func (s *bboltStore) SetSignedFleetState(mapVersion int64, mapSigned []byte, mapAnchorVersion int64, anchorVersion int64, anchorSigned []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSettings)
		curAnchor := int64(0)
		if raw := b.Get([]byte(settingAnchorVersion)); len(raw) > 0 {
			parsed, perr := strconv.ParseInt(string(raw), 10, 64)
			if perr != nil {
				return perr
			}
			curAnchor = parsed
		}
		advanceAnchor := anchorSigned != nil
		effectiveAnchor := curAnchor
		if advanceAnchor {
			effectiveAnchor = anchorVersion
		}
		if mapAnchorVersion != effectiveAnchor {
			return fmt.Errorf("routine map references anchor v%d but the row holds anchor v%d", mapAnchorVersion, effectiveAnchor)
		}
		if advanceAnchor {
			if err := b.Put([]byte(settingAnchorVersion), []byte(strconv.FormatInt(anchorVersion, 10))); err != nil {
				return err
			}
			if err := b.Put([]byte(settingSignedAnchor), anchorSigned); err != nil {
				return err
			}
		}
		if err := b.Put([]byte(settingClusterConfigVersion), []byte(strconv.FormatInt(mapVersion, 10))); err != nil {
			return err
		}
		return b.Put([]byte(settingSignedClusterConfig), mapSigned)
	})
}

// --- artifact manifests (global) ---

// ManifestKey builds the artifacts bucket key.
func ManifestKey(product, osName, arch, version string) string {
	return product + "/" + osName + "/" + arch + "/" + version
}

func (s *bboltStore) PutManifest(key string, signed []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketArtifact).Put([]byte(key), signed)
	})
}

func (s *bboltStore) GetManifest(key string) ([]byte, error) {
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

// PublishedManifestForHash returns the manifest of the release the controller published
// whose content hash is sha256hex, for the given product, or ErrNotFound if no such
// release was published. This is the authoritative "did an operator publish this
// binary, and when?" check — it scans the published-manifest registry by hash, so it
// is independent of the rollout ring AND of any version a node reports. A node
// updated to ANY published release (rolled out or pinned by hand) is recognized as
// trusted; the returned CreatedAt also drives the anti-rollback floor. The artifact
// set is small and this runs only when a node's hash actually changed, so the linear
// scan is cheap.
func (s *bboltStore) PublishedManifestForHash(product, sha256hex string) (*types.Manifest, error) {
	if sha256hex == "" {
		return nil, ErrNotFound
	}
	var found *types.Manifest
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketArtifact).ForEach(func(_, v []byte) error {
			if found != nil {
				return nil
			}
			if m := publishedManifestMatch(v, product, sha256hex); m != nil {
				found = m
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, ErrNotFound
	}
	return found, nil
}

// publishedManifestMatch decodes a stored signed manifest and returns it when it
// names the given product and content hash, else nil. A corrupt or foreign row is
// simply skipped.
func publishedManifestMatch(signedManifest []byte, product, sha256hex string) *types.Manifest {
	signed, err := types.DecodeSigned(signedManifest)
	if err != nil {
		return nil
	}
	var m types.Manifest
	if json.Unmarshal(signed.Payload, &m) != nil {
		return nil
	}
	if m.Product == product && strings.EqualFold(m.SHA256, sha256hex) {
		return &m
	}
	return nil
}
