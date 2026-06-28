package controller

import (
	"context"
	"time"

	"geneza.io/internal/types"
)

// Store is the controller's persistence surface. *bboltStore is the zero-dependency
// single-node default; a *sqlStore (pgx -> Postgres) implements the
// same interface for high-availability deployments. Records/types are
// package-level and shared by every impl. The ONE intentionally backend-aware
// method is PollDeviceGrant, whose
// redeem runs the suspension check + the cert-issue callback inside a single txn so
// the redeemed cert is never persisted; its issue callback is kept backend-agnostic.
type Store interface {
	// countDeviceGrants is impl-internal (device-grant cap) but reached through the
	// interface; an unexported method is fine since every impl lives in this package.
	countDeviceGrants() (int, error)
	ApproveDeviceGrant(userCode string, mutate func(*DeviceGrant) error) error
	CanaryNodes() ([]string, error)
	CanaryVersion() (string, error)
	RelayCanaryNodes() ([]string, error)
	RelayCanaryVersion() (string, error)
	RelayStableVersion() (string, error)
	Close() error
	ClusterConfigVersion() (int64, error)
	DeleteAuthSession(tokenHash string) error
	DeleteMember(ws, provider, subject string) error
	DeleteNode(ws, id string) error
	DeleteSourceBinding(key string) error
	DenyDeviceGrant(userCode string) error
	FindNode(ws, idOrName string) (*NodeRecord, error)
	GetAuthSession(tokenHash string) (*AuthSession, error)
	GetBinding(ws string, vni uint32, nodeID string) (*BindingRecord, error)
	GetDeviceGrantByUserCode(userCode string) (*DeviceGrant, error)
	GetManifest(key string) ([]byte, error)
	// PublishedManifestForHash returns the manifest of the published release with the
	// given content hash (or ErrNotFound) — the authoritative drift check that a
	// node's binary is one an operator published (ring rollout OR manual), not a
	// tamper, and the source of the anti-rollback floor (manifest CreatedAt).
	PublishedManifestForHash(product, sha256hex string) (*types.Manifest, error)
	GetMember(ws, provider, subject string) (*MemberRecord, error)
	GetNode(ws, id string) (*NodeRecord, error)
	GetNodeModules(ws, nodeID string) (*NodeModulesRecord, error)
	GetSession(ws, id string) (*SessionRecord, error)
	GetSetting(key string) ([]byte, error)
	GetSourceBinding(key string) (*SourceBinding, error)
	GetWorkspace(id string) (*WorkspaceRecord, error)
	IsCertRevoked(serialHex string) bool
	IsSuspended(ws, provider, subject string) bool
	// IsCertRevokedE / IsSuspendedE are the error-returning twins the deny cache
	// fronts: they report the store result AND the read error faithfully, so the
	// caller decides fail-closed (global SQL store) vs fail-open (local bbolt).
	IsCertRevokedE(serialHex string) (bool, error)
	IsSuspendedE(ws, provider, subject string) (bool, error)
	LiftSuspension(ws, provider, subject string) error
	ListAllNodes() ([]*NodeRecord, error)
	ListAllSessions() ([]*SessionRecord, error)
	ListAuthSessions() ([]*AuthSession, error)
	ListBindings(ws string, vni uint32) ([]*BindingRecord, error)
	ListMemberWorkspaces(provider, subject string) ([]string, error)
	ListMembers(ws string) ([]*MemberRecord, error)
	ListNetworks(ws string) ([]*NetworkRecord, error)
	ListNodes(ws string) ([]*NodeRecord, error)
	ListRevokedCerts() ([]*RevokedCert, error)
	ListSessions(ws string) ([]*SessionRecord, error)
	// QuerySessions filters, sorts and pages a workspace's sessions in the store
	// (SQL pushes WHERE/ORDER BY/LIMIT/OFFSET+COUNT into Postgres; bbolt does it in
	// memory) so a list view scales without the controller ever loading the full set.
	// Returns the page plus the total matching count.
	QuerySessions(ws string, q SessionQuery) (items []*SessionRecord, total int, err error)
	ListSourceBindings() ([]*SourceBinding, error)
	ListSubnets(ws string) ([]*SubnetRecord, error)
	ListSuspensions(ws string) ([]*SuspensionRecord, error)
	ListWorkspaces() ([]*WorkspaceRecord, error)
	MintWSTicket(sessionTokenHash, nodeID string, ttl time.Duration) (string, error)
	OSMintOnce(key string, now time.Time, dedupeTTL time.Duration, tok *TokenRecord, newToken func() (string, error)) (token string, reused bool, err error)
	PollDeviceGrant(deviceCode string, now int64, issue func(g *DeviceGrant) ([]byte, error)) ([]byte, error)
	PutAuthSession(rec *AuthSession) error
	PutBinding(rec *BindingRecord) error
	PutDeviceGrant(g *DeviceGrant) error
	PutHandoff(rec *HandoffRecord) error
	PutManifest(key string, signed []byte) error
	PutMember(ws string, rec *MemberRecord) error
	AddPresenceCredential(ws, provider, subject string, cred EnrolledCredential) error
	PutNetwork(rec *NetworkRecord) error
	PutNode(ws string, n *NodeRecord) error
	PutSession(ws string, rec *SessionRecord) error
	// Recordings index: the controller stores only ciphertext metadata (it never
	// reads the blob). PutRecording is write-once at the call site (the upload
	// handler refuses to overwrite an existing blob first).
	PutRecording(ws string, rec *RecordingRecord) error
	GetRecording(ws, sessionID string) (*RecordingRecord, error)
	ListRecordings(ws string) ([]*RecordingRecord, error)
	DeleteRecording(ws, sessionID string) error
	// Software inventory (per-workspace). PutNodeSBOM stores a node's whole SBOM
	// blob once and updates it in place; UpsertNodeComponents replaces a node's
	// flattened component set atomically. ListComponentsByPackage is the "who has
	// package X" fast path the matcher joins against. DeleteNode cascades all three.
	PutNodeSBOM(ws, nodeID string, rec *NodeSBOMRecord) error
	GetNodeSBOM(ws, nodeID string) (*NodeSBOMRecord, error)
	UpsertNodeComponents(ws, nodeID string, comps []ComponentRecord) error
	ListNodeComponents(ws, nodeID string) ([]ComponentRecord, error)
	ListComponentsByPackage(ws, ecosystem, name string) ([]ComponentRecord, error)
	// The computed answer table. UpsertNodeCVE writes one (node, component, cve)
	// verdict; the two reads are the headline queries — affected nodes for a cve,
	// and the cve set for a node — both workspace-scoped.
	UpsertNodeCVE(rec *NodeCVERecord) error
	// ClearNodeCVEs drops every verdict row for one node, so a node re-match writes a
	// replace-set: a component that changed version (its purl changed) or dropped out
	// leaves no stale verdict keyed on the old purl. Scoped to (ws, node).
	ClearNodeCVEs(ws, nodeID string) error
	NodesAffectedByCVE(ws, cve string) ([]NodeCVERecord, error)
	CVEsForNode(ws, nodeID string) ([]NodeCVERecord, error)
	// WorkspaceCVERollups returns the fleet-wide vulnerability listing: every CVE
	// affecting any node in the workspace, unioning the host verdicts (node_cve) with
	// the image verdicts (image_cve fanned through the node->digest association), with
	// the distinct affected-node count and list, the representative severity/status,
	// and a fixing version. Scoped to the workspace, so one tenant's rollup never
	// reveals another's nodes.
	WorkspaceCVERollups(ws string) ([]WorkspaceCVERollup, error)
	// EnrichNodeCVEs overlays the prioritization feeds (CISA KEV / FIRST EPSS) onto
	// the already-computed verdict rows: for each CVE in the map it sets kev/epss on
	// every node_cve row for that CVE, fleet-wide (the signal is the same fact for
	// every tenant). It returns how many rows it touched and is idempotent — applying
	// the same map twice yields the same fields.
	EnrichNodeCVEs(scores map[string]CVEEnrichment) (int, error)
	// DistinctNodeCVEs returns the set of CVE ids that appear in any node_cve row,
	// fleet-wide. The enrichment pass uses it to look up only the CVEs that actually
	// have verdicts, rather than applying a whole KEV/EPSS feed.
	DistinctNodeCVEs() ([]string, error)
	// Advisories are global (the same fact for every tenant). PutAdvisories upserts
	// a feed-sync batch atomically; AdvisoriesForPackage is the matcher's by-package
	// resolve.
	PutAdvisories(recs []AdvisoryRecord) error
	AdvisoriesForPackage(ecosystem, name string) ([]AdvisoryRecord, error)
	// Image-digest dedup. A container image's component set and CVE verdicts are a
	// property of its content digest (the same bytes for every node and tenant), so
	// they are stored and matched ONCE per digest in the global image tables. The
	// per-workspace node->digest association (SetNodeImages/NodeImageDigests/
	// NodesRunningDigest) is the only tenant-scoped link, so a digest's findings fan
	// to its nodes on read without re-storing the set, and the global tables never
	// leak across tenants because they are reached only through that ws-scoped join.
	HasImageComponents(digest string) (bool, error)
	PutImageComponents(digest string, comps []ImageComponentRecord) error
	ListImageComponents(digest string) ([]ImageComponentRecord, error)
	ImageDigestsForPackage(ecosystem, name string) ([]string, error)
	SetNodeImages(ws, nodeID string, digests []string) error
	NodeImageDigests(ws, nodeID string) ([]string, error)
	NodesRunningDigest(ws, digest string) ([]string, error)
	WorkspaceNodeImages(ws string) ([]NodeImageAssoc, error)
	// PutImageCVE writes one digest verdict; ClearImageCVEs is the replace-set delete
	// a digest re-match runs first so a feed retraction leaves no stale verdict.
	// DistinctImageCVEs / EnrichImageCVEs are the image-side twins of the per-node
	// enrichment pass, so KEV/EPSS overlays reach digest verdicts too.
	PutImageCVE(rec *ImageCVERecord) error
	ClearImageCVEs(digest string) error
	ImageCVEsForDigest(digest string) ([]ImageCVERecord, error)
	DistinctImageCVEs() ([]string, error)
	EnrichImageCVEs(scores map[string]CVEEnrichment) (int, error)
	PutSourceBinding(rec *SourceBinding) error
	PutSubnet(rec *SubnetRecord) error
	PutToken(token string, rec *TokenRecord) error
	PutWorkspace(rec *WorkspaceRecord) error
	RedeemHandoff(code, cookie string, now int64) (sessionInput, error)
	RedeemWSTicket(ticket string, now int64) (sessionTokenHash, nodeID string, err error)
	RevokeAuthSessionsForSubject(provider, subject string) (int, error)
	RevokeAuthSessionsForUser(user string) (int, error)
	RevokeCert(rec *RevokedCert) error
	SetCanaryNodes(nodes []string) error
	SetCanaryVersion(v string) error
	SetRelayCanaryNodes(nodes []string) error
	SetRelayCanaryVersion(v string) error
	SetRelayStableVersion(v string) error
	SetNodeApproval(ws, id string, approve bool, by string, now time.Time) (*NodeRecord, error)
	// Drift quarantine: a node-scoped sticky deny the controller raises on detected
	// drift (binary tamper / identity clone) and an admin clears via SetNodeApproval.
	QuarantineNode(ws, nodeID, reason, by string, detail map[string]string) (*NodeRecord, error)
	GetQuarantine(ws, nodeID string) (*QuarantineRecord, error)
	ListQuarantines(ws string) ([]*QuarantineRecord, error)
	FindQuarantineByHostUUID(ws, uuid string) (*QuarantineRecord, error)
	// RecordNodeMeasurement stores a heartbeat's self-measured binary hash (rejecting
	// any non-32-byte value), pins the first one seen after approval as the baseline
	// (pinned=true), and reports drift on a later mismatch. RepinBaseline accepts a
	// sanctioned-update hash as the new baseline and records its publish time as the
	// anti-rollback floor.
	RecordNodeMeasurement(ws, nodeID string, binHash []byte, atUnix int64) (drift, pinned bool, n *NodeRecord, err error)
	RepinBaseline(ws, nodeID string, binHash []byte, createdUnix int64) error
	SetNodeModules(ws, nodeID string, modules []NodeModule) (*NodeModulesRecord, error)
	SetSetting(key string, val []byte) error
	SetSignedClusterConfig(version int64, signed []byte) error
	SetStableVersion(v string) error
	SignedClusterConfig() ([]byte, error)
	// ClusterConfigSnapshot reads the version and the signed bytes together, so a
	// concurrent writer cannot pair a stale version with newer bytes (read-skew).
	ClusterConfigSnapshot() (int64, []byte, error)
	// SetSignedFleetState is the split-mode trust writer: it advances the routine
	// map (the existing version/signed columns) AND, when a non-nil anchor is
	// supplied, the trust anchors (anchor_version/anchor_signed) under ONE
	// serializable transaction. mapAnchorVersion is the AnchorVersion the routine
	// map declares; the store rejects a write whose map references an anchor
	// version that is neither the row's current anchor nor the anchor this same
	// call advances to (the cross-binding invariant at rest). Each version is CAS-
	// guarded by its own =current-1 predicate; pass anchorSigned=nil with
	// anchorVersion=current to advance only the map. Legacy SetSignedClusterConfig
	// stays the untouched high-churn path for un-split clusters.
	SetSignedFleetState(mapVersion int64, mapSigned []byte, mapAnchorVersion int64, anchorVersion int64, anchorSigned []byte) error
	// FleetStateSnapshot reads the routine map and the trust anchors together so a
	// reader never pairs a stale anchor with a newer map. anchorSigned is nil and
	// anchorVersion 0 on a legacy (un-split) row.
	FleetStateSnapshot() (mapVersion int64, mapSigned []byte, anchorVersion int64, anchorSigned []byte, err error)
	StableVersion() (string, error)
	SuspendPrincipal(ws, provider, subject, username, by, reason string) error
	SweepExpiredAuthSessions(now int64) (int, error)
	SweepExpiredDeviceGrants(now int64) (int, error)
	SweepExpiredHandoffs(now int64) (int, error)
	// ClaimAgentAffinity records controllerID as nodeID's current control-stream
	// owner and returns a strictly-monotonic epoch (greater than any prior for this
	// node). Every (re)connect to any controller bumps it; the epoch is the fence
	// token that lets a later delivery detect a superseded/zombie stream.
	ClaimAgentAffinity(nodeID, controllerID string, now time.Time) (epoch int64, err error)
	// AgentAffinity returns the current owning controller and epoch; ok=false if the
	// node is unowned (or the lookup faulted — the caller then routes/refuses).
	AgentAffinity(nodeID string) (controllerID string, epoch int64, ok bool)
	// ReleaseAgentAffinity deletes the row only if it still names this
	// (controllerID, epoch) — a compare-and-delete. A disconnect whose epoch was
	// already superseded no-ops, so a slow teardown never evicts the live owner.
	ReleaseAgentAffinity(nodeID, controllerID string, epoch int64) error
	// PutAdvertisedServices durably records a node's advertised service set stamped
	// with the claiming epoch (an older-epoch write loses). AdvertisedServices
	// reads it back (empty if the node never connected) so a named-service resolve
	// works for an agent held by another controller; ClearAdvertisedServices drops it
	// epoch-gated so a stale teardown cannot erase a newer connection's set.
	PutAdvertisedServices(ws, nodeID string, epoch int64, svcs []types.Service) error
	AdvertisedServices(ws, nodeID string) ([]types.Service, error)
	ClearAdvertisedServices(ws, nodeID string, epoch int64) error
	// UpsertRelay / ListRelays / ExpireStaleRelays hold the relay fleet's eventual
	// presence: each relay heartbeats here and the leader assembles the rows into
	// the signed relay map. A plain upsert (not a deny/single-use invariant).
	UpsertRelay(rec *RelayRecord) error
	ListRelays(region string) ([]*RelayRecord, error)
	ExpireStaleRelays(ttl time.Duration) (int, error)
	// PutAgentPresence / ListAgentPresence hold the agent fleet's eventual
	// presence (version + health + freshness) across controllers, so a rollout wave's
	// health can be evaluated fleet-wide and not just for locally-homed agents.
	PutAgentPresence(rec *AgentPresenceRecord) error
	ListAgentPresence() ([]*AgentPresenceRecord, error)
	ExpireStaleAgentPresence(ttl time.Duration) (int, error)
	// UpsertController / ListControllers / ExpireStaleControllers hold the controller fleet's
	// eventual presence: each controller self-heartbeats here and the rows assemble into
	// the signed ControllerEndpoints discovery set.
	UpsertController(rec *ControllerRecord) error
	ListControllers() ([]*ControllerRecord, error)
	ExpireStaleControllers(ttl time.Duration) (int, error)
	// PutManagedCert / GetManagedCert / ListManagedCerts / DeleteManagedCert index
	// the publicly-trusted certificates the controller mints for the managed domain
	// (one wildcard per workspace, funnel leaves later). The cert bytes live in the
	// blob store; these records hold the renewal state and the blob ref.
	PutManagedCert(rec *ManagedCertRecord) error
	GetManagedCert(id string) (*ManagedCertRecord, error)
	ListManagedCerts() ([]*ManagedCertRecord, error)
	DeleteManagedCert(id string) error
	// ReserveSubdomain atomically claims a (domain, label) for a workspace: it
	// fails errSubdomainTaken if another workspace owns it and errSubdomainLimit
	// if the workspace already holds max reservations. Re-reserving one the
	// workspace already owns is a no-op. The other methods read/list/release the
	// reservations, which the cert manager issues a wildcard per.
	ReserveSubdomain(rec *SubdomainReservation, max int) error
	GetSubdomainReservation(domain, label string) (*SubdomainReservation, error)
	ListWorkspaceSubdomains(workspaceID string) ([]*SubdomainReservation, error)
	ListSubdomainReservations() ([]*SubdomainReservation, error)
	ReleaseSubdomain(domain, label, workspaceID string) error
	// Funnel bindings expose a workspace service publicly at a hostname (under one
	// of its reservations). CreateFunnelBinding enforces hostname uniqueness and
	// the per-workspace cap atomically; the cert manager mints a narrow leaf per
	// hostname and the DNS reconciler / relay pushes consume the list.
	CreateFunnelBinding(rec *FunnelBinding, max int) error
	GetFunnelBinding(hostname string) (*FunnelBinding, error)
	ListWorkspaceFunnels(workspaceID string) ([]*FunnelBinding, error)
	ListFunnelBindings() ([]*FunnelBinding, error)
	DeleteFunnelBinding(hostname, workspaceID string) error
	// TryReconcileLock takes a transient, non-blocking advisory lock that debounces
	// the fleet-map rebuild so multiple controllers do not redundantly re-sign the same
	// map. The single-node bbolt store is the only writer and always grants it; the
	// SQL store uses a Postgres advisory lock that whoever fires first grabs for one
	// rebuild and releases — no sticky leader. The version compare-and-swap is the
	// correctness backstop if two ever slip through.
	TryReconcileLock(ctx context.Context) (held bool, release func(), err error)
	// TryVulnSyncLock is the same kind of transient, non-blocking advisory lock as
	// TryReconcileLock but on a distinct key, debouncing the daily vuln-feed sync so
	// N flat controllers do not all fetch and re-match at once. The single-node bbolt
	// store always grants it; the watermark persisted in settings keeps a sync
	// correct-on-loss if the holder dies mid-run.
	TryVulnSyncLock(ctx context.Context) (held bool, release func(), err error)
	// TryManagedCertLock is the same kind of transient, non-blocking advisory lock
	// as TryReconcileLock but on a distinct key, debouncing ACME issuance/renewal so
	// the slow DNS-01 loop never contends with the fleet-map rebuild or feed sync.
	TryManagedCertLock(ctx context.Context) (held bool, release func(), err error)
	UpdateSession(ws, id string, fn func(*SessionRecord)) error
	UpsertFirstAdmin(ws string, rec *MemberRecord) (isFirstAdmin bool, err error)
	UseToken(token string, now time.Time) (*TokenRecord, error)
	WorkspaceForNode(id string) (string, error)
}

// Compile-time assertion that both impls satisfy the interface.
var (
	_ Store = (*bboltStore)(nil)
	_ Store = (*sqlStore)(nil)
)
