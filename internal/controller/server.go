package controller

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"geneza.io/internal/affected/engine"
	"geneza.io/internal/affected/vulnfeed"
	"geneza.io/internal/affected/vulnfeed/enrich"
	"geneza.io/internal/ca"
	"geneza.io/internal/defaults"
	"geneza.io/internal/keysource"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/policy"
	"geneza.io/internal/types"
	"geneza.io/internal/version"
)

// Server wires the control plane together. It is constructed from an
// initialized data_dir (see InitDataDir) and fails closed on any missing or
// inconsistent material.
type Server struct {
	cfg      *Config
	ca       *ca.CA
	store    Store
	audit    *Audit
	registry *Registry
	broker   *Broker
	identity *identityAuth

	// inventoryFeed is the vulnerability source a node's re-match runs against when
	// it reports a changed SBOM; inventoryVEX is the optional OpenVEX suppression
	// source; inventoryEnricher overlays the CISA KEV / FIRST EPSS prioritization
	// signal. All nil/off on a deployment with no feed configured, in which case an
	// inventory report still stores the SBOM and re-indexes components but writes no
	// verdicts (there are no advisories to match).
	inventoryFeed     vulnfeed.Feed
	inventoryVEX      engine.VEXSource
	inventoryEnricher *enrich.Enricher
	// inventoryImageAdvisor is the registry scan-by-digest provider folded into an
	// image digest's match (a known image needs no local scan). Nil until set; the
	// matcher substitutes the no-op default so the match path is always non-nil.
	inventoryImageAdvisor vulnfeed.ImageAdvisoryProvider

	// recordingBlobs is the general-purpose, write-once blob store (recordings
	// today; other per-node artifacts later). Backend is operator-chosen (local
	// dir or S3) via the storage config.
	recordingBlobs blobStore

	// managedCerts issues/renews the managed-domain wildcard certs; nil when the
	// managed_domain feature is disabled.
	managedCerts *managedCertManager
	// funnelDNS publishes public A records for funnel hostnames → healthy relays;
	// nil when the feature is disabled.
	funnelDNS *funnelDNSReconciler

	// sessionSignals forwards session-scoped ICE creds/candidates between a
	// client's SessionSignal stream and the agent's NodeControl disco path.
	sessionSignals *sessionSignalBroker

	// controllerID is this process's stable identity in a multi-controller deployment;
	// router resolves a node/session to the controller holding its stream and delivers
	// there. The single-node default is an inproc pass-through to the registry.
	controllerID string
	router       streamRouter

	// deny memoizes the hot revocation/suspension reads with a short TTL (see
	// denycache.go); invalidated on local + bus-delivered deny writes.
	deny *denyCache

	// presence resolves continuous-presence factors by kind (software stub now,
	// WebAuthn later) with the software-stub safety gate.
	presence *presenceRegistry

	// grantKey signs session grants, cluster config, and session policy. It is a
	// crypto.Signer over an Ed25519 key — an in-memory key by default, or a
	// token-backed signer (HSM/KMS) that never exports the key.
	grantKey    crypto.Signer
	grantKeyID  string
	artifactPub ed25519.PublicKey
	tlsCert     tls.Certificate

	enrollProviders map[string]EnrollProvider

	// clouds holds one verifier per clouds-registry entry (service-uid), used by
	// the OpenStack vendordata endpoint to validate tokens + read Nova.
	clouds map[string]cloudVerifier

	policyMu      sync.RWMutex
	policyEngines map[string]policy.Engine // per-workspace
	members       []WorkspaceConfig        // membership (from config + auto-provisioned)

	ccMu              sync.RWMutex
	ccVersion         int64
	ccSigned          []byte
	ccRelays          []types.RelayNode          // parsed signed relay fleet, for broker candidate selection
	ccControllers     []types.ControllerEndpoint // parsed signed controller discovery set
	ccAuditRecipient  string                     // legacy single signed audit recipient (the age X25519 public key)
	ccAuditRecipients []string                   // effective signed audit recipient SET the cast is sealed to
	// Split-mode served documents: the MultiSigned trust-anchor envelope and the
	// grant-key-signed RoutineMap envelope. Both nil in legacy mode, so what is served
	// to agents/relays is the legacy ccSigned alone. In split mode they are refreshed
	// on every routine churn so a served config is never a stale legacy blob.
	ccAnchorSigned  []byte
	ccRoutineSigned []byte

	metrics        *metricsBackend
	console        *consoleAPI        // web console API; also mounted (cert-authed) on :7402 for the desktop app
	clusterConsole *clusterConsoleAPI // cluster-operator read plane, served on its own break-glass-cert-only listener

	// overlays holds one allocator per workspace (per-tenant overlay namespace:
	// each tenant draws from its own 100.64/24, so two tenants never collide on a
	// wire). overlayMu guards both the map (get-or-create) and stable per-machine
	// overlay-IP assignment.
	overlayMu sync.Mutex
	overlays  map[string]*overlayAllocator
}

// defaultWorkspace is the tenant that single-tenant deployments and legacy
// 2-segment certs resolve to (see ca.PeerIdentity).
const defaultWorkspace = "default"

func New(cfg *Config) (*Server, error) {
	if err := cfg.validateForServe(); err != nil {
		return nil, err
	}
	caInst, err := ca.Open(cfg.CADir(), cfg.caKeySource())
	if err != nil {
		return nil, fmt.Errorf("load CA (did you run `geneza-controller init`?): %w", err)
	}
	grantKey, err := keysource.Open(cfg.grantKeySource())
	if err != nil {
		return nil, fmt.Errorf("load grant key: %w", err)
	}
	grantPub, err := ed25519PublicKey(grantKey)
	if err != nil {
		return nil, fmt.Errorf("grant key: %w", err)
	}
	grantKeyID := types.KeyIDFor(grantPub)
	if b, err := os.ReadFile(cfg.GrantKeyIDPath()); err == nil {
		if stored := strings.TrimSpace(string(b)); stored != grantKeyID {
			return nil, fmt.Errorf("grant.keyid %q does not match grant.key (%q): refusing to start", stored, grantKeyID)
		}
	}
	tlsCert, err := tls.LoadX509KeyPair(cfg.controllerCertPath(), cfg.controllerKeyPath())
	if err != nil {
		return nil, fmt.Errorf("load controller TLS keypair: %w", err)
	}
	var artifactPub ed25519.PublicKey
	if cfg.ArtifactPubkeyFile != "" {
		artifactPub, err = types.LoadPublicKeyPEM(cfg.ArtifactPubkeyFile)
		if err != nil {
			return nil, fmt.Errorf("load artifact pubkey: %w", err)
		}
	}
	store, err := OpenStoreFor(cfg)
	if err != nil {
		return nil, err
	}
	// One policy engine per workspace, sourced from the durable store (seeded from
	// each workspace's policy_file on first use), so a workspace admin can edit
	// their own policy and every replica converges on it.
	engines, err := buildPolicyEngines(store, cfg)
	if err != nil {
		store.Close()
		return nil, err
	}
	sink, err := NewAuditSink(cfg.AuditSink, slog.Default())
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("audit sink: %w", err)
	}
	audit, err := OpenAudit(cfg.AuditPath(), cfg.AuditKeyPath(), cfg.AuditCheckpoint(), sink, slog.Default())
	if err != nil {
		store.Close()
		return nil, err
	}
	blobs, err := newBlobStore(cfg.Storage, cfg.RecordingsDir())
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("storage backend: %w", err)
	}

	s := &Server{
		cfg:            cfg,
		ca:             caInst,
		store:          store,
		audit:          audit,
		registry:       NewRegistry(),
		recordingBlobs: blobs,
		sessionSignals: newSessionSignalBroker(),
		presence:       newPresenceRegistry(cfg.Presence.SoftwareAllowed()),
		identity:       newIdentityAuth(cfg),
		grantKey:       grantKey,
		grantKeyID:     grantKeyID,
		artifactPub:    artifactPub,
		tlsCert:        tlsCert,
		policyEngines:  engines,
		members:        cfg.Workspaces,
		overlays:       map[string]*overlayAllocator{},
	}
	s.controllerID = cfg.ControllerID
	// The deny cache fronts the per-RPC revocation/suspension reads. Its fail policy
	// is the backend's: the global SQL store fails closed on a read fault, the local
	// bbolt store fails open (single-node byte-for-byte).
	s.deny = newDenyCache(denyCacheTTL, cfg.usesSQLStore())
	s.enrollProviders = map[string]EnrollProvider{
		"token":              &tokenProvider{store: store},
		"openstack-metadata": &openstackMetadataProvider{},
	}
	// OpenStack clouds registry: one verifier per service-uid. The vendordata
	// endpoint mints join tokens that enroll through the existing "token" provider.
	s.clouds = make(map[string]cloudVerifier, len(cfg.Clouds))
	for uid, cl := range cfg.Clouds {
		oc, err := newOpenstackClient(uid, cl)
		if err != nil {
			store.Close()
			audit.Close()
			return nil, fmt.Errorf("init cloud %q: %w", uid, err)
		}
		s.clouds[uid] = oc
	}
	// Ensure each configured workspace exists in the store (record + one default
	// Network + Subnet); idempotent. The default workspace is always present.
	for _, w := range cfg.Workspaces {
		name := w.Name
		if name == "" {
			name = w.ID
		}
		if err := s.ensureWorkspace(w.ID, name, w.OverlayCIDR); err != nil {
			s.Close()
			return nil, fmt.Errorf("bootstrap workspace %q: %w", w.ID, err)
		}
		// Config-driven source bindings: a project (or IdP group) bound here
		// resolves to this workspace. Idempotent; overwrites stale targets so the
		// config is authoritative for bindings it declares.
		for _, key := range w.Bindings {
			if err := s.store.PutSourceBinding(&SourceBinding{
				Key: key, WorkspaceID: w.ID, CreatedUnix: time.Now().Unix(), CreatedBy: "config",
			}); err != nil {
				s.Close()
				return nil, fmt.Errorf("workspace %q binding %q: %w", w.ID, key, err)
			}
		}
	}
	// Auto-provisioned workspaces persist across restarts: load a policy engine
	// for any store workspace not already covered by config (default policy).
	if err := s.loadStoreWorkspaceEngines(); err != nil {
		s.Close()
		return nil, err
	}
	// Managed-domain certificates: build the ACME issuer + renewal manager when
	// the feature is configured. Inert (nil manager) otherwise.
	if err := s.setupManagedCerts(); err != nil {
		s.Close()
		return nil, fmt.Errorf("managed domain: %w", err)
	}
	// Resolve the stream router: the single-node inproc pass-through by default, or
	// the Postgres NOTIFY router (router=pg) for a multi-controller cluster. The broker
	// delivers offers through it, so a session brokered here reaches an agent
	// connected to any controller.
	router, rerr := s.newRouter(cfg, store)
	if rerr != nil {
		s.Close()
		return nil, rerr
	}
	s.router = router
	s.broker = NewBroker(store, audit, s.router, s.policyFor, s.overlayFor,
		grantKey, grantKeyID, cfg.RelayAddrs, cfg.GrantTTL.D(), cfg.DefaultMaxSessionTTL.D())
	s.broker.SetSessionP2P(s)                 // session-scoped ICE signaling (gated by cfg.SessionP2P)
	s.broker.SetRelayFloor(s.relayFloorAddrs) // fleet-aware TCP floor (healthy picks; falls back to relay_addrs)
	s.broker.SetPresenceHeartbeat(cfg.Presence.HeartbeatInterval.D())
	s.broker.SetClusterRedirect(s.controllerID, s.clusterControllers) // inert single-node (no signed fleet)

	// metrics is a thin proxy to an external VictoriaMetrics (cfg.MetricsURL);
	// empty URL = metrics disabled (newMetricsBackend returns nil).
	metrics, err := newMetricsBackend(cfg.MetricsURL, slog.Default())
	if err != nil {
		store.Close()
		audit.Close()
		return nil, fmt.Errorf("metrics backend: %w", err)
	}
	s.metrics = metrics

	// Build the console API once (when enabled) and share it: the web console
	// listener serves it bearer-authed, and the :7402 HTTPS listener mounts its
	// /api/v1 cert-authed for the desktop app.
	if cfg.ConsoleEnabled() {
		c, cerr := s.newConsoleAPI()
		if cerr != nil {
			s.Close()
			return nil, fmt.Errorf("console api: %w", cerr)
		}
		s.console = c
	}

	// The cluster-operator read plane is built whenever its listener is configured;
	// it shares the server but authorizes solely the break-glass cluster admin cert.
	if cfg.ClusterConsoleEnabled() {
		s.clusterConsole = s.newClusterConsoleAPI()
	}

	// CVE-affectedness feed: when a source is configured, bind the feed both the
	// node-change re-match and the daily sync chore run against. Unset = nil feed:
	// inventory reports still store SBOMs and re-index components, but write no
	// verdicts (today's behaviour, byte-for-byte). The OpenVEX suppression source
	// and the KEV/EPSS enricher ride alongside, each off unless configured.
	s.inventoryFeed = s.buildVulnFeed()
	if vex, err := s.buildVulnVEX(); err != nil {
		s.Close()
		return nil, err
	} else if vex != nil {
		s.inventoryVEX = vex
	}
	s.inventoryEnricher = s.buildVulnEnricher()

	if err := s.reconcileClusterConfig(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Server) Close() {
	if s.router != nil {
		s.router.Close() // release the bus / dedicated LISTEN connection before the pool
	}
	if s.metrics != nil {
		_ = s.metrics.Close()
	}
	if s.audit != nil {
		_ = s.audit.Close()
	}
	if s.store != nil {
		_ = s.store.Close()
	}
}

// applyClusterConfigFromStore re-reads the stored signed cluster config and adopts
// a strictly newer version in memory. It is the geneza_config doorbell reaction (and
// the resync-on-reconnect re-read): a pure read+apply, never a re-sign, so a
// follower holding only a grant key adopts a version a peer or an offline signer
// advanced without ever rewriting trust.
func (s *Server) applyClusterConfigFromStore() {
	// In split mode the signed column holds the routine-map envelope, not a legacy
	// ClusterConfig; adopt it through the routine-map path so the served split
	// documents are refreshed in place rather than parsed as a ClusterConfig (which
	// would blank them and serve a pinned follower a stale legacy config it refuses).
	if active, err := splitModeActive(s.store); err != nil {
		slog.Warn("config doorbell: split-mode check", "err", err)
		return
	} else if active {
		if err := s.reconcileRoutineMap(); err != nil {
			slog.Warn("config doorbell: reconcile routine map", "err", err)
		}
		return
	}
	// Read the version and the signed bytes together so a concurrent writer cannot
	// pair a stale version with newer bytes; setClusterConfig then applies it only
	// if it is strictly newer than what is held (monotonic CAS under one lock).
	v, signed, err := s.store.ClusterConfigSnapshot()
	if err != nil {
		slog.Warn("config doorbell: read snapshot", "err", err)
		return
	}
	if len(signed) == 0 {
		return
	}
	s.ccMu.RLock()
	cur := s.ccVersion
	s.ccMu.RUnlock()
	if v <= cur { // early-out for a stale/duplicate doorbell (the CAS is the real fence)
		return
	}
	s.setClusterConfig(v, signed)
	slog.Info("cluster config advanced via doorbell; adopted", "version", v)
}

// --- policy hot-swap ---

// policyFor returns the policy engine for a workspace, or a fail-closed deny-all
// engine for an unknown/unconfigured workspace (never a default fallback).
func (s *Server) policyFor(ws string) policy.Engine {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	if e := s.policyEngines[ws]; e != nil {
		return e
	}
	return denyAllPolicy{}
}

// reloadPolicies rebuilds every workspace's policy engine from the durable store
// (admin ReloadPolicy / genezactl policy reload). Auto-provisioned (store-only)
// workspaces are preserved, so a reload never silently turns them deny-all.
func (s *Server) reloadPolicies() error {
	engines, err := buildPolicyEngines(s.store, s.cfg)
	if err != nil {
		return err
	}
	s.policyMu.Lock()
	s.policyEngines = engines
	s.policyMu.Unlock()
	return nil
}

// loadStoreWorkspaceEngines creates a default-policy engine for every workspace
// present in the store but not declared in config (i.e. auto-provisioned), so
// they survive a restart with a real (non-deny-all) policy. Config workspaces
// already have their engines from New().
func (s *Server) loadStoreWorkspaceEngines() error {
	wss, err := s.store.ListWorkspaces()
	if err != nil {
		return fmt.Errorf("list store workspaces: %w", err)
	}
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	for _, w := range wss {
		if s.policyEngines[w.ID] != nil {
			continue
		}
		eng, err := policy.Load(s.cfg.autoProvisionPolicyFile())
		if err != nil {
			return fmt.Errorf("load auto-provision policy for workspace %q: %w", w.ID, err)
		}
		s.policyEngines[w.ID] = eng
	}
	return nil
}

// registerDynamicWorkspace gives a freshly auto-provisioned workspace a policy
// engine at runtime (default policy) so the broker does not fail-closed on it
// before the next restart. Membership is intentionally NOT auto-opened: an
// auto-provisioned workspace is isolated to its project until an operator binds
// a human source onto it.
func (s *Server) registerDynamicWorkspace(ws string) {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	if s.policyEngines[ws] != nil {
		return
	}
	eng, err := policy.Load(s.cfg.autoProvisionPolicyFile())
	if err != nil {
		slog.Error("auto-provision: load policy failed; workspace is deny-all until restart", "workspace", ws, "err", err)
		return
	}
	s.policyEngines[ws] = eng
}

// workspacesForUser returns the workspaces a principal may log into: those whose
// membership matches (username or IdP group), plus every OPEN workspace.
func (s *Server) workspacesForUser(user string, groups []string) []string {
	gset := make(map[string]bool, len(groups))
	for _, g := range groups {
		gset[g] = true
	}
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	var out []string
	for _, w := range s.members {
		member := w.open()
		for _, u := range w.Members {
			if u == user {
				member = true
			}
		}
		for _, g := range w.MemberGroups {
			if gset[g] {
				member = true
			}
		}
		if member {
			out = append(out, w.ID)
		}
	}
	return out
}

// denyAllPolicy is the fail-closed engine returned for an unknown workspace.
type denyAllPolicy struct{}

func (denyAllPolicy) Evaluate(policy.Input) policy.Decision {
	return policy.Decision{Allow: false, Reason: "unknown workspace"}
}
func (denyAllPolicy) RolesFor(string, []string) []string { return nil }
func (denyAllPolicy) Records() bool                      { return false }

// overlayFor returns the per-workspace overlay allocator, creating it on first
// use. Each workspace gets its own 100.64/24 namespace so two tenants never
// collide on a wire.
func (s *Server) overlayFor(ws string) *overlayAllocator {
	s.overlayMu.Lock()
	defer s.overlayMu.Unlock()
	a := s.overlays[ws]
	if a == nil {
		a = newOverlayAllocator()
		s.overlays[ws] = a
	}
	return a
}

// ensureWorkspace creates the workspace registry record plus one default Network
// (a ws-derived VNI) and a default Subnet covering its overlay CIDR, if absent.
// Idempotent.
func (s *Server) ensureWorkspace(id, name, overlayCIDR string) error {
	if _, err := s.store.GetWorkspace(id); err == nil {
		return nil // already exists
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	now := time.Now().Unix()
	if err := s.store.PutWorkspace(&WorkspaceRecord{ID: id, Name: name, OverlayCIDR: overlayCIDR, CreatedUnix: now}); err != nil {
		return err
	}
	netID := id + "-net0"
	if err := s.store.PutNetwork(&NetworkRecord{
		WorkspaceID: id, ID: netID, VNI: vniForWorkspace(id), Name: "default",
		// nil selector = open: every node/user in the workspace is a member.
	}); err != nil {
		return err
	}
	return s.store.PutSubnet(&SubnetRecord{
		WorkspaceID: id, NetworkID: netID, ID: netID + "-sub0", CIDR: overlayCIDR,
	})
}

// vniForWorkspace derives a stable 24-bit VNI from a workspace id ("default" is
// pinned to 1). Deterministic so it needs no counter; the data plane uses it
// later as the segment demux key.
func vniForWorkspace(id string) uint32 {
	if id == defaultWorkspace {
		return 1
	}
	var h uint32 = 2166136261
	for i := 0; i < len(id); i++ { // FNV-1a, truncated to 24 bits
		h ^= uint32(id[i])
		h *= 16777619
	}
	v := h & 0x00FFFFFF
	if v == 0 || v == 1 {
		v += 2
	}
	return v
}

// --- cluster config lifecycle ---

func buildClusterConfig(version int64, rootsPEM []byte, keyID string, pub ed25519.PublicKey, cfg *Config, relays []types.RelayNode, controllers []types.ControllerEndpoint, trustKeys []types.TrustKey) types.ClusterConfig {
	return types.ClusterConfig{
		ConfigVersion: version,
		CARootsPEM:    rootsPEM,
		// Single key today; the list form is the rotation-overlap seam.
		GrantKeys:           []types.GrantKey{{KeyID: keyID, PublicKey: []byte(pub)}},
		AgentPolicy:         cfg.AgentPolicy.toTypes(),
		RelayAddrs:          cfg.RelayAddrs,
		Relays:              relays,
		ControllerEndpoints: controllers,
		// TrustKeys are carried forward from the stored config, never invented by a
		// controller: a separate trust root is established out of band (geneza-trust),
		// and the reconcile loop must not strip or rewrite it. Empty on a single-node
		// genesis, where the grant key is the implicit trust root.
		TrustKeys: trustKeys,
	}
}

// canSignConfig reports whether this controller is trusted to sign a config carrying
// the given trust set: trivially true when there is no separate trust root (the
// grant key IS the root, single-node), otherwise only if this controller's grant key
// id is itself one of the trust keys. A controller that is not trusted must never
// re-sign — that is the property that stops one controller rewriting fleet trust.
func (s *Server) canSignConfig(trustKeys []types.TrustKey) bool {
	if len(trustKeys) == 0 {
		return true
	}
	for _, k := range trustKeys {
		if k.KeyID == s.grantKeyID {
			return true
		}
	}
	return false
}

// synthesizeRelays builds the single-node signed relay map from the configured
// relay addresses, all in this controller's region. It is called by BOTH the
// genesis write and the drift reconcile so the two produce an identical map —
// otherwise the first reconcile after a restart would rebuild a config without
// the relays, detect "drift", and silently drop the map. Deterministic: same
// config + same relay cert => same bytes, so the drift diff stays quiet.
func synthesizeRelays(cfg *Config) []types.RelayNode {
	// The relay map describes the TURN/STUN data endpoint (not the TCP rendezvous
	// address, which the grant carries separately), so a synthesized candidate's
	// TURN URL matches what the single-node minter produces.
	dataAddr := cfg.relayDataAddr()
	if dataAddr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(dataAddr)
	if err != nil || host == "" {
		host = dataAddr
	}
	port := cfg.relayDataPort()
	return []types.RelayNode{{
		RegionID:     canonicalRegion(cfg.Region),
		RelayID:      host,
		Addrs:        []string{dataAddr},
		STUNPort:     port,
		TURNPort:     port,
		RelayCertPub: relayCertSPKI(cfg),
	}}
}

// selectableRelays returns the relays a NEW session may be steered to: the live
// fleet with draining and stale relays removed, so a session is never pinned to a
// relay that is shedding for a swap or has missed its heartbeats. It reads the
// presence rows directly (not the cached signed map) so it sees LastSeen for
// staleness and the freshly-recorded drain bit without waiting for a map rebuild.
//
// Fail-soft: if EVERY fleet relay is draining (a whole-region swap) it returns the
// full set rather than nothing, logging it — a degraded floor onto a draining relay
// still beats no relay at all. A transient store read error falls back to the
// last-known signed fleet. Single-node (no SQL/region) uses the synthesized map,
// which is never draining or stale.
func (s *Server) selectableRelays() []types.RelayNode {
	if s.cfg.Region == "" && !s.cfg.usesSQLStore() {
		return s.clusterRelays()
	}
	recs, err := s.store.ListRelays("")
	if err != nil {
		return s.clusterRelays()
	}
	cutoff := time.Now().Add(-relayStaleTTL).Unix()
	live := make([]types.RelayNode, 0, len(recs))
	var draining []types.RelayNode
	for _, r := range recs {
		if r.LastSeenUnix < cutoff {
			continue // stale: missed its heartbeats, implicitly unselectable
		}
		if r.Draining {
			draining = append(draining, r.RelayNode)
			continue
		}
		live = append(live, r.RelayNode)
	}
	if len(live) == 0 && len(draining) > 0 {
		slog.Warn("relay selection: all live relays draining, falling back to least-bad set", "count", len(draining))
		live = draining
	}
	sortRelayNodes(live)
	return live
}

// relayFloorAddrs returns the ordered healthy relay-TCP rendezvous addresses a new
// session's floor should dial: the live fleet's selectable relays (draining/stale
// already excluded) projected onto their TCP rendezvous endpoint (ControlAddr). It
// returns nil when there is no dynamic fleet to pick from (single-node, or every
// fleet relay advertises only a data endpoint) so the broker falls back to the
// static relay_addrs config — the configured floor a single-node deploy relies on.
func (s *Server) relayFloorAddrs() []string {
	if s.cfg.Region == "" && !s.cfg.usesSQLStore() {
		return nil // single-node: the broker uses the configured relay_addrs floor
	}
	out := make([]string, 0)
	for _, r := range s.selectableRelays() {
		if r.ControlAddr != "" {
			out = append(out, r.ControlAddr)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// relayMapRebuildInterval coalesces relay registrations/expiries into at most one
// signed-config version bump per window (no per-flap broadcast storm).
const relayMapRebuildInterval = 10 * time.Second

// assembleRelays returns the relay set the signed map should carry: in a
// regional / SQL deployment it is the live registrar fleet; otherwise it is the
// single configured local relay. Sorted for a stable drift diff.
func (s *Server) assembleRelays() []types.RelayNode {
	if s.cfg.Region != "" || s.cfg.usesSQLStore() {
		recs, err := s.store.ListRelays("")
		if err != nil {
			// A transient store read must NOT be read as "the fleet is now one
			// relay" — that would drop every remote relay from the signed map and
			// churn the config version. Keep the last-known-good map instead.
			return s.clusterRelays()
		}
		fleet := make([]types.RelayNode, 0, len(recs))
		for _, r := range recs {
			fleet = append(fleet, r.RelayNode)
		}
		sortRelayNodes(fleet)
		return fleet
	}
	return synthesizeRelays(s.cfg)
}

func sortRelayNodes(rs []types.RelayNode) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].RegionID != rs[j].RegionID {
			return rs[i].RegionID < rs[j].RegionID
		}
		return rs[i].RelayID < rs[j].RelayID
	})
}

// assembleControllerEndpoints returns the controller discovery set the signed map should
// carry: the live self-heartbeating fleet in a SQL/regional deployment, sorted for
// a stable drift diff; nil on single-node (there is no fleet to discover). On a
// transient store read error it keeps the last-known-good set rather than dropping
// every peer and churning the config version.
func (s *Server) assembleControllerEndpoints() []types.ControllerEndpoint {
	if s.cfg.Region == "" && !s.cfg.usesSQLStore() {
		return nil
	}
	recs, err := s.store.ListControllers()
	if err != nil {
		return s.clusterControllers()
	}
	fleet := make([]types.ControllerEndpoint, 0, len(recs))
	for _, r := range recs {
		fleet = append(fleet, r.ControllerEndpoint)
	}
	sort.Slice(fleet, func(i, j int) bool { return fleet[i].ControllerID < fleet[j].ControllerID })
	return fleet
}

// controllerEndpoint is this controller's own dialable entry for the discovery set: its
// advertised names/IPs paired with the gRPC port, tagged with its id and region.
func (s *Server) controllerEndpoint() types.ControllerEndpoint {
	_, port, err := net.SplitHostPort(s.cfg.GRPCListen)
	if err != nil || port == "" {
		port = "7401"
	}
	hosts := append(append([]string{}, s.cfg.Advertise.DNSNames...), s.cfg.Advertise.IPs...)
	advertise := func(p string) []string {
		out := make([]string, 0, len(hosts))
		for _, h := range hosts {
			out = append(out, net.JoinHostPort(h, p))
		}
		return out
	}
	ep := types.ControllerEndpoint{ControllerID: s.controllerID, Addrs: advertise(port), RegionID: s.cfg.Region}
	// When the relay registrar lives on its own listener, advertise that port so a
	// relay's discovery dials where RelayRegistry actually answers, not the gRPC port
	// (which the client/agent redirect uses). Empty when the registrar shares gRPC.
	if _, cport, cerr := net.SplitHostPort(s.cfg.ClusterControlListen); cerr == nil && cport != "" {
		ep.ControlAddrs = advertise(cport)
	}
	return ep
}

// maintainRelayMap is the leader-only debounced rebuild of the signed relay map
// from the registrar fleet. It commits through the same compare-and-swap reconcile
// path, so agents pull the new map on their existing schedule rather than per
// relay flap. It does nothing in a single-node deployment (the local relay never
// changes) — only a regional / SQL controller runs the registrar at all.
func (s *Server) maintainRelayMap(ctx context.Context) {
	if s.cfg.Region == "" && !s.cfg.usesSQLStore() {
		return
	}
	t := time.NewTicker(relayMapRebuildInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			relayDrift := !reflect.DeepEqual(s.assembleRelays(), s.clusterRelays())
			controllerDrift := !reflect.DeepEqual(s.assembleControllerEndpoints(), s.clusterControllers())
			if !(relayDrift || controllerDrift) {
				continue
			}
			// Debounce so N controllers do not all re-sign the same map every tick: a
			// transient, non-blocking advisory lock that whoever fires first grabs and
			// releases when its rebuild commits — the coordinator role moves freely, no
			// sticky leader. The version compare-and-swap is the correctness backstop if
			// two ever slip through (the loser adopts the winner's config).
			held, release, err := s.store.TryReconcileLock(ctx)
			if err != nil {
				slog.Warn("fleet map rebuild: lock", "err", err)
				continue
			}
			if !held {
				continue // another controller is rebuilding this tick
			}
			rerr := s.reconcileClusterConfig()
			release()
			if rerr != nil {
				slog.Warn("fleet map rebuild", "err", rerr)
			}
		}
	}
}

// controllerHeartbeatInterval / controllerStaleTTL pace a controller's self-presence upsert
// and how long after its last beat a dead controller is dropped from the discovery set.
const (
	controllerHeartbeatInterval = 15 * time.Second
	controllerStaleTTL          = 60 * time.Second
)

// maintainControllerPresence upserts this controller's own dialable endpoint on a timer
// so it appears in the signed discovery set every other controller and every agent/
// relay re-homes across. It is inert on single-node (no fleet to discover).
func (s *Server) maintainControllerPresence(ctx context.Context) {
	if s.cfg.Region == "" && !s.cfg.usesSQLStore() {
		return
	}
	beat := func() {
		rec := &ControllerRecord{ControllerEndpoint: s.controllerEndpoint(), LastSeenUnix: time.Now().Unix(), Version: version.Version}
		if err := s.store.UpsertController(rec); err != nil {
			slog.Warn("controller presence heartbeat", "err", err)
		}
	}
	beat()
	t := time.NewTicker(controllerHeartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			beat()
		}
	}
}

// relayCertSPKI returns the relay TLS certificate's public key in PKIX/SPKI form,
// which is what a dialing agent pins against the signed map. Best-effort: returns
// nil if the cert is absent or unparseable (the relay-TCP floor then falls back
// to chain-to-root verification, as it did before the map existed).
func relayCertSPKI(cfg *Config) []byte {
	pemBytes, err := os.ReadFile(cfg.relayCertPath())
	if err != nil {
		return nil
	}
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil
	}
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil
	}
	return spki
}

func signClusterConfig(cc types.ClusterConfig, key crypto.Signer, keyID string) ([]byte, error) {
	signed, err := types.Sign(key, keyID, defaults.ContextClusterConfig, cc)
	if err != nil {
		return nil, err
	}
	return signed.Encode()
}

// ed25519PublicKey extracts the Ed25519 public half of a grant signer. The grant
// key is always Ed25519 (file or token); a signer whose public key is anything
// else is a misconfiguration and fails closed rather than producing grants no
// verifier will accept.
func ed25519PublicKey(s crypto.Signer) (ed25519.PublicKey, error) {
	pub, ok := s.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("grant signer public key is %T, want ed25519.PublicKey", s.Public())
	}
	return pub, nil
}

// reconcileClusterConfig compares the config-file-derived desired state with
// the stored signed config (ignoring config_version) and bumps + re-signs on
// drift, so editing controller.yaml and restarting converges the fleet.
func (s *Server) reconcileClusterConfig() error {
	// Split mode: when offline/threshold trust anchors are present, the high-churn
	// routing view is its own grant-key-signed document bound to those anchors. The
	// grant key re-signs the routine map online but never the anchors. A legacy
	// (un-split) store falls through to the single-envelope path below, byte-for-byte
	// unchanged.
	if active, aerr := splitModeActive(s.store); aerr != nil {
		return aerr
	} else if active {
		return s.reconcileRoutineMap()
	}

	storedVersion, err := s.store.ClusterConfigVersion()
	if err != nil {
		return fmt.Errorf("cluster config version: %w", err)
	}
	storedSigned, err := s.store.SignedClusterConfig()
	if err != nil {
		return err
	}
	if storedVersion == 0 || len(storedSigned) == 0 {
		return errors.New("no signed cluster config in store: run `geneza-controller init` first")
	}
	signed, err := types.DecodeSigned(storedSigned)
	if err != nil {
		return fmt.Errorf("stored cluster config: %w", err)
	}
	var stored types.ClusterConfig
	if err := json.Unmarshal(signed.Payload, &stored); err != nil {
		return fmt.Errorf("stored cluster config payload: %w", err)
	}

	pub, err := ed25519PublicKey(s.grantKey)
	if err != nil {
		return fmt.Errorf("grant key: %w", err)
	}
	// Carry the stored trust set forward so a config bearing a separate trust root
	// is not seen as drift (and never stripped) by a controller re-signing the mutable
	// relay map.
	candidate := buildClusterConfig(0, s.ca.RootsPEM, s.grantKeyID, pub, s.cfg, s.assembleRelays(), s.assembleControllerEndpoints(), stored.TrustKeys)
	stored.ConfigVersion = 0
	candB, err := json.Marshal(candidate)
	if err != nil {
		return err
	}
	storedB, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	if string(candB) == string(storedB) {
		s.setClusterConfig(storedVersion, storedSigned)
		return nil
	}

	// Real drift, but a controller holding only its grant key must NOT re-sign a config
	// protected by a separate trust root — doing so would let one controller rewrite
	// fleet trust. Keep the offline-signed config; an operator re-signs the update
	// with geneza-trust.
	if !s.canSignConfig(stored.TrustKeys) {
		s.setClusterConfig(storedVersion, storedSigned)
		slog.Warn("cluster config drift detected but this controller holds no trust key; an offline geneza-trust re-sign is required to apply it")
		return nil
	}

	newVersion := storedVersion + 1
	candidate.ConfigVersion = newVersion
	newSigned, err := signClusterConfig(candidate, s.grantKey, s.grantKeyID)
	if err != nil {
		return fmt.Errorf("sign cluster config: %w", err)
	}
	if err := s.store.SetSignedClusterConfig(newVersion, newSigned); err != nil {
		if errors.Is(err, errClusterConfigConflict) {
			// Another controller advanced the version first. Adopt the stored config
			// instead of ours; the next reconcile re-checks for drift against it.
			v, adopted, serr := s.store.ClusterConfigSnapshot()
			if serr != nil {
				return serr
			}
			s.setClusterConfig(v, adopted)
			slog.Info("cluster config advanced by another controller; adopted", "version", v)
			return nil
		}
		return err
	}
	s.setClusterConfig(newVersion, newSigned)
	s.registry.Broadcast(&genezav1.ControllerMsg{Msg: &genezav1.ControllerMsg_ClusterConfig{ClusterConfig: newSigned}})
	slog.Info("cluster config updated", "version", newVersion)
	return nil
}

func (s *Server) setClusterConfig(version int64, signed []byte) {
	// Cache the parsed relay fleet so the broker can select per-session candidates
	// without re-decoding the signed config on every CreateSession.
	var relays []types.RelayNode
	var controllers []types.ControllerEndpoint
	var auditRecipient string
	var auditRecipients []string
	if env, err := types.DecodeSigned(signed); err == nil {
		var cc types.ClusterConfig
		if json.Unmarshal(env.Payload, &cc) == nil {
			relays = cc.Relays
			controllers = cc.ControllerEndpoints
			auditRecipient = cc.AuditRecipient
			auditRecipients = cc.EffectiveAuditRecipients()
		}
	}
	s.ccMu.Lock()
	defer s.ccMu.Unlock()
	// Monotonic compare-and-set under one lock: a stale read (e.g. a doorbell that
	// races the startup reconcile) must never clobber a newer in-memory config.
	if version < s.ccVersion {
		return
	}
	s.ccVersion = version
	s.ccSigned = signed
	s.ccRelays = relays
	s.ccControllers = controllers
	s.ccAuditRecipient = auditRecipient
	s.ccAuditRecipients = auditRecipients
	// The legacy path never serves split documents. Clearing them keeps a cluster that
	// has not (or no longer) established an anchor from emitting a stale split pair.
	s.ccAnchorSigned = nil
	s.ccRoutineSigned = nil
}

// fleetWire returns the documents served to agents and relays: the version, the
// legacy signed ClusterConfig, and — in split mode — the trust-anchor and routine
// -map envelopes. In legacy mode the split bytes are nil and only the legacy config
// travels (byte-for-byte today). In split mode all three travel so a mixed fleet
// converges off one message: a pinned node verifies the split pair, an un-pinned
// node falls back to the legacy config.
func (s *Server) fleetWire() (version int64, legacy, anchors, routineMap []byte) {
	s.ccMu.RLock()
	defer s.ccMu.RUnlock()
	return s.ccVersion, s.ccSigned, s.ccAnchorSigned, s.ccRoutineSigned
}

// fleetControllerMsg builds the config push for an agent's control stream. In legacy
// mode it is the bare cluster_config arm, byte-for-byte as before. In split mode it
// is the FleetState arm carrying the legacy fallback AND the split pair, so a mixed
// fleet converges off one message.
func (s *Server) fleetControllerMsg() *genezav1.ControllerMsg {
	_, legacy, anchors, routineMap := s.fleetWire()
	if len(anchors) == 0 || len(routineMap) == 0 {
		return &genezav1.ControllerMsg{Msg: &genezav1.ControllerMsg_ClusterConfig{ClusterConfig: legacy}}
	}
	return &genezav1.ControllerMsg{Msg: &genezav1.ControllerMsg_FleetState{FleetState: &genezav1.FleetState{
		ClusterConfig: legacy,
		TrustAnchors:  anchors,
		RoutineMap:    routineMap,
	}}}
}

// clusterRelays returns the parsed signed relay fleet grouped by region.
func (s *Server) clusterRelays() []types.RelayNode {
	s.ccMu.RLock()
	defer s.ccMu.RUnlock()
	return s.ccRelays
}

// clusterControllers returns the parsed signed controller discovery set.
func (s *Server) clusterControllers() []types.ControllerEndpoint {
	s.ccMu.RLock()
	defer s.ccMu.RUnlock()
	return s.ccControllers
}

func (s *Server) clusterConfig() (int64, []byte) {
	s.ccMu.RLock()
	defer s.ccMu.RUnlock()
	return s.ccVersion, s.ccSigned
}

// auditRecipient returns the workspace audit age recipient from the parsed signed
// cluster config (empty when none is configured). It is the public half only; the
// controller never holds the private key.
func (s *Server) auditRecipient() string {
	s.ccMu.RLock()
	defer s.ccMu.RUnlock()
	return s.ccAuditRecipient
}

// auditRecipients returns the effective workspace audit recipient SET from the
// parsed signed cluster config — the keys a recording is sealed to (the single
// recipient as a one-element set when no list is configured). The controller labels
// each indexed recording with this set's id but holds no private half of any key.
func (s *Server) auditRecipients() []string {
	s.ccMu.RLock()
	defer s.ccMu.RUnlock()
	return s.ccAuditRecipients
}

func (s *Server) signedClusterConfig() []byte {
	_, b := s.clusterConfig()
	return b
}

// --- shared views ---

func (s *Server) nodeSummaries(ws string) ([]*genezav1.NodeSummary, error) {
	nodes, err := s.store.ListNodes(ws)
	if err != nil {
		return nil, err
	}
	// One lookup of the workspace's active quarantines, fanned to the summaries
	// below, so the node list shows WHY a node is denied (drift cause) not just that
	// it is unapproved.
	qmap := map[string]string{}
	if qs, qerr := s.store.ListQuarantines(ws); qerr == nil {
		for _, q := range qs {
			qmap[q.NodeID] = q.Reason
		}
	}
	out := make([]*genezav1.NodeSummary, 0, len(nodes))
	for _, n := range nodes {
		sum := &genezav1.NodeSummary{
			NodeId:           n.ID,
			Name:             n.Name,
			Labels:           n.Labels,
			Os:               n.Platform.OS,
			Arch:             n.Platform.Arch,
			Version:          n.Platform.AgentVersion,
			Distro:           n.Platform.Distro,
			DistroVersion:    n.Platform.DistroVersion,
			OsPretty:         n.Platform.OSPretty,
			Approved:         n.Approved,
			OverlayIp:        n.OverlayIP,
			QuarantineReason: qmap[n.ID],
		}
		if info, ok := s.registry.Info(n.ID); ok {
			sum.Online = true
			sum.LastSeenUnix = info.LastSeen.Unix()
			sum.Version = info.Version
			sum.ActiveSessions = info.Active
			sum.DetachedSessions = info.Detached
		}
		out = append(out, sum)
	}
	return out, nil
}

// --- serving ---

// newGRPCServer builds a gRPC server with the controller's mTLS creds, the cert-kind
// auth interceptors, and keepalive policy — shared by the main listener and the
// optional separate cluster-control listener so both enforce identical auth.
func (s *Server) newGRPCServer(grpcTLS *tls.Config) *grpc.Server {
	return grpc.NewServer(
		grpc.Creds(credentials.NewTLS(grpcTLS)),
		grpc.ChainUnaryInterceptor(s.unaryAuthInterceptor()),
		grpc.ChainStreamInterceptor(s.streamAuthInterceptor()),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		// Actively probe peers so a black-holed connection (a relay's watch stream or
		// an agent's control stream on a dead node, no RST) is torn down well inside
		// the relay stale-TTL — otherwise the server would keep a dead relay's presence
		// fresh on a half-open stream. Timeout+Time worst case (30s) < relayStaleTTL.
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    20 * time.Second,
			Timeout: 10 * time.Second,
		}),
	)
}

// Run serves gRPC and HTTPS until ctx is cancelled, then drains gracefully.
func (s *Server) Run(ctx context.Context) error {
	grpcTLS, err := s.grpcTLSConfig()
	if err != nil {
		return err
	}
	lis, err := net.Listen("tcp", s.cfg.GRPCListen)
	if err != nil {
		return fmt.Errorf("grpc listen %s: %w", s.cfg.GRPCListen, err)
	}
	grpcSrv := s.newGRPCServer(grpcTLS)
	genezav1.RegisterEnrollmentServer(grpcSrv, &enrollmentService{s: s})
	genezav1.RegisterNodeControlServer(grpcSrv, &nodeControlService{s: s})
	genezav1.RegisterWorkspaceAPIServer(grpcSrv, &workspaceAPIService{s: s})
	genezav1.RegisterClusterAPIServer(grpcSrv, &clusterAPIService{s: s})

	// The controller↔relay control plane (the relay registrar) optionally lives on a
	// separate, firewall-able mTLS listener so operators can restrict it to the
	// relay/management subnet; otherwise it shares the main gRPC listener. Either
	// way the cert-kind auth interceptor still admits only relay certs.
	var ctrlSrv *grpc.Server
	var ctrlLis net.Listener
	if s.cfg.ClusterControlListen != "" {
		ctrlLis, err = net.Listen("tcp", s.cfg.ClusterControlListen)
		if err != nil {
			return fmt.Errorf("cluster-control listen %s: %w", s.cfg.ClusterControlListen, err)
		}
		ctrlSrv = s.newGRPCServer(grpcTLS)
		genezav1.RegisterRelayRegistryServer(ctrlSrv, &relayRegistryService{s: s})
	} else {
		genezav1.RegisterRelayRegistryServer(grpcSrv, &relayRegistryService{s: s})
	}

	clientCAs, err := ca.PoolFromPEM(s.ca.RootsPEM)
	if err != nil {
		return fmt.Errorf("client CA pool: %w", err)
	}
	httpSrv := &http.Server{
		Addr:              s.cfg.HTTPListen,
		Handler:           s.httpHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{s.tlsCert},
			MinVersion:   tls.VersionTLS13,
			// Request + chain-verify a client cert when offered (the desktop app's
			// user cert for the cert-authed /api/v1 mount); public routes that
			// present no cert are unaffected.
			ClientCAs:  clientCAs,
			ClientAuth: tls.VerifyClientCertIfGiven,
		},
	}

	consoleSrv, err := s.consoleServer()
	if err != nil {
		return fmt.Errorf("console: %w", err)
	}

	clusterConsoleSrv, err := s.clusterConsoleServer()
	if err != nil {
		return fmt.Errorf("cluster console: %w", err)
	}

	// Rebuild the signed fleet map from the registrar/presence rows, debounced by a
	// transient advisory lock (no-op on a single-node controller).
	go s.maintainRelayMap(ctx)

	// Self-heartbeat this controller's endpoint into the signed discovery set (inert
	// on single-node).
	go s.maintainControllerPresence(ctx)

	// Continuous authorization: re-evaluate live sessions against current policy.
	go s.runContinuousAuthz(ctx, s.cfg.ReauthInterval.D())

	// Staggered rollout controller: drive any in-flight agent/relay rollout
	// through its waves (leader-only, store-driven).
	go s.runRolloutController(ctx, rolloutTickInterval)

	// CVE-affectedness freshness: a debounced, advisory-lock-shared daily feed sync
	// that re-matches only the changed advisories' nodes. Inert unless a feed source
	// is configured.
	go s.runVulnSync(ctx)

	// Managed-domain certificates: issue/renew the per-workspace wildcards via ACME
	// DNS-01 (leader-only, store-driven). Inert unless managed_domain is configured.
	go s.runManagedCertController(ctx, s.cfg.ManagedDomain.RenewInterval.D())

	// Sweep lapsed deny-cache entries so a long-lived controller does not accumulate
	// one entry per distinct cert/principal ever seen.
	go s.deny.runGC(ctx.Done())

	// Keep install_dir populated with the signed geneza-node binaries (no-op
	// unless agent_release.pull is set).
	go s.startAgentPull(ctx)

	errCh := make(chan error, 5)
	go func() {
		slog.Info("gRPC listening", "addr", s.cfg.GRPCListen, "cluster", s.cfg.ClusterName, "version", version.Version)
		if err := grpcSrv.Serve(lis); err != nil {
			errCh <- fmt.Errorf("grpc serve: %w", err)
		}
	}()
	if ctrlSrv != nil {
		go func() {
			slog.Info("cluster-control gRPC listening", "addr", s.cfg.ClusterControlListen)
			if err := ctrlSrv.Serve(ctrlLis); err != nil {
				errCh <- fmt.Errorf("cluster-control serve: %w", err)
			}
		}()
	}
	go func() {
		slog.Info("HTTPS listening", "addr", s.cfg.HTTPListen)
		if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("https serve: %w", err)
		}
	}()
	if consoleSrv != nil {
		go func() {
			slog.Info("console listening", "addr", consoleSrv.Addr, "static", s.cfg.Console.StaticDir)
			if err := consoleSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("console serve: %w", err)
			}
		}()
	}
	if clusterConsoleSrv != nil {
		go func() {
			slog.Info("cluster console listening", "addr", clusterConsoleSrv.Addr)
			if err := clusterConsoleSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("cluster console serve: %w", err)
			}
		}()
	}

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	if consoleSrv != nil {
		_ = consoleSrv.Shutdown(shutCtx)
	}
	if clusterConsoleSrv != nil {
		_ = clusterConsoleSrv.Shutdown(shutCtx)
	}
	stopped := make(chan struct{})
	go func() {
		grpcSrv.GracefulStop()
		if ctrlSrv != nil {
			ctrlSrv.GracefulStop()
		}
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-shutCtx.Done():
		grpcSrv.Stop()
		if ctrlSrv != nil {
			ctrlSrv.Stop()
		}
	}
	slog.Info("controller stopped")
	return runErr
}
