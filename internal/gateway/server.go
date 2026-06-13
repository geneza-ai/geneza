package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"osie.cloud/geneza/internal/ca"
	"osie.cloud/geneza/internal/defaults"
	genezadns "osie.cloud/geneza/internal/dns"
	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
	"osie.cloud/geneza/internal/policy"
	"osie.cloud/geneza/internal/types"
	"osie.cloud/geneza/internal/version"
)

// Server wires the control plane together. It is constructed from an
// initialized data_dir (see InitDataDir) and fails closed on any missing or
// inconsistent material.
type Server struct {
	cfg      *Config
	ca       *ca.CA
	store    *Store
	audit    *Audit
	registry *Registry
	broker   *Broker
	identity *identityAuth

	grantKey    ed25519.PrivateKey
	grantKeyID  string
	artifactPub ed25519.PublicKey
	tlsCert     tls.Certificate

	enrollProviders map[string]EnrollProvider

	policyMu      sync.RWMutex
	policyEngines map[string]policy.Engine // per-workspace
	members       []WorkspaceConfig        // membership (from config)

	ccMu      sync.RWMutex
	ccVersion int64
	ccSigned  []byte

	metrics  *metricsStore
	resolver *genezadns.Resolver // policy-aware DNS for the tenant zone

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
	caInst, err := ca.Load(cfg.CADir())
	if err != nil {
		return nil, fmt.Errorf("load CA (did you run `geneza-gateway init`?): %w", err)
	}
	grantKey, err := types.LoadPrivateKeyPEM(cfg.GrantKeyPath())
	if err != nil {
		return nil, fmt.Errorf("load grant key: %w", err)
	}
	grantKeyID := types.KeyIDFor(grantKey.Public().(ed25519.PublicKey))
	if b, err := os.ReadFile(cfg.GrantKeyIDPath()); err == nil {
		if stored := strings.TrimSpace(string(b)); stored != grantKeyID {
			return nil, fmt.Errorf("grant.keyid %q does not match grant.key (%q): refusing to start", stored, grantKeyID)
		}
	}
	tlsCert, err := tls.LoadX509KeyPair(cfg.gatewayCertPath(), cfg.gatewayKeyPath())
	if err != nil {
		return nil, fmt.Errorf("load gateway TLS keypair: %w", err)
	}
	var artifactPub ed25519.PublicKey
	if cfg.ArtifactPubkeyFile != "" {
		artifactPub, err = types.LoadPublicKeyPEM(cfg.ArtifactPubkeyFile)
		if err != nil {
			return nil, fmt.Errorf("load artifact pubkey: %w", err)
		}
	}
	// One policy engine per workspace (config-driven). applyDefaults guarantees a
	// "default" workspace whose policy_file = the top-level policy_file.
	engines := make(map[string]policy.Engine, len(cfg.Workspaces))
	for _, w := range cfg.Workspaces {
		eng, err := policy.Load(w.PolicyFile)
		if err != nil {
			return nil, fmt.Errorf("load policy for workspace %q (%s): %w", w.ID, w.PolicyFile, err)
		}
		engines[w.ID] = eng
	}
	store, err := OpenStore(cfg.StatePath())
	if err != nil {
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

	s := &Server{
		cfg:           cfg,
		ca:            caInst,
		store:         store,
		audit:         audit,
		registry:      NewRegistry(),
		identity:      newIdentityAuth(cfg),
		grantKey:      grantKey,
		grantKeyID:    grantKeyID,
		artifactPub:   artifactPub,
		tlsCert:       tlsCert,
		policyEngines: engines,
		members:       cfg.Workspaces,
		overlays:      map[string]*overlayAllocator{},
		resolver:      genezadns.NewResolver(cfg.dnsZone()),
	}
	s.enrollProviders = map[string]EnrollProvider{
		"token":              &tokenProvider{store: store},
		"openstack-metadata": &openstackMetadataProvider{},
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
	}
	s.broker = NewBroker(store, audit, s.registry, s.policyFor, s.overlayFor,
		grantKey, grantKeyID, cfg.RelayAddrs, cfg.GrantTTL.D(), cfg.DefaultMaxSessionTTL.D())

	retention := cfg.MetricsRetention.D()
	if retention <= 0 {
		retention = 15 * 24 * time.Hour
	}
	// sink is nil = local TSDB only; wire a remoteWriteSink here for Thanos/Mimir.
	metrics, err := newMetricsStore(cfg.MetricsDir(), retention, slog.Default(), nil)
	if err != nil {
		store.Close()
		audit.Close()
		return nil, fmt.Errorf("metrics store: %w", err)
	}
	s.metrics = metrics

	if err := s.reconcileClusterConfig(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Server) Close() {
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

// policy returns the default workspace's engine (compat for the console's
// pre-workspace-resolution role lookup).
func (s *Server) policy() policy.Engine { return s.policyFor(defaultWorkspace) }

// reloadPolicies re-loads every workspace's policy file (admin ReloadPolicy).
func (s *Server) reloadPolicies() error {
	engines := make(map[string]policy.Engine, len(s.cfg.Workspaces))
	for _, w := range s.cfg.Workspaces {
		eng, err := policy.Load(w.PolicyFile)
		if err != nil {
			return fmt.Errorf("workspace %q (%s): %w", w.ID, w.PolicyFile, err)
		}
		engines[w.ID] = eng
	}
	s.policyMu.Lock()
	s.policyEngines = engines
	s.policyMu.Unlock()
	return nil
}

// workspacesForUser returns the workspaces a principal may log into: those whose
// membership matches (username or IdP group), plus every OPEN workspace.
func (s *Server) workspacesForUser(user string, groups []string) []string {
	gset := make(map[string]bool, len(groups))
	for _, g := range groups {
		gset[g] = true
	}
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

func buildClusterConfig(version int64, rootsPEM []byte, keyID string, pub ed25519.PublicKey, cfg *Config) types.ClusterConfig {
	return types.ClusterConfig{
		ConfigVersion: version,
		CARootsPEM:    rootsPEM,
		// Single key today; the list form is the rotation-overlap seam.
		GrantKeys:   []types.GrantKey{{KeyID: keyID, PublicKey: []byte(pub)}},
		AgentPolicy: cfg.AgentPolicy.toTypes(),
		RelayAddrs:  cfg.RelayAddrs,
	}
}

func signClusterConfig(cc types.ClusterConfig, key ed25519.PrivateKey, keyID string) ([]byte, error) {
	signed, err := types.Sign(key, keyID, defaults.ContextClusterConfig, cc)
	if err != nil {
		return nil, err
	}
	return signed.Encode()
}

// reconcileClusterConfig compares the config-file-derived desired state with
// the stored signed config (ignoring config_version) and bumps + re-signs on
// drift, so editing gateway.yaml and restarting converges the fleet.
func (s *Server) reconcileClusterConfig() error {
	storedVersion, err := s.store.ClusterConfigVersion()
	if err != nil {
		return fmt.Errorf("cluster config version: %w", err)
	}
	storedSigned, err := s.store.SignedClusterConfig()
	if err != nil {
		return err
	}
	if storedVersion == 0 || len(storedSigned) == 0 {
		return errors.New("no signed cluster config in store: run `geneza-gateway init` first")
	}
	signed, err := types.DecodeSigned(storedSigned)
	if err != nil {
		return fmt.Errorf("stored cluster config: %w", err)
	}
	var stored types.ClusterConfig
	if err := json.Unmarshal(signed.Payload, &stored); err != nil {
		return fmt.Errorf("stored cluster config payload: %w", err)
	}

	pub := s.grantKey.Public().(ed25519.PublicKey)
	candidate := buildClusterConfig(0, s.ca.RootsPEM, s.grantKeyID, pub, s.cfg)
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

	newVersion := storedVersion + 1
	candidate.ConfigVersion = newVersion
	newSigned, err := signClusterConfig(candidate, s.grantKey, s.grantKeyID)
	if err != nil {
		return fmt.Errorf("sign cluster config: %w", err)
	}
	if err := s.store.SetSignedClusterConfig(newVersion, newSigned); err != nil {
		return err
	}
	s.setClusterConfig(newVersion, newSigned)
	s.registry.Broadcast(newSigned)
	slog.Info("cluster config updated", "version", newVersion)
	return nil
}

func (s *Server) setClusterConfig(version int64, signed []byte) {
	s.ccMu.Lock()
	s.ccVersion = version
	s.ccSigned = signed
	s.ccMu.Unlock()
}

func (s *Server) clusterConfig() (int64, []byte) {
	s.ccMu.RLock()
	defer s.ccMu.RUnlock()
	return s.ccVersion, s.ccSigned
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
	out := make([]*genezav1.NodeSummary, 0, len(nodes))
	for _, n := range nodes {
		sum := &genezav1.NodeSummary{
			NodeId:    n.ID,
			Name:      n.Name,
			Labels:    n.Labels,
			Os:        n.Platform.OS,
			Arch:      n.Platform.Arch,
			Version:   n.Platform.AgentVersion,
			Approved:  n.Approved,
			OverlayIp: n.OverlayIP,
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
	grpcSrv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(grpcTLS)),
		grpc.ChainUnaryInterceptor(unaryAuthInterceptor()),
		grpc.ChainStreamInterceptor(streamAuthInterceptor()),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	genezav1.RegisterEnrollmentServer(grpcSrv, &enrollmentService{s: s})
	genezav1.RegisterNodeControlServer(grpcSrv, &nodeControlService{s: s})
	genezav1.RegisterUserAPIServer(grpcSrv, &userAPIService{s: s})
	genezav1.RegisterAdminAPIServer(grpcSrv, &adminAPIService{s: s})

	httpSrv := &http.Server{
		Addr:              s.cfg.HTTPListen,
		Handler:           s.httpHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{s.tlsCert},
			MinVersion:   tls.VersionTLS13,
		},
	}

	consoleSrv, err := s.consoleServer()
	if err != nil {
		return fmt.Errorf("console: %w", err)
	}

	// Continuous authorization: re-evaluate live sessions against current policy.
	go s.runContinuousAuthz(ctx, s.cfg.ReauthInterval.D())

	errCh := make(chan error, 3)
	go func() {
		slog.Info("gRPC listening", "addr", s.cfg.GRPCListen, "cluster", s.cfg.ClusterName, "version", version.Version)
		if err := grpcSrv.Serve(lis); err != nil {
			errCh <- fmt.Errorf("grpc serve: %w", err)
		}
	}()
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
	stopped := make(chan struct{})
	go func() {
		grpcSrv.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-shutCtx.Done():
		grpcSrv.Stop()
	}
	slog.Info("gateway stopped")
	return runErr
}
