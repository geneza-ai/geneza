package agentd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"osie.cloud/geneza/internal/ca"
	"osie.cloud/geneza/internal/defaults"
	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
	"osie.cloud/geneza/internal/types"
	"osie.cloud/geneza/internal/version"
)

const (
	healthTouchPeriod  = 10 * time.Second
	renewCheckPeriod   = time.Minute
	uploadScanPeriod   = 30 * time.Second
	reconnectBackoffLo = time.Second
	reconnectBackoffHi = 30 * time.Second
	hostRPCTimeout     = 5 * time.Second
)

// Worker is the long-running agent process: control channel, session-host
// supervision, data-path sessions and recording upload.
type Worker struct {
	cfg     *Config
	log     *slog.Logger
	st      *State
	noSpawn bool

	// mu guards the trust state that gateway pushes can rotate at runtime.
	mu      sync.RWMutex
	cluster *types.ClusterConfig
	trusted map[string]ed25519.PublicKey
	tlsCert tls.Certificate
	caPool  *x509.CertPool

	// Shared gateway gRPC conn; marked stale after cert/roots rotation so the
	// next user redials with fresh credentials.
	connMu    sync.Mutex
	conn      *grpc.ClientConn
	connStale bool

	hostMu   sync.Mutex
	hostConn *grpc.ClientConn

	// events is drained by whichever control stream is currently up; audit
	// events are best-effort across reconnects (buffered, dropped on overflow).
	events chan *genezav1.AgentMsg

	// uploadKick wakes the recording uploader right after (re)connect.
	uploadKick chan struct{}

	// Ephemeral SSH host key for sessions inside the tunnel. Identity is
	// proven by the Noise layer + signed grant, not by this key.
	hostSigner ssh.Signer

	// live tracks established sessions by id so a gateway SessionRevoke
	// (continuous authorization) can tear one down immediately.
	liveMu sync.Mutex
	live   map[string]context.CancelFunc

	// modules reconciles pluggable agent modules (monitoring, future exporters)
	// against the gateway's pushed ModuleConfig and streams their metrics up.
	modules *moduleManager
}

// advertisedServices converts the configured services into the hello message.
func (w *Worker) advertisedServices() []*genezav1.ServiceAdvert {
	out := make([]*genezav1.ServiceAdvert, 0, len(w.cfg.Services))
	for _, s := range w.cfg.Services {
		if s.Name == "" || !types.KnownServiceKind(s.Kind) {
			w.log.Warn("skipping invalid service decl", "name", s.Name, "kind", s.Kind)
			continue
		}
		out = append(out, &genezav1.ServiceAdvert{Name: s.Name, Kind: s.Kind, Addr: s.Addr, Labels: s.Labels})
	}
	return out
}

// registerLive records a live session's cancel func for revocation.
func (w *Worker) registerLive(id string, cancel context.CancelFunc) {
	w.liveMu.Lock()
	defer w.liveMu.Unlock()
	if w.live == nil {
		w.live = map[string]context.CancelFunc{}
	}
	w.live[id] = cancel
}

func (w *Worker) unregisterLive(id string) {
	w.liveMu.Lock()
	defer w.liveMu.Unlock()
	delete(w.live, id)
}

// revokeLive tears down a live session by id (gateway-driven continuous authz).
func (w *Worker) revokeLive(id, reason string) {
	w.liveMu.Lock()
	cancel := w.live[id]
	w.liveMu.Unlock()
	if cancel == nil {
		return // not here (maybe already ended, or on another node)
	}
	w.log.Warn("session revoked by gateway", "session", id, "reason", reason)
	cancel()
	w.emitEvent(&genezav1.SessionEvent{SessionId: id, Event: "revoked", Detail: reason})
}

// NewWorker loads persisted state and prepares the worker. It fails with a
// clear message when the agent has not been enrolled.
func NewWorker(log *slog.Logger, cfg *Config, noSpawnSessionHost bool) (*Worker, error) {
	st, err := LoadState(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	w := &Worker{
		cfg:        cfg,
		log:        log,
		st:         st,
		noSpawn:    noSpawnSessionHost,
		events:     make(chan *genezav1.AgentMsg, 256),
		uploadKick: make(chan struct{}, 1),
	}
	w.modules = newModuleManager(log, w.enqueue)
	cluster, trusted, err := parseAndCheckClusterConfig(st.ClusterRaw, 0)
	if err != nil {
		return nil, fmt.Errorf("cluster config in state dir: %w", err)
	}
	w.cluster = cluster
	w.trusted = trusted
	if err := w.reloadTLS(); err != nil {
		return nil, err
	}
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	w.hostSigner, err = ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		return nil, err
	}
	return w, nil
}

// reloadTLS rebuilds the mTLS client material from current state.
func (w *Worker) reloadTLS() error {
	cert, err := w.st.TLSCertificate()
	if err != nil {
		return fmt.Errorf("node certificate: %w", err)
	}
	pool, err := ca.PoolFromPEM(w.st.CARootsPEM)
	if err != nil {
		return fmt.Errorf("ca-roots.pem: %w", err)
	}
	w.mu.Lock()
	w.tlsCert = cert
	w.caPool = pool
	w.mu.Unlock()
	return nil
}

func (w *Worker) gatewayAddr() string {
	if w.cfg.GatewayGRPCAddr != "" {
		return w.cfg.GatewayGRPCAddr
	}
	return w.st.GatewayAddr
}

func (w *Worker) trustedKeys() map[string]ed25519.PublicKey {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.trusted
}

func (w *Worker) agentPolicy() types.AgentPolicy {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.cluster.AgentPolicy
}

func (w *Worker) clusterVersion() int64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.cluster.ConfigVersion
}

func (w *Worker) rootPool() *x509.CertPool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.caPool
}

// Run executes the worker event loop until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) error {
	if w.gatewayAddr() == "" {
		return fmt.Errorf("no gateway address: set gateway_grpc_addr in the config (state has none recorded)")
	}
	w.log.Info("worker starting",
		"node_id", w.st.NodeID,
		"gateway", w.gatewayAddr(),
		"version", version.Version,
		"cluster_config_version", w.clusterVersion())

	var wg sync.WaitGroup
	run := func(f func(context.Context)) {
		wg.Add(1)
		go func() { defer wg.Done(); f(ctx) }()
	}

	// Liveness for the bootstrap health gate. Written for as long as this
	// loop is alive, regardless of gateway reachability: a gateway outage
	// must never look like an unhealthy worker.
	run(w.healthFileLoop)

	if w.cfg.SpawnHost() && !w.noSpawn {
		run(w.superviseSessionHost)
	} else {
		w.log.Info("session host spawn disabled; expecting an externally supervised session host",
			"socket", w.cfg.SessionHostSocket)
	}

	// Policy is re-applied periodically (idempotent) so a restarted session
	// host converges back to the pushed guardrails even if we missed the
	// restart, and immediately on each verified config update.
	run(w.policySyncLoop)

	run(w.uploadLoop)
	run(w.streamLoop)

	wg.Wait()
	w.modules.stopAll()
	w.closeConn()
	w.closeHostConn()
	return ctx.Err()
}

// ---------------------------------------------------------------------------
// Health file
// ---------------------------------------------------------------------------

func (w *Worker) healthFileLoop(ctx context.Context) {
	if err := os.MkdirAll(filepath.Dir(w.cfg.HealthFile), 0o755); err != nil {
		w.log.Error("create health file dir", "err", err)
	}
	t := time.NewTicker(healthTouchPeriod)
	defer t.Stop()
	w.touchHealth()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.touchHealth()
		}
	}
}

func (w *Worker) touchHealth() {
	content := fmt.Sprintf("ok %d pid=%d version=%s\n", time.Now().UnixMilli(), os.Getpid(), version.Version)
	if err := atomicWrite(w.cfg.HealthFile, []byte(content), 0o644); err != nil {
		w.log.Error("write health file", "path", w.cfg.HealthFile, "err", err)
	}
}

// ---------------------------------------------------------------------------
// Gateway connection management
// ---------------------------------------------------------------------------

// grpcConn returns the shared gateway connection, rebuilding it when the TLS
// material changed (cert renewal, CA roots rotation).
func (w *Worker) grpcConn() (*grpc.ClientConn, error) {
	w.connMu.Lock()
	defer w.connMu.Unlock()
	if w.conn != nil && !w.connStale {
		return w.conn, nil
	}
	if w.conn != nil {
		_ = w.conn.Close()
		w.conn = nil
	}
	w.mu.RLock()
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{w.tlsCert},
		RootCAs:      w.caPool,
		MinVersion:   tls.VersionTLS12,
	}
	w.mu.RUnlock()
	conn, err := grpc.NewClient(w.gatewayAddr(), grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, err
	}
	w.conn = conn
	w.connStale = false
	return conn, nil
}

func (w *Worker) markConnStale() {
	w.connMu.Lock()
	w.connStale = true
	w.connMu.Unlock()
}

func (w *Worker) closeConn() {
	w.connMu.Lock()
	defer w.connMu.Unlock()
	if w.conn != nil {
		_ = w.conn.Close()
		w.conn = nil
	}
}

// ---------------------------------------------------------------------------
// Control stream
// ---------------------------------------------------------------------------

func (w *Worker) streamLoop(ctx context.Context) {
	backoff := reconnectBackoffLo
	for {
		started := time.Now()
		err := w.streamOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		// A stream that lived a while means the gateway was reachable; start
		// the backoff over instead of compounding transient blips.
		if time.Since(started) > reconnectBackoffHi {
			backoff = reconnectBackoffLo
		}
		w.log.Warn("control stream down, reconnecting", "err", err, "backoff", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > reconnectBackoffHi {
			backoff = reconnectBackoffHi
		}
	}
}

func (w *Worker) streamOnce(ctx context.Context) error {
	conn, err := w.grpcConn()
	if err != nil {
		return err
	}
	client := genezav1.NewNodeControlClient(conn)

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := client.Stream(sctx)
	if err != nil {
		return err
	}

	// grpc client streams allow at most one concurrent Send; serialize.
	var sendMu sync.Mutex
	send := func(m *genezav1.AgentMsg) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(m)
	}

	hello := &genezav1.AgentMsg{Msg: &genezav1.AgentMsg_Hello{Hello: &genezav1.AgentHello{
		NodeId:               w.st.NodeID,
		Version:              version.Version,
		Labels:               w.cfg.Labels,
		Capabilities:         defaults.AgentCapabilities,
		ClusterConfigVersion: w.clusterVersion(),
		Services:             w.advertisedServices(),
	}}}
	if err := send(hello); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}
	w.log.Info("control stream connected", "gateway", w.gatewayAddr())
	w.kickUpload()

	// Heartbeats + queued session events ride the same stream.
	go func() {
		hb := time.NewTicker(defaults.HeartbeatPeriod)
		defer hb.Stop()
		for {
			select {
			case <-sctx.Done():
				return
			case <-hb.C:
				active, detached := w.sessionCounts(sctx)
				err := send(&genezav1.AgentMsg{Msg: &genezav1.AgentMsg_Heartbeat{Heartbeat: &genezav1.Heartbeat{
					UnixMs:           time.Now().UnixMilli(),
					ActiveSessions:   active,
					DetachedSessions: detached,
					Version:          version.Version,
					Healthy:          true,
				}}})
				if err != nil {
					cancel()
					return
				}
			case ev := <-w.events:
				if err := send(ev); err != nil {
					cancel()
					return
				}
			}
		}
	}()

	// Cert renewal piggybacks on stream lifetime: when it succeeds we force a
	// re-dial so the new certificate is actually presented.
	go func() {
		t := time.NewTicker(renewCheckPeriod)
		defer t.Stop()
		for {
			select {
			case <-sctx.Done():
				return
			case <-t.C:
				renewed, err := w.maybeRenewCert(sctx, client)
				if err != nil {
					w.log.Warn("cert renewal failed", "err", err)
					continue
				}
				if renewed {
					w.log.Info("node certificate renewed; re-dialing control stream")
					cancel()
					return
				}
			}
		}
	}()

	for {
		gw, err := stream.Recv()
		if err != nil {
			return err
		}
		switch m := gw.Msg.(type) {
		case *genezav1.GatewayMsg_SessionOffer:
			w.handleSessionOffer(ctx, m.SessionOffer, send)
		case *genezav1.GatewayMsg_SessionRevoke:
			w.revokeLive(m.SessionRevoke.GetSessionId(), m.SessionRevoke.GetReason())
		case *genezav1.GatewayMsg_ClusterConfig:
			w.handleClusterConfig(ctx, m.ClusterConfig)
		case *genezav1.GatewayMsg_ModuleConfig:
			w.modules.reconcile(m.ModuleConfig)
		case *genezav1.GatewayMsg_Ping:
			// Liveness probe; the next heartbeat answers it implicitly.
		default:
			w.log.Warn("unknown gateway message", "msg", fmt.Sprintf("%T", gw.Msg))
		}
	}
}

// enqueue best-effort queues any AgentMsg on the control stream outbox; dropped
// on overflow (metrics/events are re-sent on the next tick / reconnect).
func (w *Worker) enqueue(m *genezav1.AgentMsg) {
	select {
	case w.events <- m:
	default:
		w.log.Warn("agent message dropped (queue full)", "type", fmt.Sprintf("%T", m.GetMsg()))
	}
}

// emitEvent queues a session lifecycle event for the audit trail.
// Best-effort: events buffered across reconnects, dropped on overflow.
func (w *Worker) emitEvent(ev *genezav1.SessionEvent) {
	ev.UnixMs = time.Now().UnixMilli()
	w.enqueue(&genezav1.AgentMsg{Msg: &genezav1.AgentMsg_SessionEvent{SessionEvent: ev}})
}

// ---------------------------------------------------------------------------
// Cluster config updates
// ---------------------------------------------------------------------------

// handleClusterConfig verifies a pushed config against the CURRENTLY trusted
// grant keys. Rejecting on any failure is what contains a compromised
// gateway: it cannot rotate the fleet onto keys the agents never trusted.
func (w *Worker) handleClusterConfig(ctx context.Context, raw []byte) {
	env, err := types.DecodeSigned(raw)
	if err != nil {
		w.log.Error("REJECTED cluster config push: bad envelope", "err", err)
		return
	}
	newCfg, err := types.VerifyClusterConfig(w.trustedKeys(), env, w.clusterVersion())
	if err != nil {
		w.log.Error("REJECTED cluster config push: verification failed (possible gateway compromise)", "err", err)
		return
	}
	newTrusted, err := newCfg.TrustedKeys()
	if err != nil {
		w.log.Error("REJECTED cluster config push: bad grant keys", "err", err)
		return
	}

	if err := w.st.SaveClusterConfig(raw); err != nil {
		w.log.Error("persist cluster config", "err", err)
		return
	}
	rootsChanged := false
	if len(newCfg.CARootsPEM) > 0 && string(newCfg.CARootsPEM) != string(w.st.CARootsPEM) {
		if err := w.st.SaveCARoots(newCfg.CARootsPEM); err != nil {
			w.log.Error("persist ca-roots.pem", "err", err)
			return
		}
		rootsChanged = true
	}

	w.mu.Lock()
	w.cluster = newCfg
	w.trusted = newTrusted
	w.mu.Unlock()

	if rootsChanged {
		if err := w.reloadTLS(); err != nil {
			w.log.Error("reload TLS after CA roots update", "err", err)
		}
		w.markConnStale()
	}
	w.log.Info("cluster config applied", "version", newCfg.ConfigVersion, "grant_keys", len(newCfg.GrantKeys), "roots_changed", rootsChanged)
	w.applyHostPolicy(ctx)
}

// ---------------------------------------------------------------------------
// Certificate renewal
// ---------------------------------------------------------------------------

// needsRenewal reports whether less than 1/3 of the certificate lifetime
// remains. Pure for tests.
func needsRenewal(notBefore, notAfter, now time.Time) bool {
	ttl := notAfter.Sub(notBefore)
	if ttl <= 0 {
		return true
	}
	return now.After(notAfter.Add(-ttl / 3))
}

func (w *Worker) maybeRenewCert(ctx context.Context, client genezav1.NodeControlClient) (bool, error) {
	leaf, err := w.st.LeafCert()
	if err != nil {
		return false, err
	}
	if !needsRenewal(leaf.NotBefore, leaf.NotAfter, time.Now()) {
		return false, nil
	}
	csrPEM, err := ca.MakeCSR(w.st.Key, w.st.NodeID) // same key, fresh CSR
	if err != nil {
		return false, err
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := client.RenewCert(rctx, &genezav1.RenewCertRequest{CsrPem: csrPEM})
	if err != nil {
		return false, err
	}
	if len(resp.NodeCertPem) == 0 {
		return false, fmt.Errorf("gateway returned empty certificate")
	}
	if err := w.st.SaveNodeCert(resp.NodeCertPem); err != nil {
		return false, err
	}
	if err := w.st.SaveCARoots(resp.CaRootsPem); err != nil {
		return false, err
	}
	if err := w.reloadTLS(); err != nil {
		return false, err
	}
	w.markConnStale()
	return true, nil
}

// ---------------------------------------------------------------------------
// Session host client
// ---------------------------------------------------------------------------

// hostClient returns a SessionHost client over the unix socket. The conn is
// cached; gRPC reconnects under it as the host restarts.
func (w *Worker) hostClient() (genezav1.SessionHostClient, error) {
	w.hostMu.Lock()
	defer w.hostMu.Unlock()
	if w.hostConn == nil {
		conn, err := grpc.NewClient("unix://"+w.cfg.SessionHostSocket,
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, err
		}
		w.hostConn = conn
	}
	return genezav1.NewSessionHostClient(w.hostConn), nil
}

func (w *Worker) closeHostConn() {
	w.hostMu.Lock()
	defer w.hostMu.Unlock()
	if w.hostConn != nil {
		_ = w.hostConn.Close()
		w.hostConn = nil
	}
}

// sessionCounts queries SessionHost.Health; (0,0) when the socket is down so
// a dead session host never blocks heartbeats.
func (w *Worker) sessionCounts(ctx context.Context) (active, detached uint32) {
	h, ok := w.hostHealth(ctx)
	if !ok {
		return 0, 0
	}
	return h.Active, h.Detached
}

func (w *Worker) hostHealth(ctx context.Context) (*genezav1.HostHealthResponse, bool) {
	shc, err := w.hostClient()
	if err != nil {
		return nil, false
	}
	hctx, cancel := context.WithTimeout(ctx, hostRPCTimeout)
	defer cancel()
	h, err := shc.Health(hctx, &genezav1.HostEmpty{})
	if err != nil || h == nil || !h.Ok {
		return nil, false
	}
	return h, true
}

// applyHostPolicy pushes the cluster config's agent policy to the session
// host. Idempotent; errors are logged and retried by policySyncLoop.
func (w *Worker) applyHostPolicy(ctx context.Context) {
	pol := w.agentPolicy()
	ver := w.clusterVersion()
	shc, err := w.hostClient()
	if err != nil {
		w.log.Warn("apply host policy: no session host client", "err", err)
		return
	}
	hctx, cancel := context.WithTimeout(ctx, hostRPCTimeout)
	defer cancel()
	_, err = shc.ApplyPolicy(hctx, &genezav1.HostPolicy{
		ForbidDetach:    pol.ForbidDetach,
		MaxSessions:     pol.MaxSessions,
		MaxDetached:     pol.MaxDetached,
		RingBufferBytes: pol.RingBufferBytes,
		DetachedTtlSec:  pol.DetachedTTLSec,
		IdleReapSec:     pol.IdleReapSec,
	})
	if err != nil {
		w.log.Warn("apply host policy", "err", err)
		return
	}
	w.log.Debug("session host policy applied", "config_version", ver, "forbid_detach", pol.ForbidDetach)
}

// policySyncLoop converges host policy on a slow cadence so a restarted
// session host (which loses in-memory policy) is brought back in line even
// when the restart was not observed by this process.
func (w *Worker) policySyncLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	w.applyHostPolicy(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, ok := w.hostHealth(ctx); ok {
				w.applyHostPolicy(ctx)
			}
		}
	}
}
