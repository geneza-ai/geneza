package agentd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	mrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"geneza.io/internal/ca"
	"geneza.io/internal/defaults"
	"geneza.io/internal/icewire"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/sessionconn"
	"geneza.io/internal/types"
	"geneza.io/internal/version"
)

const (
	healthTouchPeriod  = 10 * time.Second
	renewCheckPeriod   = time.Minute
	uploadScanPeriod   = 30 * time.Second
	reconnectBackoffLo = time.Second
	reconnectBackoffHi = 30 * time.Second
	hostRPCTimeout     = 5 * time.Second

	// Map-refresh cadence: an enrolled agent pulls the signed cluster map with a
	// cheap unary, independent of the control Stream. The initial pull runs soon
	// after start (so a long-offline restart converges its fleet view without
	// waiting on the Stream); thereafter a jittered period bounds how long a
	// wedged push can leave the map stale.
	mapRefreshInitialDelay = 3 * time.Second
	mapRefreshPeriod       = 5 * time.Minute
	mapRefreshJitter       = time.Minute
	mapFetchTimeout        = 15 * time.Second
)

// Worker is the long-running agent process: control channel, session-host
// supervision, data-path sessions and recording upload.
type Worker struct {
	cfg     *Config
	log     *slog.Logger
	st      *State
	noSpawn bool

	// mu guards the trust state that controller pushes can rotate at runtime.
	mu      sync.RWMutex
	cluster *types.ClusterConfig
	trusted map[string]ed25519.PublicKey
	// configTrust is the set that verifies the ClusterConfig ENVELOPE (its
	// TrustKeys, pinned from the held config), separate from `trusted` which
	// verifies session grants. The split is what stops a single controller — which
	// holds only a grant key — from rewriting the fleet trust set.
	configTrust map[string]ed25519.PublicKey
	// Split-mode pinned trust root: the offline/threshold TrustKeys + Threshold the
	// node verifies every TrustAnchors push against (TOFU-pinned from the first anchor,
	// re-derived from the held anchors on reload), never the incoming document's own.
	// pinnedTrust is nil on a legacy node, which stays on the configTrust path.
	pinnedTrust     map[string]ed25519.PublicKey
	pinnedThreshold int
	anchorVersion   int64  // held TrustAnchors version (rollback floor for anchors)
	anchorRaw       []byte // the held MultiSigned anchor envelope (persisted verbatim)
	routineRaw      []byte // the held Signed RoutineMap envelope
	tlsCert         tls.Certificate
	caPool          *x509.CertPool

	// adoptMu serializes cluster-config adoption so the two adopt callers — the
	// Stream's pushed config and the unary map refresh — cannot interleave their
	// version check and swap and briefly roll the held trust set backwards.
	adoptMu sync.Mutex

	// directUntil pins the control stream to a direct controller dial after a
	// relay-homed stream failed fast, so a flapping relay cannot hot-loop the agent
	// between relay and direct.
	cooldownMu  sync.Mutex
	directUntil time.Time

	// Shared controller gRPC conn; marked stale after cert/roots rotation so the
	// next user redials with fresh credentials.
	connMu    sync.Mutex
	conn      *grpc.ClientConn
	connStale bool
	// controllerIdx selects which candidate controller to dial; advanced on a fast
	// stream failure so the agent re-homes to another controller when its own dies.
	// Atomic because controllerAddr reads it while connMu is already held.
	controllerIdx atomic.Uint64

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

	// live tracks established sessions by id so a controller SessionRevoke
	// (continuous authorization) can tear one down immediately, and so each session
	// carries its fail-closed lease timer + downgrade caps (see lease.go).
	liveMu sync.Mutex
	live   map[string]*liveSession

	// sessionICE holds the per-session ICE signaler for an in-progress session
	// p2p handshake, keyed by session_id, so a forwarded DiscoMsg.session_id
	// reaches the right session's ICE agent (not the overlay disco backend).
	sessionICEMu sync.Mutex
	sessionICE   map[string]*sessionSignaler

	// drainTriggers holds, per live session, the handler that reacts to a controller
	// proactive drain notice. It exists for EVERY session (p2p or relay-TCP), unlike
	// the ICE signaler, so a relay-TCP session is migrated off a draining relay too —
	// the handler drops the transport when the drained relay is the one in use, and the
	// session's existing recovery (agent in-session re-home for p2p, client reattach for
	// a detachable relay-TCP shell) carries it onto a survivor.
	drainMu       sync.Mutex
	drainTriggers map[string]func(relayID, relayAddr string)

	// modules reconciles pluggable agent modules (monitoring, future exporters)
	// against the controller's pushed ModuleConfig and streams their metrics up.
	modules *moduleManager

	// networks reconciles per-Network WireGuard interfaces against the controller's
	// pushed NetworkConfig (the data plane). nil when the agent has no WG key.
	networks *networkManager
	// certs holds the node's managed-domain certificates (sealed to its Noise key
	// by the controller, served via GetCertificate). nil if no Noise key.
	certs *certManager
	// funnels tracks the public funnel routes this node serves (controller-pushed).
	funnels *funnelManager
	// disco routes ICE signaling (candidates/creds) to the userspace data-plane
	// backend; nil on the kernel path.
	disco discoBackend
}

// workerSink adapts the data-plane bind's ICE signaling onto the control stream
// (AgentMsg.disco). The controller forwards each message to the named peer.
type workerSink struct{ enqueue func(*genezav1.AgentMsg) }

func (s workerSink) SendLocalCandidate(vni uint32, peerWGPub [32]byte, candidate string) {
	peer := peerWGPub
	s.enqueue(&genezav1.AgentMsg{Msg: &genezav1.AgentMsg_Disco{Disco: &genezav1.DiscoMsg{
		Vni: vni, PeerWgpub: peer[:],
		Body: &genezav1.DiscoMsg_Endpoints{Endpoints: &genezav1.EndpointUpdate{Vni: vni, LocalAddrs: []string{candidate}}},
	}}})
}

func (s workerSink) SendICECreds(vni uint32, peerWGPub [32]byte, ufrag, pwd string) {
	peer := peerWGPub
	s.enqueue(&genezav1.AgentMsg{Msg: &genezav1.AgentMsg_Disco{Disco: &genezav1.DiscoMsg{
		Vni: vni, PeerWgpub: peer[:],
		Body: &genezav1.DiscoMsg_IceCreds{IceCreds: &genezav1.IceCreds{Ufrag: ufrag, Pwd: pwd}},
	}}})
}

// registerDrainTrigger records a session's proactive-drain handler so a controller drain
// notice can reach it; fn decides (by relay id/addr) whether the notice applies and, if
// so, drops the transport so the session migrates. Registered for EVERY live session.
func (w *Worker) registerDrainTrigger(sessionID string, fn func(relayID, relayAddr string)) {
	w.drainMu.Lock()
	if w.drainTriggers == nil {
		w.drainTriggers = map[string]func(string, string){}
	}
	w.drainTriggers[sessionID] = fn
	w.drainMu.Unlock()
}

func (w *Worker) unregisterDrainTrigger(sessionID string) {
	w.drainMu.Lock()
	delete(w.drainTriggers, sessionID)
	w.drainMu.Unlock()
}

// fireDrainTrigger delivers a proactive drain notice to a session's handler (a no-op
// when the session has none, e.g. it already ended).
func (w *Worker) fireDrainTrigger(sessionID, relayID, relayAddr string) {
	w.drainMu.Lock()
	fn := w.drainTriggers[sessionID]
	w.drainMu.Unlock()
	if fn != nil {
		fn(relayID, relayAddr)
	}
}

// handleDisco routes a controller-relayed peer's ICE signaling to the bind.
func (w *Worker) handleDisco(d *genezav1.DiscoMsg) {
	// Session p2p signaling is keyed by session_id: route it to the per-session
	// ICE signaler, NOT the overlay disco backend.
	if sid := d.GetSessionId(); sid != "" {
		// A proactive drain notice routes to the per-session drain TRIGGER, which exists
		// for every session (p2p or relay-TCP) — unlike the ICE signaler, which is p2p-
		// only — so a relay-TCP-floor session is migrated off the draining relay too.
		if dn := d.GetDrainNotice(); dn != nil {
			w.fireDrainTrigger(sid, dn.GetDrainingRelayId(), dn.GetDrainingRelayAddr())
			return
		}
		// Everything else is session p2p ICE signaling: route it to the per-session ICE
		// signaler. Absent (a relay-TCP session) means there is no ICE handshake to feed.
		s := w.sessionSignalerFor(sid)
		if s == nil {
			return // no in-progress handshake for this session
		}
		switch b := d.GetBody().(type) {
		case *genezav1.DiscoMsg_IceCreds:
			s.deliver(&sessionconn.Signal{Ufrag: b.IceCreds.GetUfrag(), Pwd: b.IceCreds.GetPwd()})
		case *genezav1.DiscoMsg_CallMeMaybe:
			for _, c := range b.CallMeMaybe.GetCandidates() {
				s.deliver(&sessionconn.Signal{Candidate: c})
			}
		case *genezav1.DiscoMsg_Endpoints:
			for _, c := range b.Endpoints.GetLocalAddrs() {
				s.deliver(&sessionconn.Signal{Candidate: c})
			}
		case *genezav1.DiscoMsg_Rehome:
			s.deliverRehome(b.Rehome)
		}
		return
	}
	if w.disco == nil {
		return
	}
	switch b := d.GetBody().(type) {
	case *genezav1.DiscoMsg_CallMeMaybe:
		w.disco.DeliverCandidates(d.GetVni(), d.GetPeerWgpub(), b.CallMeMaybe.GetCandidates())
	case *genezav1.DiscoMsg_IceCreds:
		w.disco.DeliverICECreds(d.GetVni(), d.GetPeerWgpub(), b.IceCreds.GetUfrag(), b.IceCreds.GetPwd())
	case *genezav1.DiscoMsg_PunchAt:
		w.disco.DeliverPunchAt(d.GetVni(), d.GetPeerWgpub(), b.PunchAt.GetT0UnixMs(), int(b.PunchAt.GetAttempt()))
	}
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

// registerLive records a live session with its cancel func, parsed grant, and
// path class, and arms an initial fail-closed grace timer (the controller's first
// lease extends it). The grant is kept for the downgrade-subset check; the path
// class is reported in audit events.
func (w *Worker) registerLive(id string, cancel context.CancelFunc, grant *types.SessionGrant, pathClass string) {
	ls := &liveSession{
		cancel:         cancel,
		grant:          grant,
		pathClass:      pathClass,
		clientNoisePub: grant.ClientNoisePub,
	}
	w.liveMu.Lock()
	if w.live == nil {
		w.live = map[string]*liveSession{}
	}
	w.live[id] = ls
	w.liveMu.Unlock()
	// Arm the initial grace deadline so a session whose controller never leases it
	// still fails closed; the first controller lease (initial mint / first sweep)
	// extends it well before this fires.
	w.armLeaseTimer(id, time.Now().Add(defaults.SessionLeaseTTL).UnixMilli())
}

func (w *Worker) unregisterLive(id string) {
	w.liveMu.Lock()
	ls := w.live[id]
	delete(w.live, id)
	w.liveMu.Unlock()
	if ls != nil {
		ls.stopLeaseTimer()
	}
}

// revokeLive tears down a live session on an EXPLICIT controller revoke (authz
// denied). Unlike lease starvation, this reaps the host PTY too — a denied
// session must not survive as a reattachable detached shell.
func (w *Worker) revokeLive(id, reason string) {
	w.liveMu.Lock()
	ls := w.live[id]
	delete(w.live, id)
	w.liveMu.Unlock()
	pathClass, epoch := "", int64(0)
	if ls != nil {
		ls.stopLeaseTimer()
		ls.cancel() // tear down this process's live bridge (an attached session)
		pathClass = ls.pathClass
		ls.mu.Lock()
		epoch = ls.epoch
		ls.mu.Unlock()
	}
	// Kill at the session-host too: a DETACHED session — or any session
	// established by a PREVIOUS worker process (this worker restarted, or the
	// controller is delivering a revoke that was owed while we were offline) — is not
	// in w.live, so cancelling this process's bridge is not enough. The session
	// host (a separate, longer-lived process) still owns that PTY; look it up by
	// controller session id and kill it directly, or the revoked shell keeps running.
	w.killHostSession(id)
	w.log.Warn("session revoked by controller", "session", id, "reason", reason)
	// Always ack, even if nothing was here to kill (the session may have already
	// ended). The controller treats this "revoked" event as delivery confirmation
	// and stops re-pushing; acking an unknown session is safe and idempotent.
	w.emitEvent(&genezav1.SessionEvent{SessionId: id, Event: "revoked", Detail: reason, PathClass: pathClass, Epoch: epoch})
}

// killHostSession force-terminates the session-host PTY for a controller session
// id, regardless of which worker process established it (the host indexes its
// sessions by the controller session id). No-op if the host is unreachable or holds
// no such session.
func (w *Worker) killHostSession(sessionID string) {
	shc, err := w.hostClient()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	list, err := shc.List(ctx, &genezav1.HostListRequest{})
	if err != nil {
		return
	}
	for _, hs := range list.GetSessions() {
		if hs.GetSessionId() == sessionID {
			_, _ = shc.Kill(ctx, &genezav1.HostKillRequest{HostSessionId: hs.GetHostSessionId()})
			return
		}
	}
}

// setHostCaps pushes a downgrade to the session-host so it becomes the
// authoritative read-only/quiesce point — the cut reaches a DETACHED PTY with no
// agent bridge in the loop, and it survives a worker restart (the host is a
// separate process). Idempotent + non-fatal: the host may have reaped the session
// concurrently, or this worker holds no matching host session; the caller has
// already stored the caps agent-side regardless. read_only is derived from
// !AllowInput (a read-only shell has input disabled).
func (w *Worker) setHostCaps(sessionID string, c *genezav1.SessionCaps) {
	if c == nil {
		return
	}
	shc, err := w.hostClient()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	list, err := shc.List(ctx, &genezav1.HostListRequest{})
	if err != nil {
		return
	}
	for _, hs := range list.GetSessions() {
		if hs.GetSessionId() == sessionID {
			if _, err := shc.SetCaps(ctx, &genezav1.HostSetCapsRequest{
				HostSessionId:    hs.GetHostSessionId(),
				ReadOnly:         !c.GetAllowInput(),
				AllowNewChannels: c.GetAllowNewChannels(),
				AllowSftpWrite:   c.GetAllowSftpWrite(),
				AllowedForwards:  c.GetForwardTargets(),
			}); err != nil {
				w.log.Warn("failed to set host caps", "session", sessionID, "err", err)
			}
			return
		}
	}
}

// NewWorker loads persisted state and prepares the worker. It fails with a
// clear message when the agent has not been enrolled.
func NewWorker(log *slog.Logger, cfg *Config, noSpawnSessionHost bool) (*Worker, error) {
	st, err := LoadState(cfg.StateDir, cfg.nodeKeySource())
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
	w.funnels = newFunnelManager(log)
	if len(st.Noise.Private) == 32 {
		w.certs = newCertManager(log, filepath.Join(st.Dir, "managed-certs"), st.Noise.Private)
	}
	if st.HasWG {
		var backend wgBackend
		// Userspace (pion ICE/TURN/STUN over wireguard-go) is the DEFAULT data
		// plane: it NAT-traverses (hole-punch + relay fallback) and is cross-
		// platform, per the exec decision (memory geneza-dataplane-decision). The
		// kernel-wgctrl backend has no NAT traversal — a peer behind NAT (e.g. an
		// OpenStack VM) can only mesh on the userspace path. Kernel is opt-in via
		// `dataplane: kernel` for a same-L2, direct-only deployment.
		if strings.EqualFold(cfg.Dataplane, "kernel") {
			backend = realWGBackend{log: log}
			log.Info("data plane: kernel WireGuard (direct-only, no NAT traversal)")
		} else {
			us := newUserspaceWGBackend(log, cfg.DataplaneRelayOnly)
			us.SetSignalSink(workerSink{enqueue: w.enqueue})
			w.disco = us
			backend = us
			log.Info("data plane: userspace WireGuard over pion ICE/TURN/STUN", "relay_only", cfg.DataplaneRelayOnly)
		}
		w.networks = newNetworkManager(log, st.WGPriv, backend)
		// Report each Network's WG listen port up the control stream (kernel path
		// uses it for the direct hint; the ICE path reports 0 and pion gathers
		// host/srflx candidates itself).
		w.networks.report = func(eps []wgEndpoint) {
			msg := &genezav1.NetworkEndpoints{}
			for _, e := range eps {
				msg.Endpoints = append(msg.Endpoints, &genezav1.NetworkEndpoint{
					Vni: e.vni, ListenPort: uint32(e.port),
				})
			}
			w.enqueue(&genezav1.AgentMsg{Msg: &genezav1.AgentMsg_NetworkEndpoints{NetworkEndpoints: msg}})
		}
	} else {
		log.Warn("no wireguard key in state dir; per-Network data plane disabled (re-enroll to enable)")
	}
	// The legacy config seeds the trust/grant view on a legacy or migrating node. A
	// require-split node that holds only the split pair has no legacy config; it derives
	// everything from the anchors below.
	if len(st.ClusterRaw) > 0 {
		cluster, trusted, cerr := parseAndCheckClusterConfig(st.ClusterRaw, 0)
		if cerr != nil {
			return nil, fmt.Errorf("cluster config in state dir: %w", cerr)
		}
		w.cluster = cluster
		w.trusted = trusted
		// Pin the held config's trust set: every later push verifies against this,
		// never against the incoming config's own keys.
		w.configTrust, err = cluster.TrustedConfigKeys()
		if err != nil {
			return nil, fmt.Errorf("cluster trust keys: %w", err)
		}
	}
	// Split mode: when the state dir holds a verified anchor + routine map, re-pin the
	// trust root from the HELD anchors and adopt the split routing/trust view. This is
	// the reload counterpart of TOFU-at-enrollment — the channel is never re-trusted,
	// only the documents already on disk. A legacy node skips this and keeps the
	// configTrust path above unchanged.
	if st.SplitMode() {
		fs, ferr := parseAndCheckFleetState(st.AnchorRaw, st.RoutineMapRaw, 0, 0)
		if ferr != nil {
			return nil, fmt.Errorf("fleet state in state dir: %w", ferr)
		}
		if err := w.adoptFleetState(fs, st.AnchorRaw, st.RoutineMapRaw); err != nil {
			return nil, fmt.Errorf("adopt held fleet state: %w", err)
		}
	}
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

// controllerAddr returns the controller this agent should dial now: one of its candidate
// controllers selected by the current rotation index, so a re-home (advanceController)
// dials a different controller on the next connection.
func (w *Worker) controllerAddr() string {
	cands := w.controllerCandidates()
	if len(cands) == 0 {
		return ""
	}
	return cands[int(w.controllerIdx.Load()%uint64(len(cands)))]
}

// controllerCandidates is the set of controllers the agent may connect to: its configured
// or enrolled seed, plus any others discovered from the signed cluster config's
// ControllerEndpoints, so it can re-home when its current controller dies. The seed leads
// (it is always retained), discovered peers follow, deduped.
func (w *Worker) controllerCandidates() []string {
	seed := w.cfg.ControllerGRPCAddr
	if seed == "" {
		seed = w.st.ControllerAddr
	}
	out := make([]string, 0, 4)
	seen := map[string]bool{}
	if seed != "" {
		out = append(out, seed)
		seen[seed] = true
	}
	for _, a := range w.discoveredControllerAddrs() {
		if a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// discoveredControllerAddrs returns the gRPC addresses of the controllers in the current
// signed cluster config (the failover set), controller-interleaved + IP-first so a hung
// controller costs one failover step, not one per advertised address. Empty until the
// first config is held.
func (w *Worker) discoveredControllerAddrs() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.cluster == nil {
		return nil
	}
	return types.FailoverAddrs(w.cluster.ControllerEndpoints, false)
}

// advanceController rotates to the next candidate controller and forces a re-dial. It is
// called when a control stream failed fast (the controller is likely down), so the
// agent re-homes to another controller instead of hammering a dead one.
func (w *Worker) advanceController() {
	w.controllerIdx.Add(1)
	w.markConnStale()
}

func (w *Worker) trustedKeys() map[string]ed25519.PublicKey {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.trusted
}

// configTrustKeys is the pinned set that verifies a pushed ClusterConfig envelope
// (the held config's TrustKeys), distinct from trustedKeys() which verifies grants.
func (w *Worker) configTrustKeys() map[string]ed25519.PublicKey {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.configTrust
}

func (w *Worker) agentPolicy() types.AgentPolicy {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.cluster.AgentPolicy
}

// auditRecipient is the legacy single per-workspace age recipient (from the
// signed cluster config). Kept so an older host that reads only audit_recipient
// still seals to the workspace key; the full set rides auditRecipients.
func (w *Worker) auditRecipient() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.cluster == nil {
		return ""
	}
	return w.cluster.AuditRecipient
}

// auditRecipients is the full set the session host seals each recording to (from
// the signed cluster config). Empty when none is configured, in which case the
// host refuses to record rather than spool plaintext. With a single configured
// recipient this is a one-element set, identical to the pre-list behavior.
func (w *Worker) auditRecipients() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.cluster == nil {
		return nil
	}
	return w.cluster.EffectiveAuditRecipients()
}

// homeRegion is this agent's closest relay region, reported in its hello so the
// controller hands its sessions that region's relay candidates. With zero or one
// region in the signed map (the single-node default) it does no probing and just
// returns that region — so single-node behavior is unchanged. With several
// regions it STUN-RTT probes one relay per region and returns the closest.
func (w *Worker) homeRegion() string {
	w.mu.RLock()
	var relays []types.RelayNode
	if w.cluster != nil {
		relays = w.cluster.Relays
	}
	w.mu.RUnlock()
	var eps []icewire.RegionEndpoint
	seen := map[string]bool{}
	for _, r := range relays {
		if seen[r.RegionID] || len(r.Addrs) == 0 {
			continue
		}
		seen[r.RegionID] = true
		host, _, err := net.SplitHostPort(r.Addrs[0])
		if err != nil || host == "" {
			host = r.Addrs[0]
		}
		port := r.STUNPort
		if port == 0 {
			port = r.TURNPort
		}
		eps = append(eps, icewire.RegionEndpoint{Region: r.RegionID, Addr: net.JoinHostPort(host, strconv.Itoa(port))})
	}
	if len(eps) <= 1 {
		if len(eps) == 1 {
			return eps[0].Region
		}
		return ""
	}
	return icewire.ClosestRegion(eps, 2*time.Second)
}

// relayCertPubs returns the SPKI public keys of the relays in the current signed
// map. A dialed relay's leaf must match one of these (it is in the trusted
// fleet). Empty when the map carries no relay keys, in which case the dial pins
// nothing beyond chain-to-root.
func (w *Worker) relayCertPubs() [][]byte {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.cluster == nil {
		return nil
	}
	var out [][]byte
	for _, r := range w.cluster.Relays {
		if len(r.RelayCertPub) > 0 {
			out = append(out, r.RelayCertPub)
		}
	}
	return out
}

// keyScopes returns each trusted grant key's workspace scope (the scoped-grant
// floor), from the current cluster config.
func (w *Worker) keyScopes() map[string][]string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.cluster == nil {
		return nil
	}
	return w.cluster.KeyScopes()
}

func (w *Worker) clusterVersion() int64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.clusterVersionLocked()
}

// clusterVersionLocked returns the held config/routine-map version. In split mode the
// view's ConfigVersion is the routine map's, so the agent's rollback floor and the
// version it reports to the controller stay on one counter. Caller holds w.mu.
func (w *Worker) clusterVersionLocked() int64 {
	if w.cluster == nil {
		return 0
	}
	return w.cluster.ConfigVersion
}

func (w *Worker) rootPool() *x509.CertPool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.caPool
}

// Run executes the worker event loop until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) error {
	if w.controllerAddr() == "" {
		return fmt.Errorf("no controller address: set controller_grpc_addr in the config (state has none recorded)")
	}
	w.log.Info("worker starting",
		"node_id", w.st.NodeID,
		"controller", w.controllerAddr(),
		"version", version.Version,
		"cluster_config_version", w.clusterVersion())

	var wg sync.WaitGroup
	run := func(f func(context.Context)) {
		wg.Add(1)
		go func() { defer wg.Done(); f(ctx) }()
	}

	// Give the funnel manager its lifetime + relay transport so any pushed funnel
	// routes start registering with the relay pool.
	if w.funnels != nil {
		w.funnels.start(ctx, w.dialRelayFunnel)
	}

	// Liveness for the bootstrap health gate. Written for as long as this
	// loop is alive, regardless of controller reachability: a controller outage
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
	run(w.mapRefreshLoop)

	wg.Wait()
	w.modules.stopAll()
	if w.networks != nil {
		w.networks.downAll()
	}
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
// Controller connection management
// ---------------------------------------------------------------------------

// grpcConn returns the shared controller connection, rebuilding it when the TLS
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
	conn, err := grpc.NewClient(w.controllerAddr(),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		// Probe the controller so a black-holed control stream (a dead controller node, no
		// RST) fails fast and the agent re-homes, instead of blocking Recv forever.
		// Time >= the controller's keepalive MinTime (10s) so it never GOAWAYs us.
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                15 * time.Second,
			Timeout:             20 * time.Second,
			PermitWithoutStream: true,
		}))
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
		homed, err := w.streamOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		// A stream that lived a while means the controller was reachable; keep it and
		// start the backoff over. A stream that failed fast means this controller is
		// likely down, so re-home to the next candidate controller (no-op when only the
		// seed is known). gRPC keepalive makes even a black-holed controller fail fast.
		if time.Since(started) > reconnectBackoffHi {
			backoff = reconnectBackoffLo
		} else {
			w.advanceController()
			// A relay-homed stream that died fast: cool down to a direct controller dial
			// so a flapping relay does not hot-loop the agent between relay and direct.
			if homed {
				w.startDirectCooldown()
			}
		}
		w.log.Warn("control stream down, reconnecting", "err", err, "controller", w.controllerAddr(), "backoff", backoff)
		// Full jitter ([0, backoff]): a fleet that all lost the controller at once must
		// not reconnect in lockstep and stampede the SERIALIZABLE affinity claim. The
		// relay registrar de-correlates its re-homing the same way.
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(mrand.Int63n(int64(backoff) + 1))):
		}
		backoff *= 2
		if backoff > reconnectBackoffHi {
			backoff = reconnectBackoffHi
		}
	}
}

// streamOnce runs one control-stream connection and reports whether it was homed
// through a relay (so the caller can cool down a flapping relay). The transport is
// chosen by controlHomePlan: a direct controller dial (the default and single-node
// path) or a blind relay forward.
func (w *Worker) streamOnce(ctx context.Context) (bool, error) {
	region := w.homeRegion()
	plan := w.controlHomePlan(region)
	conn, cleanup, homed, err := w.controlConn(ctx, plan)
	if err != nil {
		return homed, err
	}
	defer cleanup()
	client := genezav1.NewNodeControlClient(conn)

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := client.Stream(sctx)
	if err != nil {
		return homed, err
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
		HomeRegion:           region,
	}}}
	if err := send(hello); err != nil {
		return homed, fmt.Errorf("send hello: %w", err)
	}
	w.log.Info("control stream connected", "controller", w.controllerAddr(), "relay_homed", homed)
	if w.networks != nil {
		// The controller re-derives and re-pushes the desired networks on this fresh
		// stream with a per-connection version that restarts at 1; re-baseline so those
		// pushes are not rejected as stale after a reconnect or a re-home to another
		// controller. Running interfaces are untouched, so the data plane holds until the
		// re-push reconciles it.
		w.networks.resetVersion()
	}
	w.kickUpload()

	// Heartbeats + queued session events ride the same stream.
	go func() {
		hb := time.NewTicker(defaults.HeartbeatPeriod)
		defer hb.Stop()
		// Self-measure the running binary once: the running image is immutable for the
		// life of this process, so a swap only takes effect on restart and the new
		// process measures its new image. The controller renders the drift verdict.
		binHash := measureSelf()
		for {
			select {
			case <-sctx.Done():
				return
			case <-hb.C:
				active, detached := w.sessionCounts(sctx)
				invHash, _ := w.modules.inventoryHash()
				err := send(&genezav1.AgentMsg{Msg: &genezav1.AgentMsg_Heartbeat{Heartbeat: &genezav1.Heartbeat{
					UnixMs:           time.Now().UnixMilli(),
					ActiveSessions:   active,
					DetachedSessions: detached,
					Version:          version.Version,
					Healthy:          true,
					InventoryHash:    invHash,
					BinaryHash:       binHash,
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
			return homed, err
		}
		switch m := gw.Msg.(type) {
		case *genezav1.ControllerMsg_SessionOffer:
			w.handleSessionOffer(ctx, m.SessionOffer, send)
		case *genezav1.ControllerMsg_SessionRevoke:
			w.applyRevoke(m.SessionRevoke)
		case *genezav1.ControllerMsg_SessionLease:
			w.applyLease(m.SessionLease)
		case *genezav1.ControllerMsg_SessionPolicyDelta:
			w.applyDelta(m.SessionPolicyDelta)
		case *genezav1.ControllerMsg_ClusterConfig:
			w.handleClusterConfig(ctx, m.ClusterConfig)
		case *genezav1.ControllerMsg_FleetState:
			w.handleFleetPush(ctx, m.FleetState.GetTrustAnchors(), m.FleetState.GetRoutineMap(), m.FleetState.GetClusterConfig())
		case *genezav1.ControllerMsg_ModuleConfig:
			w.modules.reconcile(m.ModuleConfig)
		case *genezav1.ControllerMsg_InventoryControl:
			// The controller could not apply our last delta (lost its base); ship a full
			// SBOM next cycle so both ends re-converge on a known set.
			if m.InventoryControl.GetRequestFull() {
				w.modules.requestFullInventory()
			}
		case *genezav1.ControllerMsg_NetworkConfig:
			if w.networks != nil {
				w.networks.reconcile(m.NetworkConfig)
			}
		case *genezav1.ControllerMsg_CertBundle:
			if w.certs != nil {
				w.certs.reconcile(m.CertBundle)
			}
		case *genezav1.ControllerMsg_FunnelServe:
			if w.funnels != nil {
				w.funnels.reconcile(m.FunnelServe)
			}
		case *genezav1.ControllerMsg_Disco:
			w.handleDisco(m.Disco)
		case *genezav1.ControllerMsg_Ping:
			// Liveness probe; the next heartbeat answers it implicitly.
		default:
			w.log.Warn("unknown controller message", "msg", fmt.Sprintf("%T", gw.Msg))
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

// mapRefreshLoop refreshes the signed fleet map directly from a controller with a
// cheap unary, decoupled from the control Stream: a long-disconnected or
// just-restarted agent converges its controller/relay/trust view without waiting on
// a Stream push, and a wedged push (Stream up but no version bump arriving) is
// caught within one refresh period. Best-effort — a controller outage falls back to
// the held map and never blocks. The Stream's own on-connect reconcile still
// does the bulk of the work on a healthy start; this is the backstop and the
// seam for homing the control socket away from the controller later.
func (w *Worker) mapRefreshLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(mapRefreshInitialDelay):
		if err := w.fetchClusterConfigOnce(ctx); err != nil {
			w.log.Debug("map refresh (initial) failed", "err", err)
		}
	}
	for {
		// Full jitter on the period so a fleet that all (re)started together does
		// not probe the seed controllers in lockstep — the same de-correlation the
		// reconnect backoff uses.
		d := mapRefreshPeriod + time.Duration(mrand.Int63n(int64(mapRefreshJitter)+1))
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
		if err := w.fetchClusterConfigOnce(ctx); err != nil {
			w.log.Debug("map refresh failed", "err", err)
		}
	}
}

// fetchClusterConfigOnce asks the current controller for a map newer than the one
// held; the controller returns nothing when the agent is already current. A
// returned config is adopted through the SAME verified path a pushed config
// takes (pinned-trust verification, persist, swap), so a hostile or stale seed
// cannot inject an untrusted or rolled-back map here either.
func (w *Worker) fetchClusterConfigOnce(ctx context.Context) error {
	conn, err := w.grpcConn()
	if err != nil {
		return err
	}
	client := genezav1.NewNodeControlClient(conn)
	fctx, cancel := context.WithTimeout(ctx, mapFetchTimeout)
	defer cancel()
	resp, err := client.FetchClusterConfig(fctx, &genezav1.MapRequest{HaveVersion: w.clusterVersion()})
	if err != nil {
		return err
	}
	anchorRaw, mapRaw, legacy := resp.GetTrustAnchors(), resp.GetRoutineMap(), resp.GetClusterConfig()
	if len(anchorRaw) == 0 && len(mapRaw) == 0 && len(legacy) == 0 {
		return nil // already current
	}
	w.handleFleetPush(ctx, anchorRaw, mapRaw, legacy)
	return nil
}

// handleClusterConfig verifies a config against the CURRENTLY trusted grant
// keys. Rejecting on any failure is what contains a compromised controller: it
// cannot rotate the fleet onto keys the agents never trusted. adoptMu serializes
// it against the unary refresh path so the version check and the swap are atomic
// — two concurrent adopts can never apply an older config over a newer one.
func (w *Worker) handleClusterConfig(ctx context.Context, raw []byte) {
	w.adoptMu.Lock()
	defer w.adoptMu.Unlock()
	env, err := types.DecodeSigned(raw)
	if err != nil {
		w.log.Error("REJECTED cluster config push: bad envelope", "err", err)
		return
	}
	// Verify the envelope against the PINNED trust set (the held config's
	// TrustKeys), never the incoming config's own — else a config could rotate its
	// own trust root. A config may carry a new TrustKeys set (rotation), but only
	// if it is itself signed by a currently-pinned key.
	newCfg, err := types.VerifyClusterConfig(w.configTrustKeys(), env, w.clusterVersion())
	if err != nil {
		w.log.Error("REJECTED cluster config push: verification failed (possible controller compromise)", "err", err)
		return
	}
	// An equal-version refresh is a no-op: this config is already held and applied.
	// Skipping it avoids a redundant persist + host-policy round trip when the unary
	// refresh and the Stream's on-connect reconcile both deliver the same newer
	// version in the startup window (both callers run under adoptMu). The strict-
	// newer swap below stays the correctness fence; VerifyClusterConfig already
	// refused anything older.
	if newCfg.ConfigVersion == w.clusterVersion() {
		return
	}
	newTrusted, err := newCfg.TrustedKeys()
	if err != nil {
		w.log.Error("REJECTED cluster config push: bad grant keys", "err", err)
		return
	}
	newConfigTrust, err := newCfg.TrustedConfigKeys()
	if err != nil {
		w.log.Error("REJECTED cluster config push: bad trust keys", "err", err)
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
	w.configTrust = newConfigTrust // adopt the rotated trust set for the next push
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

// clusterViewFromFleetState projects a verified split (anchors, routine map) pair onto
// the ClusterConfig view the rest of the agent already consumes (grant keys, agent
// policy, audit recipients, relay fleet, controller discovery set). It carries the routine
// map's ConfigVersion so the agent's version floor and the version it reports to the
// controller stay consistent with the legacy field. The trust fields come from the
// ANCHORS (the trust-class document), the routing fields from the ROUTINE MAP.
func clusterViewFromFleetState(fs *types.FleetState) *types.ClusterConfig {
	return &types.ClusterConfig{
		ConfigVersion:    fs.Map.ConfigVersion,
		CARootsPEM:       fs.Anchors.CARootsPEM,
		GrantKeys:        fs.Anchors.GrantKeys,
		AgentPolicy:      fs.Anchors.AgentPolicy,
		RelayAddrs:       fs.Map.RelayAddrs,
		Relays:           fs.Map.Relays,
		ControllerEndpoints: fs.Map.ControllerEndpoints,
		AuditRecipient:   fs.Anchors.AuditRecipient,
		AuditRecipients:  fs.Anchors.AuditRecipients,
	}
}

// adoptFleetState swaps in a verified split fleet state: it re-pins the trust root from
// the anchors (the held set the NEXT push verifies against), updates the grant-key set
// and the projected cluster view, advances both held versions, and reloads TLS if the
// CA roots rotated. Caller has already verified fs against the held pinned set (or the
// TOFU first-pin) and persisted the envelopes. anchorRaw/mapRaw are the exact verified
// bytes (kept for re-serving and rollback floors).
func (w *Worker) adoptFleetState(fs *types.FleetState, anchorRaw, mapRaw []byte) error {
	view := clusterViewFromFleetState(fs)
	grantKeys, err := fs.Anchors.TrustedGrantKeys()
	if err != nil {
		return err
	}
	pinned, err := fs.Anchors.PinnedTrustKeys()
	if err != nil {
		return err
	}
	rootsChanged := len(fs.Anchors.CARootsPEM) > 0 && string(fs.Anchors.CARootsPEM) != string(w.st.CARootsPEM)
	if rootsChanged {
		if err := w.st.SaveCARoots(fs.Anchors.CARootsPEM); err != nil {
			return fmt.Errorf("persist ca-roots.pem: %w", err)
		}
	}
	w.mu.Lock()
	w.cluster = view
	w.trusted = grantKeys
	w.pinnedTrust = pinned
	w.pinnedThreshold = fs.Anchors.Threshold
	w.anchorVersion = fs.Anchors.AnchorVersion
	w.anchorRaw = anchorRaw
	w.routineRaw = mapRaw
	w.mu.Unlock()
	if rootsChanged {
		if err := w.reloadTLS(); err != nil {
			w.log.Error("reload TLS after CA roots update", "err", err)
		}
		w.markConnStale()
	}
	return nil
}

// alreadyPinned reports whether the node holds a pinned split trust root.
func (w *Worker) alreadyPinned() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.pinnedTrust != nil
}

// handleFleetPush routes a config delivery that may carry split documents. A node that
// has already pinned the split trust root verifies the split pair and NEVER falls back
// to the legacy config (that would be a downgrade off the anchored trust set). A node
// that has not pinned yet (mid-migration) tries to adopt the split pair (TOFU first
// pin) when one is present, and otherwise — or if no split pair is offered — applies
// the legacy config exactly as before. anchorRaw/mapRaw are the split documents (may be
// empty); legacy is the fallback ClusterConfig (may be empty in a pure-split push).
func (w *Worker) handleFleetPush(ctx context.Context, anchorRaw, mapRaw, legacy []byte) {
	if len(anchorRaw) > 0 && len(mapRaw) > 0 {
		w.handleFleetState(ctx, anchorRaw, mapRaw)
		return
	}
	// No split pair offered. A pinned node must not regress to a legacy config; an
	// un-pinned node applies it as before.
	if w.alreadyPinned() {
		return
	}
	if len(legacy) > 0 {
		w.handleClusterConfig(ctx, legacy)
	}
}

// handleFleetState is the split-mode adopt path: it runs the two-step VerifyFleetState
// against the HELD pinned trust set (the anchors' TrustKeys, never the incoming
// document's own), and on success persists + adopts the pair. A node that has not yet
// pinned (still legacy) pins TOFU from this first anchor — anchored by the mTLS channel
// it arrived on, exactly as the legacy config is pinned at enrollment. Rejecting on any
// failure is what contains a compromised controller: a grant-key-forged routine map (bound
// to a wrong/absent anchor) or an anchor not signed by >=threshold pinned trust keys is
// refused. It shares adoptMu with the legacy path so the two cannot interleave.
func (w *Worker) handleFleetState(ctx context.Context, anchorRaw, mapRaw []byte) {
	w.adoptMu.Lock()
	defer w.adoptMu.Unlock()
	if len(anchorRaw) == 0 || len(mapRaw) == 0 {
		return
	}
	anchorEnv, err := types.DecodeMultiSigned(anchorRaw)
	if err != nil {
		w.log.Error("REJECTED fleet state: bad anchor envelope", "err", err)
		return
	}
	mapEnv, err := types.DecodeSigned(mapRaw)
	if err != nil {
		w.log.Error("REJECTED fleet state: bad routine map envelope", "err", err)
		return
	}

	w.mu.RLock()
	pinned, threshold := w.pinnedTrust, w.pinnedThreshold
	heldAnchorV, heldConfigV := w.anchorVersion, w.clusterVersionLocked()
	w.mu.RUnlock()

	if pinned == nil {
		// TOFU first-pin: derive the trust set from THIS anchor (the channel that
		// delivered it is the mTLS-authenticated controller, the same trust surface that
		// pins the legacy config at enrollment). Thereafter every push verifies against
		// the held set, never the incoming document's own.
		var a types.TrustAnchors
		if jerr := json.Unmarshal(anchorEnv.Payload, &a); jerr != nil {
			w.log.Error("REJECTED fleet state: bad anchor payload", "err", jerr)
			return
		}
		p, terr := a.PinnedTrustKeys()
		if terr != nil {
			w.log.Error("REJECTED fleet state: anchor lists no usable trust keys", "err", terr)
			return
		}
		pinned, threshold = p, a.Threshold
		heldAnchorV, heldConfigV = 0, w.clusterVersion()
	}

	fs, err := types.VerifyFleetState(pinned, threshold, heldAnchorV, heldConfigV, anchorEnv, mapEnv, time.Now())
	if err != nil {
		w.log.Error("REJECTED fleet state: verification failed (possible controller compromise)", "err", err)
		return
	}
	// An equal-version refresh of both documents is a no-op: already held and applied.
	w.mu.RLock()
	sameAnchor := fs.Anchors.AnchorVersion == w.anchorVersion
	sameMap := fs.Map.ConfigVersion == w.clusterVersionLocked()
	w.mu.RUnlock()
	if sameAnchor && sameMap && w.st.SplitMode() {
		return
	}
	if err := w.st.SaveFleetState(anchorRaw, mapRaw); err != nil {
		w.log.Error("persist fleet state", "err", err)
		return
	}
	if err := w.adoptFleetState(fs, anchorRaw, mapRaw); err != nil {
		w.log.Error("adopt fleet state", "err", err)
		return
	}
	w.log.Info("fleet state applied", "anchor_version", fs.Anchors.AnchorVersion, "config_version", fs.Map.ConfigVersion, "grant_keys", len(fs.Anchors.GrantKeys))
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
		return false, fmt.Errorf("controller returned empty certificate")
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
