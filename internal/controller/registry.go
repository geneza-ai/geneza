package controller

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

// AgentInfo is the live view of one connected agent.
type AgentInfo struct {
	Online       bool
	LastSeen     time.Time
	Version      string
	Healthy      bool
	Active       uint32
	Detached     uint32
	Capabilities []string
	Services     []types.Service
	// InventoryHash is the node's last-reported SBOM content hash (hex), carried on
	// the heartbeat. It is the visibility signal for inventory drift; the node ships
	// a full InventoryReport only when this changes.
	InventoryHash string
}

// controllerSender abstracts the gRPC server stream's send side (tests inject a
// fake; gRPC streams are not safe for concurrent Send, hence sendMu).
type controllerSender interface {
	Send(*genezav1.ControllerMsg) error
}

type agentHandle struct {
	nodeID string

	sendMu sync.Mutex
	stream controllerSender

	mu      sync.Mutex
	info    AgentInfo
	waiters map[string]chan *genezav1.SessionOfferAck
	// affEpoch is the affinity epoch this connection claimed in the shared
	// directory. A push whose target affinity epoch differs from this is aimed at a
	// superseded stream and must not be delivered through this handle.
	affEpoch int64

	// netVersion is the per-principal monotonic version stamped on each
	// NetworkConfig push. Computed (not stored) — Network membership is derived,
	// so the version need only be monotonic for the life of the connection.
	netVersion int64

	// Data-plane endpoint discovery: the observed source IP of this control
	// stream plus the per-Network WG listen ports the agent reported. Combined
	// they form the direct endpoint co-members are told to send WG packets to.
	epMu       sync.Mutex
	observedIP string
	wgPorts    map[uint32]int
}

func (h *agentHandle) setObservedIP(ip string) {
	h.epMu.Lock()
	h.observedIP = ip
	h.epMu.Unlock()
}

func (h *agentHandle) observedIPGet() string {
	h.epMu.Lock()
	defer h.epMu.Unlock()
	return h.observedIP
}

// cloneSnapshot reads the two values the clone-conflict check compares — the
// observed source IP and the last-heartbeat time — for a displaced handle whose
// recv loop is still mutating both. They live under different mutexes, so reading
// them in one helper (rather than two separate call-site reads) keeps the (ip,
// lastSeen) pair as consistent as a lock-free read allows and documents the intent.
func (h *agentHandle) cloneSnapshot() (observedIP string, lastSeen time.Time) {
	h.epMu.Lock()
	observedIP = h.observedIP
	h.epMu.Unlock()
	h.mu.Lock()
	lastSeen = h.info.LastSeen
	h.mu.Unlock()
	return observedIP, lastSeen
}

// setWGPort records a Network's reported listen port and reports whether it
// changed. The agent re-reports its ports after every reconcile; repushing only
// on a real change is what stops an endpoint-report→repush→reconcile→report
// feedback loop from flooding the control stream.
func (h *agentHandle) setWGPort(vni uint32, port int) (changed bool) {
	h.epMu.Lock()
	defer h.epMu.Unlock()
	if h.wgPorts == nil {
		h.wgPorts = map[uint32]int{}
	}
	if h.wgPorts[vni] == port {
		return false
	}
	h.wgPorts[vni] = port
	return true
}

// endpointFor returns the direct "ip:port" a co-member should send WG packets to
// for this node's given Network, or ok=false until both the source IP and the
// Network's listen port are known.
func (h *agentHandle) endpointFor(vni uint32) (string, bool) {
	h.epMu.Lock()
	defer h.epMu.Unlock()
	if h.observedIP == "" {
		return "", false
	}
	port := h.wgPorts[vni]
	if port == 0 {
		return "", false
	}
	return net.JoinHostPort(h.observedIP, strconv.Itoa(port)), true
}

// nextNetVersion returns the next monotonic NetworkConfig version for this
// connection. Serialized under sendMu so an explicit push and a sweep push
// cannot mint the same number.
func (h *agentHandle) nextNetVersion() int64 {
	h.sendMu.Lock()
	defer h.sendMu.Unlock()
	h.netVersion++
	return h.netVersion
}

func (h *agentHandle) send(msg *genezav1.ControllerMsg) error {
	h.sendMu.Lock()
	defer h.sendMu.Unlock()
	return h.stream.Send(msg)
}

func (h *agentHandle) addWaiter(sessionID string) (chan *genezav1.SessionOfferAck, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.waiters[sessionID]; exists {
		return nil, fmt.Errorf("duplicate offer for session %s", sessionID)
	}
	ch := make(chan *genezav1.SessionOfferAck, 1)
	h.waiters[sessionID] = ch
	return ch, nil
}

func (h *agentHandle) removeWaiter(sessionID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.waiters, sessionID)
}

func (h *agentHandle) deliverAck(ack *genezav1.SessionOfferAck) bool {
	h.mu.Lock()
	ch, ok := h.waiters[ack.GetSessionId()]
	h.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case ch <- ack:
	default: // duplicate ack; first one wins
	}
	return true
}

func (h *agentHandle) updateInfo(fn func(*AgentInfo)) {
	h.mu.Lock()
	fn(&h.info)
	h.mu.Unlock()
}

func (h *agentHandle) snapshot() AgentInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.info
}

// Registry tracks connected agent control streams.
type Registry struct {
	mu     sync.RWMutex
	agents map[string]*agentHandle
}

func NewRegistry() *Registry {
	return &Registry{agents: make(map[string]*agentHandle)}
}

// Register installs a handle for nodeID, replacing any stale one (the old
// stream's recv loop will fail on its own and its Unregister becomes a no-op
// thanks to the pointer comparison).
// Register installs the new control-stream handle for a node and returns it along
// with the prior handle it displaced (nil if none). A displaced handle that was
// still actively heartbeating from a different source IP is the clone-conflict
// signal the caller acts on — two hosts presenting the same node identity at once.
func (r *Registry) Register(nodeID string, stream controllerSender, hello *genezav1.AgentHello) (*agentHandle, *agentHandle) {
	h := &agentHandle{
		nodeID:  nodeID,
		stream:  stream,
		waiters: make(map[string]chan *genezav1.SessionOfferAck),
		info: AgentInfo{
			Online:       true,
			LastSeen:     time.Now(),
			Version:      hello.GetVersion(),
			Healthy:      true,
			Capabilities: hello.GetCapabilities(),
			Services:     servicesFromHello(nodeID, hello.GetServices()),
		},
	}
	r.mu.Lock()
	displaced := r.agents[nodeID]
	r.agents[nodeID] = h
	r.mu.Unlock()
	return h, displaced
}

func (r *Registry) Unregister(h *agentHandle) {
	r.mu.Lock()
	if cur, ok := r.agents[h.nodeID]; ok && cur == h {
		delete(r.agents, h.nodeID)
	}
	r.mu.Unlock()
}

func (r *Registry) get(nodeID string) *agentHandle {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.agents[nodeID]
}

func (r *Registry) Online(nodeID string) bool { return r.get(nodeID) != nil }

// Services returns the live services advertised by a connected node.
func (r *Registry) Services(nodeID string) ([]types.Service, bool) {
	h := r.get(nodeID)
	if h == nil {
		return nil, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]types.Service(nil), h.info.Services...), true
}

func servicesFromHello(nodeID string, adverts []*genezav1.ServiceAdvert) []types.Service {
	out := make([]types.Service, 0, len(adverts))
	for _, a := range adverts {
		if a.GetName() == "" || !types.KnownServiceKind(a.GetKind()) {
			continue
		}
		out = append(out, types.Service{
			Name: a.GetName(), Kind: a.GetKind(), Addr: a.GetAddr(),
			NodeID: nodeID, Labels: a.GetLabels(),
		})
	}
	return out
}

func (r *Registry) Info(nodeID string) (AgentInfo, bool) {
	h := r.get(nodeID)
	if h == nil {
		return AgentInfo{}, false
	}
	return h.snapshot(), true
}

// SendOffer pushes a signed grant to the agent and waits for the matching
// SessionOfferAck (correlated by session id) or the timeout.
func (r *Registry) SendOffer(ctx context.Context, nodeID, sessionID string, signedGrant []byte, turn *genezav1.TurnCreds, timeout time.Duration) (accepted bool, reason string, err error) {
	h := r.get(nodeID)
	if h == nil {
		return false, "", fmt.Errorf("node %s is not connected", nodeID)
	}
	ch, err := h.addWaiter(sessionID)
	if err != nil {
		return false, "", err
	}
	defer h.removeWaiter(sessionID)

	msg := &genezav1.ControllerMsg{
		Msg: &genezav1.ControllerMsg_SessionOffer{
			SessionOffer: &genezav1.SessionOffer{SignedGrant: signedGrant, Turn: turn},
		},
	}
	if err := h.send(msg); err != nil {
		return false, "", fmt.Errorf("send offer to %s: %w", nodeID, err)
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case ack := <-ch:
		return ack.GetAccepted(), ack.GetReason(), nil
	case <-t.C:
		return false, "", fmt.Errorf("node %s did not ack session offer within %s", nodeID, timeout)
	case <-ctx.Done():
		return false, "", ctx.Err()
	}
}

// SendRevoke tells the node to immediately terminate a live session
// (continuous authorization). The message is pre-signed by the caller (controller
// signRevoke) so the agent can verify it independently on a DIRECT path. Returns
// an error if the node is not connected.
//
// Enforcement messages (revoke/lease/delta) deliberately go straight through the
// serialized, blocking h.send (gRPC stream.Send) — there is NO bounded buffer
// here to drop them. The never-drop guarantee comes from the serialized send PLUS
// the idempotent per-sweep re-drive and reconnect re-push (continuousauthz.go).
// Do NOT introduce a buffered queue on this path.
func (r *Registry) SendRevoke(nodeID string, rev *genezav1.SessionRevoke) error {
	h := r.get(nodeID)
	if h == nil {
		return fmt.Errorf("node %s is not connected", nodeID)
	}
	return h.send(&genezav1.ControllerMsg{Msg: &genezav1.ControllerMsg_SessionRevoke{SessionRevoke: rev}})
}

// SendSessionLease refreshes a live session's fail-closed data-path lease (signed,
// monotonic epoch). Re-pushed every sweep tick; never buffered (see SendRevoke).
func (r *Registry) SendSessionLease(nodeID string, lease *genezav1.SessionLease) error {
	h := r.get(nodeID)
	if h == nil {
		return fmt.Errorf("node %s is not connected", nodeID)
	}
	return h.send(&genezav1.ControllerMsg{Msg: &genezav1.ControllerMsg_SessionLease{SessionLease: lease}})
}

// SendSessionPolicyDelta pushes a signed downgrade-only capability delta; the
// agent's per-op enforcement consumes it. Never buffered (see SendRevoke).
func (r *Registry) SendSessionPolicyDelta(nodeID string, delta *genezav1.SessionPolicyDelta) error {
	h := r.get(nodeID)
	if h == nil {
		return fmt.Errorf("node %s is not connected", nodeID)
	}
	return h.send(&genezav1.ControllerMsg{Msg: &genezav1.ControllerMsg_SessionPolicyDelta{SessionPolicyDelta: delta}})
}

// SendModuleConfig pushes a node's desired agent-module set in realtime. Returns
// an error if the node is not connected (it will get it on next reconnect).
func (r *Registry) SendModuleConfig(nodeID string, cfg *genezav1.ModuleConfig) error {
	h := r.get(nodeID)
	if h == nil {
		return fmt.Errorf("node %s is not connected", nodeID)
	}
	return h.send(&genezav1.ControllerMsg{Msg: &genezav1.ControllerMsg_ModuleConfig{ModuleConfig: cfg}})
}

// SendInventoryControl asks a connected node's inventory module to ship a full SBOM
// next cycle (sent when the controller could not apply a delta). Best-effort: an offline
// node re-collects and reports on reconnect, and the first report is always full.
func (r *Registry) SendInventoryControl(nodeID string, requestFull bool) error {
	h := r.get(nodeID)
	if h == nil {
		return fmt.Errorf("node %s is not connected", nodeID)
	}
	return h.send(&genezav1.ControllerMsg{Msg: &genezav1.ControllerMsg_InventoryControl{
		InventoryControl: &genezav1.InventoryControl{RequestFull: requestFull},
	}})
}

// SendNetworkConfig pushes a node's desired per-Network WireGuard set in
// realtime. Returns an error if the node is not connected (it reconciles on the
// next reconnect). The caller stamps cfg.Version via handle.nextNetVersion.
func (r *Registry) SendNetworkConfig(nodeID string, cfg *genezav1.NetworkConfig) error {
	h := r.get(nodeID)
	if h == nil {
		return fmt.Errorf("node %s is not connected", nodeID)
	}
	return h.send(&genezav1.ControllerMsg{Msg: &genezav1.ControllerMsg_NetworkConfig{NetworkConfig: cfg}})
}

// SendCertBundle pushes a node its sealed managed-domain certificate set; the
// agent reconciles to it declaratively. Returns an error if the node is not
// connected (reconnect re-pushes).
func (r *Registry) SendCertBundle(nodeID string, b *genezav1.CertBundle) error {
	h := r.get(nodeID)
	if h == nil {
		return fmt.Errorf("node %s is not connected", nodeID)
	}
	return h.send(&genezav1.ControllerMsg{Msg: &genezav1.ControllerMsg_CertBundle{CertBundle: b}})
}

// SendFunnelServe pushes a node its funnel-serve set (the public hostnames it
// hosts + relays to register with). Best-effort; reconnect re-pushes.
func (r *Registry) SendFunnelServe(nodeID string, fs *genezav1.FunnelServe) error {
	h := r.get(nodeID)
	if h == nil {
		return fmt.Errorf("node %s is not connected", nodeID)
	}
	return h.send(&genezav1.ControllerMsg{Msg: &genezav1.ControllerMsg_FunnelServe{FunnelServe: fs}})
}

// SendDisco forwards an ICE signaling message to a node (best-effort).
func (r *Registry) SendDisco(nodeID string, d *genezav1.DiscoMsg) error {
	h := r.get(nodeID)
	if h == nil {
		return fmt.Errorf("node %s is not connected", nodeID)
	}
	return h.send(&genezav1.ControllerMsg{Msg: &genezav1.ControllerMsg_Disco{Disco: d}})
}

// handle returns the live agentHandle for a node (nil if not connected); used by
// the network-push path to mint a per-connection monotonic version.
func (r *Registry) handle(nodeID string) *agentHandle { return r.get(nodeID) }

func (h *agentHandle) setAffinityEpoch(e int64) { h.mu.Lock(); h.affEpoch = e; h.mu.Unlock() }
func (h *agentHandle) affinityEpoch() int64     { h.mu.Lock(); defer h.mu.Unlock(); return h.affEpoch }

// NodeEndpoint returns the direct WG endpoint ("ip:port") for a node's Network,
// or ok=false when the node is offline or its endpoint is not yet discovered.
func (r *Registry) NodeEndpoint(nodeID string, vni uint32) (string, bool) {
	h := r.get(nodeID)
	if h == nil {
		return "", false
	}
	return h.endpointFor(vni)
}

// Broadcast pushes a config message to every connected agent. The caller builds
// the message (legacy cluster_config arm, or the split FleetState arm), so this is
// mode-agnostic. Best-effort: agents that miss it reconcile on their next hello.
func (r *Registry) Broadcast(msg *genezav1.ControllerMsg) {
	r.mu.RLock()
	handles := make([]*agentHandle, 0, len(r.agents))
	for _, h := range r.agents {
		handles = append(handles, h)
	}
	r.mu.RUnlock()
	for _, h := range handles {
		_ = h.send(msg)
	}
}
