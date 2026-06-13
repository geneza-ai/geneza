package gateway

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
	"osie.cloud/geneza/internal/types"
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
}

// gatewaySender abstracts the gRPC server stream's send side (tests inject a
// fake; gRPC streams are not safe for concurrent Send, hence sendMu).
type gatewaySender interface {
	Send(*genezav1.GatewayMsg) error
}

type agentHandle struct {
	nodeID string

	sendMu sync.Mutex
	stream gatewaySender

	mu      sync.Mutex
	info    AgentInfo
	waiters map[string]chan *genezav1.SessionOfferAck

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

func (h *agentHandle) send(msg *genezav1.GatewayMsg) error {
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
func (r *Registry) Register(nodeID string, stream gatewaySender, hello *genezav1.AgentHello) *agentHandle {
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
	r.agents[nodeID] = h
	r.mu.Unlock()
	return h
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
func (r *Registry) SendOffer(ctx context.Context, nodeID, sessionID string, signedGrant []byte, timeout time.Duration) (accepted bool, reason string, err error) {
	h := r.get(nodeID)
	if h == nil {
		return false, "", fmt.Errorf("node %s is not connected", nodeID)
	}
	ch, err := h.addWaiter(sessionID)
	if err != nil {
		return false, "", err
	}
	defer h.removeWaiter(sessionID)

	msg := &genezav1.GatewayMsg{
		Msg: &genezav1.GatewayMsg_SessionOffer{
			SessionOffer: &genezav1.SessionOffer{SignedGrant: signedGrant},
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
// (continuous authorization). Returns an error if the node is not connected.
func (r *Registry) SendRevoke(nodeID, sessionID, reason string) error {
	h := r.get(nodeID)
	if h == nil {
		return fmt.Errorf("node %s is not connected", nodeID)
	}
	return h.send(&genezav1.GatewayMsg{
		Msg: &genezav1.GatewayMsg_SessionRevoke{
			SessionRevoke: &genezav1.SessionRevoke{SessionId: sessionID, Reason: reason},
		},
	})
}

// SendModuleConfig pushes a node's desired agent-module set in realtime. Returns
// an error if the node is not connected (it will get it on next reconnect).
func (r *Registry) SendModuleConfig(nodeID string, cfg *genezav1.ModuleConfig) error {
	h := r.get(nodeID)
	if h == nil {
		return fmt.Errorf("node %s is not connected", nodeID)
	}
	return h.send(&genezav1.GatewayMsg{Msg: &genezav1.GatewayMsg_ModuleConfig{ModuleConfig: cfg}})
}

// SendNetworkConfig pushes a node's desired per-Network WireGuard set in
// realtime. Returns an error if the node is not connected (it reconciles on the
// next reconnect). The caller stamps cfg.Version via handle.nextNetVersion.
func (r *Registry) SendNetworkConfig(nodeID string, cfg *genezav1.NetworkConfig) error {
	h := r.get(nodeID)
	if h == nil {
		return fmt.Errorf("node %s is not connected", nodeID)
	}
	return h.send(&genezav1.GatewayMsg{Msg: &genezav1.GatewayMsg_NetworkConfig{NetworkConfig: cfg}})
}

// SendDisco forwards an ICE signaling message to a node (best-effort).
func (r *Registry) SendDisco(nodeID string, d *genezav1.DiscoMsg) error {
	h := r.get(nodeID)
	if h == nil {
		return fmt.Errorf("node %s is not connected", nodeID)
	}
	return h.send(&genezav1.GatewayMsg{Msg: &genezav1.GatewayMsg_Disco{Disco: d}})
}

// handle returns the live agentHandle for a node (nil if not connected); used by
// the network-push path to mint a per-connection monotonic version.
func (r *Registry) handle(nodeID string) *agentHandle { return r.get(nodeID) }

// NodeEndpoint returns the direct WG endpoint ("ip:port") for a node's Network,
// or ok=false when the node is offline or its endpoint is not yet discovered.
func (r *Registry) NodeEndpoint(nodeID string, vni uint32) (string, bool) {
	h := r.get(nodeID)
	if h == nil {
		return "", false
	}
	return h.endpointFor(vni)
}

// Broadcast pushes a (signed) cluster config to every connected agent.
// Best-effort: agents that miss it reconcile on their next hello.
func (r *Registry) Broadcast(signedClusterConfig []byte) {
	r.mu.RLock()
	handles := make([]*agentHandle, 0, len(r.agents))
	for _, h := range r.agents {
		handles = append(handles, h)
	}
	r.mu.RUnlock()
	for _, h := range handles {
		_ = h.send(&genezav1.GatewayMsg{
			Msg: &genezav1.GatewayMsg_ClusterConfig{ClusterConfig: signedClusterConfig},
		})
	}
}
