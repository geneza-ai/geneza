package gateway

import (
	"context"
	"fmt"
	"sync"
	"time"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
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
