package agentd

import (
	"context"
	"log/slog"
	"net"
	"sync"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// funnelManager runs the public funnel routes this node serves (controller-pushed,
// declarative full set). For each route it starts a funnelClient per relay in the
// pool, which dials OUT, registers, and proxies funnel traffic to the local
// target. Until the worker wires a relay dialer + context (start), routes are
// recorded but not yet dialed.
type funnelManager struct {
	log *slog.Logger

	mu        sync.Mutex
	ctx       context.Context
	relayDial func(ctx context.Context, addr string) (net.Conn, error)
	routes    map[string]*runningFunnel // hostname -> running route
}

type runningFunnel struct {
	route  *genezav1.FunnelRoute
	cancel context.CancelFunc
}

func newFunnelManager(log *slog.Logger) *funnelManager {
	return &funnelManager{log: log, routes: map[string]*runningFunnel{}}
}

// start gives the manager the transport (relay dialer) and lifetime it needs to
// actually run registrations, and (re)starts any routes recorded before it.
func (m *funnelManager) start(ctx context.Context, relayDial func(context.Context, string) (net.Conn, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ctx = ctx
	m.relayDial = relayDial
	for host, rf := range m.routes {
		rf.cancel()
		m.startRouteLocked(host, rf.route)
	}
}

// reconcile applies the pushed funnel-serve set as the complete desired state.
func (m *funnelManager) reconcile(fs *genezav1.FunnelServe) {
	if fs == nil {
		return
	}
	desired := make(map[string]*genezav1.FunnelRoute, len(fs.GetRoutes()))
	for _, r := range fs.GetRoutes() {
		desired[r.GetHostname()] = r
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for host, rf := range m.routes {
		if _, ok := desired[host]; !ok {
			rf.cancel()
			delete(m.routes, host)
			m.log.Info("funnel route removed", "host", host)
		}
	}
	for host, r := range desired {
		if rf, ok := m.routes[host]; ok {
			if sameFunnelRoute(rf.route, r) {
				continue
			}
			rf.cancel()
		} else {
			m.log.Info("funnel route added", "host", host, "target", r.GetTarget(), "mode", r.GetMode(), "relays", len(r.GetRelayAddrs()))
		}
		m.startRouteLocked(host, r)
	}
}

// startRouteLocked starts (or records) a route. The caller holds m.mu.
func (m *funnelManager) startRouteLocked(host string, r *genezav1.FunnelRoute) {
	if m.ctx == nil || m.relayDial == nil {
		m.routes[host] = &runningFunnel{route: r, cancel: func() {}} // recorded; runs once start() wires transport
		return
	}
	rctx, cancel := context.WithCancel(m.ctx)
	m.routes[host] = &runningFunnel{route: r, cancel: cancel}
	for _, relayAddr := range r.GetRelayAddrs() {
		fc := &funnelClient{
			log: m.log, relayAddr: relayAddr, hostname: host, target: r.GetTarget(),
			regToken: r.GetRegToken(), relayDial: m.relayDial,
		}
		go fc.run(rctx)
	}
}

func (m *funnelManager) served() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.routes))
	for h := range m.routes {
		out = append(out, h)
	}
	return out
}

func sameFunnelRoute(a, b *genezav1.FunnelRoute) bool {
	if a.GetTarget() != b.GetTarget() || a.GetMode() != b.GetMode() {
		return false
	}
	ar, br := a.GetRelayAddrs(), b.GetRelayAddrs()
	if len(ar) != len(br) {
		return false
	}
	for i := range ar {
		if ar[i] != br[i] {
			return false
		}
	}
	return true
}
