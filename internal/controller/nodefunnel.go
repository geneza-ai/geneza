package controller

import (
	"log/slog"
	"time"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// Funnel-serve distribution: the controller tells a target agent which public
// hostnames it serves, the local target to proxy to, and the relay pool to
// register with. The agent dials OUT to those relays (no inbound) and registers;
// the relay terminates public TLS and forwards into the agent's back-connection
// (see docs/managed-domain-spec.md §7b). Declarative + on-connect re-push, like
// the cert and network pushes.

// relayPoolControlAddrs returns the rendezvous endpoints of healthy, non-draining
// relays an agent should register its funnels with.
func (s *Server) relayPoolControlAddrs() []string {
	relays, err := s.store.ListRelays("")
	if err != nil {
		slog.Warn("funnel: list relays", "err", err)
		return nil
	}
	cutoff := time.Now().Add(-relayStaleTTL).Unix()
	var out []string
	for _, r := range relays {
		if r.Draining || r.ControlAddr == "" || r.LastSeenUnix < cutoff {
			continue
		}
		out = append(out, r.ControlAddr)
	}
	return out
}

func (s *Server) buildNodeFunnelServe(ws, nodeID string) *genezav1.FunnelServe {
	funnels, err := s.store.ListWorkspaceFunnels(ws)
	if err != nil {
		slog.Warn("funnel: list workspace funnels", "ws", ws, "err", err)
		return &genezav1.FunnelServe{}
	}
	var relays []string
	var routes []*genezav1.FunnelRoute
	for _, f := range funnels {
		if f.NodeID != nodeID {
			continue
		}
		if relays == nil {
			relays = s.relayPoolControlAddrs() // resolved once, only if this node has funnels
		}
		routes = append(routes, &genezav1.FunnelRoute{
			Hostname: f.Hostname, Target: f.Target, Mode: f.Mode, RelayAddrs: relays,
			RegToken: f.RegToken,
		})
	}
	return &genezav1.FunnelServe{Routes: routes}
}

// pushNodeFunnels sends a node its funnel-serve set if the feature is on and the
// node is connected here. Best-effort: an offline node reconciles on reconnect.
func (s *Server) pushNodeFunnels(ws, nodeID string) {
	if s.managedCerts == nil {
		return
	}
	if s.registry.handle(nodeID) == nil {
		return
	}
	if err := s.registry.SendFunnelServe(nodeID, s.buildNodeFunnelServe(ws, nodeID)); err != nil {
		slog.Debug("funnel-serve not pushed (node offline?)", "node", nodeID, "err", err)
	}
}
