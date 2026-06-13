package gateway

import (
	"log/slog"
	"strings"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
	"osie.cloud/geneza/internal/policy"
)

// networkpush.go is the control half of the per-Network WireGuard data plane:
// it derives which Networks a principal belongs to (tag-gated, server-side),
// allocates stable per-Network overlay IPs (the FIB / BindingRecord), builds the
// NetworkConfig proto, and pushes it to connected nodes. The agent realizes each
// NetworkSpec as one kernel-WireGuard interface (see internal/agentd/network.go).
//
// Membership is the isolation root: a node whose labels do not match a Network's
// Selector never appears in that Network's desired set, so it gets no wg
// interface and no peer key — kernel WG then drops any stray packet.

// desiredNetworks returns the Networks a node is a member of: every Network in
// the workspace whose Selector matches the node's labels (empty Selector = all).
func (s *Server) desiredNetworks(ws string, node *NodeRecord) []*NetworkRecord {
	nets, err := s.store.ListNetworks(ws)
	if err != nil {
		slog.Warn("list networks", "ws", ws, "err", err)
		return nil
	}
	var out []*NetworkRecord
	for _, n := range nets {
		if policy.LabelsMatch(n.Selector, node.Labels) {
			out = append(out, n)
		}
	}
	return out
}

// networkSubnet returns the Network's primary subnet CIDR, falling back to the
// workspace overlay CIDR (the default Network's subnet) when none is recorded.
func (s *Server) networkSubnet(ws string, net *NetworkRecord) string {
	subs, err := s.store.ListSubnets(ws)
	if err == nil {
		for _, sn := range subs {
			if sn.NetworkID == net.ID && sn.CIDR != "" {
				return sn.CIDR
			}
		}
	}
	if wsRec, err := s.store.GetWorkspace(ws); err == nil && wsRec.OverlayCIDR != "" {
		return wsRec.OverlayCIDR
	}
	return defaultOverlayCIDR
}

// networkOverlayIP returns a STABLE per-(Network,node) overlay IP. For the
// workspace's DEFAULT Network it reuses the node's DNS-visible OverlayIP so name
// resolution and the data path agree; for any other Network it allocates from
// the Network's subnet and persists a BindingRecord (the FIB) so the assignment
// survives restarts and is idempotent.
func (s *Server) networkOverlayIP(ws string, net *NetworkRecord, node *NodeRecord) (string, error) {
	if net.VNI == vniForWorkspace(ws) {
		return s.ensureNodeOverlayIP(node)
	}
	// Fast path: an existing binding is authoritative.
	if b, err := s.store.GetBinding(ws, net.VNI, node.ID); err == nil && b.OverlayIP != "" {
		return b.OverlayIP, nil
	}
	s.overlayMu.Lock()
	defer s.overlayMu.Unlock()
	// Re-check under the lock (another resolve may have just allocated).
	if b, err := s.store.GetBinding(ws, net.VNI, node.ID); err == nil && b.OverlayIP != "" {
		return b.OverlayIP, nil
	}
	used := map[string]bool{}
	if existing, err := s.store.ListBindings(ws, net.VNI); err == nil {
		for _, b := range existing {
			used[b.OverlayIP] = true
		}
	}
	cidr := s.networkSubnet(ws, net)
	ip, err := allocIPInCIDR(cidr, used)
	if err != nil {
		return "", err
	}
	if err := s.store.PutBinding(&BindingRecord{
		WorkspaceID: ws, NetworkID: net.ID, VNI: net.VNI, NodeID: node.ID, OverlayIP: ip,
	}); err != nil {
		return "", err
	}
	return ip, nil
}

// prefixLen extracts the CIDR prefix (e.g. "24" from "100.64.0.0/24"); defaults
// to "24" when malformed.
func prefixLen(cidr string) string {
	if i := strings.LastIndexByte(cidr, '/'); i >= 0 && i+1 < len(cidr) {
		return cidr[i+1:]
	}
	return "24"
}

// networkPeers builds the WGPeer list for a Network from this node's vantage:
// every OTHER approved member with a WG key, advertising its per-Network overlay
// IP as a /32 allowedIP. Endpoints are filled by the endpoint-distribution phase
// (empty here means "no direct path yet").
func (s *Server) networkPeers(ws string, net *NetworkRecord, self *NodeRecord) []*genezav1.WGPeer {
	nodes, err := s.store.ListNodes(ws)
	if err != nil {
		slog.Warn("list nodes for peers", "ws", ws, "err", err)
		return nil
	}
	var peers []*genezav1.WGPeer
	for _, peer := range nodes {
		if peer.ID == self.ID || !peer.Approved || len(peer.WGPub) == 0 {
			continue
		}
		if !policy.LabelsMatch(net.Selector, peer.Labels) {
			continue
		}
		ip, err := s.networkOverlayIP(ws, net, peer)
		if err != nil || ip == "" {
			slog.Debug("peer overlay IP unavailable", "ws", ws, "vni", net.VNI, "peer", peer.ID, "err", err)
			continue
		}
		wp := &genezav1.WGPeer{
			WgPubkey:   peer.WGPub,
			AllowedIps: []string{ip + "/32"},
		}
		// Direct hint (LAN-only under NAT): observed control-stream source IP +
		// reported WG listen port. The userspace path treats this as a candidate;
		// the kernel path uses it directly on a flat L2.
		if ep, ok := s.registry.NodeEndpoint(peer.ID, net.VNI); ok {
			wp.Endpoint = ep
		}
		// Ephemeral TURN credentials (userspace pion data plane): the agent's ICE
		// agent uses them to allocate a relay candidate on the blind TURN floor.
		// Best-effort — on error the peer is still pushed (the kernel path ignores
		// .turn). Derived, not stored; the relay validates against a shared secret.
		if url, user, pass, realm, controlling, err := s.turnCredsFor(self.ID, peer.ID); err == nil {
			wp.Turn = &genezav1.TurnCreds{
				TurnUrl: url, Username: user, Password: pass, Realm: realm, Controlling: controlling,
			}
		} else {
			slog.Debug("turn creds unavailable", "ws", ws, "vni", net.VNI, "self", self.ID, "peer", peer.ID, "err", err)
		}
		peers = append(peers, wp)
	}
	return peers
}

// networkConfigProto builds the full desired NetworkConfig for a node.
func (s *Server) networkConfigProto(ws string, node *NodeRecord, version int64) *genezav1.NetworkConfig {
	cfg := &genezav1.NetworkConfig{Version: version}
	for _, net := range s.desiredNetworks(ws, node) {
		ip, err := s.networkOverlayIP(ws, net, node)
		if err != nil || ip == "" {
			slog.Warn("own overlay IP unavailable; skipping network", "ws", ws, "vni", net.VNI, "node", node.ID, "err", err)
			continue
		}
		cidr := s.networkSubnet(ws, net)
		cfg.Networks = append(cfg.Networks, &genezav1.NetworkSpec{
			Vni:         net.VNI,
			Name:        net.Name,
			OverlayCidr: ip + "/" + prefixLen(cidr),
			Peers:       s.networkPeers(ws, net, node),
		})
	}
	return cfg
}

// pushNodeNetworks sends a node its current desired Network set (best-effort:
// offline nodes reconcile on reconnect, which re-pushes). Only nodes with a WG
// key participate; a node that enrolled before the data plane simply gets no
// push until it re-enrolls.
func (s *Server) pushNodeNetworks(ws, nodeID string) {
	node, err := s.store.GetNode(ws, nodeID)
	if err != nil {
		slog.Warn("load node for network push", "ws", ws, "node", nodeID, "err", err)
		return
	}
	if !node.Approved {
		return // pending nodes get no data plane
	}
	h := s.registry.handle(nodeID)
	if h == nil {
		return // offline; reconnect re-derives
	}
	cfg := s.networkConfigProto(ws, node, h.nextNetVersion())
	if err := s.registry.SendNetworkConfig(nodeID, cfg); err != nil {
		slog.Debug("network config not pushed (node offline?)", "node", nodeID, "err", err)
	}
}

// repushAllNetworks re-derives and pushes the Network set to every node in a
// workspace. This is the N×N fan-out primitive: a membership change for one node
// alters every co-member's peer list, so all must be re-pushed.
func (s *Server) repushAllNetworks(ws string) {
	nodes, err := s.store.ListNodes(ws)
	if err != nil {
		slog.Warn("repush all networks: list nodes", "ws", ws, "err", err)
		return
	}
	for _, n := range nodes {
		s.pushNodeNetworks(ws, n.ID)
	}
}
