package controller

import (
	"log/slog"
	"strings"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/policy"
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
func (s *Server) networkPeers(net *NetworkRecord, self *NodeRecord, nodes []*NodeRecord, peerIPs map[string]string) []*genezav1.WGPeer {
	var peers []*genezav1.WGPeer
	for _, peer := range nodes {
		ip, ok := peerIPs[peer.ID]
		if !ok {
			continue // not an eligible peer on this Network (filtered in networkPeerIPs)
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
			slog.Debug("turn creds unavailable", "vni", net.VNI, "self", self.ID, "peer", peer.ID, "err", err)
		}
		peers = append(peers, wp)
	}
	return peers
}

// networkConfigProto builds the full desired NetworkConfig for a node. It lists
// the workspace node set once; repushAllNetworks shares one list across the whole
// fan-out via networkConfigFrom.
func (s *Server) networkConfigProto(ws string, node *NodeRecord, version int64) *genezav1.NetworkConfig {
	nodes, err := s.store.ListNodes(ws)
	if err != nil {
		slog.Warn("list nodes for network config", "ws", ws, "err", err)
	}
	return s.networkConfigFrom(ws, node, version, nodes)
}

// networkConfigFrom builds the desired config from an ALREADY-LISTED workspace
// node set, so a repush scans the node table once for the whole fan-out instead
// of once per node, per Network, and per direction. Each peer's per-Network
// overlay IP is resolved once and shared by the peer list and the DNS set.
func (s *Server) networkConfigFrom(ws string, node *NodeRecord, version int64, nodes []*NodeRecord) *genezav1.NetworkConfig {
	cfg := &genezav1.NetworkConfig{Version: version}
	var defaultRecs []*genezav1.DnsRecord
	for _, net := range s.desiredNetworks(ws, node) {
		ip, err := s.networkOverlayIP(ws, net, node)
		if err != nil || ip == "" {
			slog.Warn("own overlay IP unavailable; skipping network", "ws", ws, "vni", net.VNI, "node", node.ID, "err", err)
			continue
		}
		cidr := s.networkSubnet(ws, net)
		peerIPs := s.networkPeerIPs(ws, net, node, nodes)
		zone, recs := s.networkDNS(ws, net, node, ip, nodes, peerIPs)
		if net.VNI == vniForWorkspace(ws) {
			defaultRecs = recs // the primary overlay's names back the managed zones
		}
		cfg.Networks = append(cfg.Networks, &genezav1.NetworkSpec{
			Vni:         net.VNI,
			Name:        net.Name,
			OverlayCidr: ip + "/" + prefixLen(cidr),
			Peers:       s.networkPeers(net, node, nodes, peerIPs),
			DnsZone:     zone,
			DnsRecords:  recs,
		})
	}
	cfg.DnsZones = s.managedDNSZones(ws, defaultRecs)
	return cfg
}

// managedDNSZones builds the DNS-only zones for a workspace's managed-domain
// reservations: each reserved <label>.<base> resolves the same overlay names as
// the workspace's default zone, so a managed name works on the VPN exactly like
// the internal .geneza name. Empty when the feature is off or nothing reserved.
func (s *Server) managedDNSZones(ws string, defaultRecs []*genezav1.DnsRecord) []*genezav1.DnsZoneSpec {
	if !s.cfg.ManagedDomain.enabled() || len(defaultRecs) == 0 {
		return nil
	}
	subs, err := s.store.ListWorkspaceSubdomains(ws)
	if err != nil || len(subs) == 0 {
		return nil
	}
	out := make([]*genezav1.DnsZoneSpec, 0, len(subs))
	for _, r := range subs {
		out = append(out, &genezav1.DnsZoneSpec{Suffix: r.Zone(), Records: defaultRecs})
	}
	return out
}

// networkPeerIPs resolves every ELIGIBLE peer's per-Network overlay IP exactly
// once — the single membership filter (a different node, approved, WG-keyed,
// label-matched) shared by the peer list and the DNS set. For a non-default
// Network it loads the FIB once and serves bound peers from memory, falling back
// to the allocating resolve only for a peer with no binding yet — turning the old
// per-peer GetBinding/ListBindings (O(N) reads per peer → O(N²) per config) into
// one ListBindings per Network.
func (s *Server) networkPeerIPs(ws string, net *NetworkRecord, self *NodeRecord, nodes []*NodeRecord) map[string]string {
	out := make(map[string]string, len(nodes))
	eligible := func(p *NodeRecord) bool {
		return p.ID != self.ID && p.Approved && len(p.WGPub) > 0 && policy.LabelsMatch(net.Selector, p.Labels)
	}
	if net.VNI == vniForWorkspace(ws) {
		for _, peer := range nodes {
			if !eligible(peer) {
				continue
			}
			if ip, err := s.ensureNodeOverlayIP(peer); err == nil && ip != "" {
				out[peer.ID] = ip
			}
		}
		return out
	}
	bound := map[string]string{}
	if existing, err := s.store.ListBindings(ws, net.VNI); err == nil {
		for _, b := range existing {
			bound[b.NodeID] = b.OverlayIP
		}
	}
	for _, peer := range nodes {
		if !eligible(peer) {
			continue
		}
		if ip := bound[peer.ID]; ip != "" {
			out[peer.ID] = ip
			continue
		}
		if ip, err := s.networkOverlayIP(ws, net, peer); err == nil && ip != "" {
			out[peer.ID] = ip
		}
	}
	return out
}

// networkDNS builds THIS Network's zone suffix + the policy-filtered name->overlayIP
// record set this node may resolve, for the in-network local resolver. CRITICAL:
// the membership filter is IDENTICAL to networkPeers (approved + WG-keyed +
// LabelsMatch + has overlay IP), so a node's DNS-visible set == its WG peer set
// (node-scoped, Tailscale-style) — it can resolve exactly what it can route to,
// nothing more (isolation/policy by construction). selfIP is the node's own
// overlay IP on this Network (already computed by the caller).
func (s *Server) networkDNS(ws string, net *NetworkRecord, self *NodeRecord, selfIP string, nodes []*NodeRecord, peerIPs map[string]string) (string, []*genezav1.DnsRecord) {
	zone := s.dnsZoneFor(ws, net.Name)
	var recs []*genezav1.DnsRecord
	if lbl := dnsLabel(self.Name); lbl != "" && selfIP != "" {
		recs = append(recs, &genezav1.DnsRecord{Name: lbl, Ip: selfIP, Ttl: dnsTTL})
	}
	for _, peer := range nodes {
		ip, ok := peerIPs[peer.ID]
		if !ok {
			continue // same eligible peer set as networkPeers
		}
		lbl := dnsLabel(peer.Name)
		if lbl == "" {
			continue
		}
		recs = append(recs, &genezav1.DnsRecord{Name: lbl, Ip: ip, Ttl: dnsTTL})
	}
	return zone, recs
}

// dnsZoneFor is THIS Network's zone suffix / search domain. The base zone (default
// "geneza") is prefixed with the non-default network + workspace segments so each
// Network in each workspace has a distinct search domain, while the default
// workspace's default Network stays the bare base ("geneza") for back-compat:
//
//	default ws / default net      -> "geneza"
//	default ws / net "prod"       -> "prod.geneza"
//	ws "acme"  / net "prod"       -> "prod.acme.geneza"
//	ws "acme"  / default net      -> "acme.geneza"
func (s *Server) dnsZoneFor(ws, netName string) string {
	base := s.cfg.dnsZone()
	var segs []string
	if l := dnsLabel(netName); l != "" && l != "default" {
		segs = append(segs, l)
	}
	if l := dnsLabel(ws); l != "" && l != defaultWorkspace {
		segs = append(segs, l)
	}
	segs = append(segs, base)
	return strings.Join(segs, ".")
}

// dnsLabel sanitizes a machine/network/workspace name into a single DNS label
// (lowercase a-z0-9-, '.'/'_'/' ' -> '-', trimmed). Empty if nothing valid.
func dnsLabel(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		case r == '.' || r == '_' || r == ' ':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
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
		// Not held here. If another controller owns the stream, ring it so it re-derives
		// and pushes; otherwise the node is offline and reconnect re-derives. The
		// per-connection version counter lives on the owning controller's handle, so the
		// config can only be stamped where the agent is connected.
		s.router.RouteNetcfg(ws, nodeID)
		return
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
		s.pushNodeNetworksFrom(ws, n, nodes)
	}
}

// pushNodeNetworksFrom pushes one node's config from an already-listed workspace
// node set, so the repush fan-out shares a single ListNodes across every node
// instead of re-listing (and re-scanning bindings) per node.
func (s *Server) pushNodeNetworksFrom(ws string, node *NodeRecord, nodes []*NodeRecord) {
	if !node.Approved {
		return // pending nodes get no data plane
	}
	h := s.registry.handle(node.ID)
	if h == nil {
		s.router.RouteNetcfg(ws, node.ID)
		return
	}
	cfg := s.networkConfigFrom(ws, node, h.nextNetVersion(), nodes)
	if err := s.registry.SendNetworkConfig(node.ID, cfg); err != nil {
		slog.Debug("network config not pushed (node offline?)", "node", node.ID, "err", err)
	}
}
