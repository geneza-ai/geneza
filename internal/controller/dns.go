package controller

// dns.go holds the controller's overlay-IP allocation used to build DNS records. The
// controller is NOT a DNS query endpoint: in-network DNS is resolved LOCALLY at each
// agent from the zone pushed in NetworkSpec.dns_records (see networkpush.go
// networkDNS) — there is no per-query controller path (memory geneza-roadmap-dns-tenancy).

// dnsTTL is short on purpose: overlay assignments and fleet membership change.
const dnsTTL = 15

// ensureNodeOverlayIP returns the node's stable overlay IP, assigning+persisting
// one from the machine sub-range on first use. Serialized so two concurrent
// resolves never hand out the same address.
func (s *Server) ensureNodeOverlayIP(node *NodeRecord) (string, error) {
	if node.OverlayIP != "" {
		return node.OverlayIP, nil
	}
	s.overlayMu.Lock()
	defer s.overlayMu.Unlock()
	// Re-read under the lock and collect addresses already in use WITHIN this
	// workspace (overlay IPs are per-tenant, so the uniqueness scan is ws-local).
	fresh, err := s.store.GetNode(node.WorkspaceID, node.ID)
	if err == nil && fresh.OverlayIP != "" {
		return fresh.OverlayIP, nil
	}
	used := map[string]bool{}
	if all, err := s.store.ListNodes(node.WorkspaceID); err == nil {
		for _, n := range all {
			if n.OverlayIP != "" {
				used[n.OverlayIP] = true
			}
		}
	}
	ip, err := allocMachineIP(used)
	if err != nil {
		return "", err
	}
	updated := node
	if fresh != nil {
		updated = fresh
	}
	updated.OverlayIP = ip
	if err := s.store.PutNode(updated.WorkspaceID, updated); err != nil {
		return "", err
	}
	node.OverlayIP = ip
	return ip, nil
}
