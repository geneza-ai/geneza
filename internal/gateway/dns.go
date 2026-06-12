package gateway

import (
	"strings"
	"time"

	"osie.cloud/geneza/internal/ca"
	"osie.cloud/geneza/internal/policy"
)

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
	// Re-read under the lock and collect addresses already in use fleet-wide.
	fresh, err := s.store.GetNode(node.ID)
	if err == nil && fresh.OverlayIP != "" {
		return fresh.OverlayIP, nil
	}
	used := map[string]bool{}
	if all, err := s.store.ListNodes(); err == nil {
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
	if err := s.store.PutNode(updated); err != nil {
		return "", err
	}
	node.OverlayIP = ip
	return ip, nil
}

// dnsCanReach is the resolver's policy gate: a machine name resolves only if the
// caller would be allowed SOME way onto it (shell/exec/vpn). DNS is thus a strict
// projection of policy — the names you can resolve are exactly the ones you can
// reach. Denied -> the resolver returns NXDOMAIN (no enumeration oracle).
func (s *Server) dnsCanReach(ident *ca.Identity, node *NodeRecord) bool {
	eng := s.policy()
	for _, action := range []string{"shell", "exec", "vpn"} {
		d := eng.Evaluate(policy.Input{
			User:       ident.Name,
			Roles:      ident.Roles,
			NodeID:     node.ID,
			NodeName:   node.Name,
			NodeLabels: node.Labels,
			Action:     action,
			ClientPath: "native",
			Now:        time.Now(),
		})
		if d.Allow {
			return true
		}
	}
	return false
}

// dnsLookupA builds the per-caller A-record lookup the resolver calls: resolve a
// machine label to its stable overlay IP iff the node exists, is approved, and
// the caller may reach it. Anything else -> ok=false (NXDOMAIN).
func (s *Server) dnsLookupA(ident *ca.Identity) func(string) (string, uint32, bool) {
	return func(label string) (string, uint32, bool) {
		node, err := s.store.FindNode(strings.ToLower(label))
		if err != nil || node == nil {
			return "", 0, false
		}
		if !node.Approved {
			return "", 0, false
		}
		if !s.dnsCanReach(ident, node) {
			return "", 0, false
		}
		ip, err := s.ensureNodeOverlayIP(node)
		if err != nil || ip == "" {
			return "", 0, false
		}
		return ip, dnsTTL, true
	}
}
