package controller

import (
	"geneza.io/internal/types"
)

// nodeServices returns the full service set a node exposes: the implicit host
// services (shell/exec/sftp — the host itself) plus everything the agent
// advertised in its hello. Online-only (services live with the connection).
func (s *Server) nodeServices(node *NodeRecord) []types.Service {
	implicit := []types.Service{
		{Name: "shell", Kind: types.KindShell, NodeID: node.ID},
		{Name: "exec", Kind: types.KindExec, NodeID: node.ID},
		{Name: "sftp", Kind: types.KindSFTP, NodeID: node.ID},
	}
	adv, _ := s.registry.Services(node.ID)
	out := append(implicit, adv...)
	for i := range out {
		// Carry the node name for display; node labels are the node's, service
		// labels stay the service's own.
		out[i].NodeID = node.ID
	}
	return out
}

// resolveService finds a named service on a node (implicit or advertised).
func (s *Server) resolveService(node *NodeRecord, name string) (types.Service, bool) {
	for _, svc := range s.nodeServices(node) {
		if svc.Name == name {
			return svc, true
		}
	}
	return types.Service{}, false
}
