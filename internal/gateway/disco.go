package gateway

import (
	"bytes"
	"log/slog"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

// disco.go is the gateway's ICE signaling relay: a pure, stateless forwarder. The
// gateway is the trusted, always-connected coordinator both endpoints hold a
// control stream to, so it forwards each endpoint's ICE candidates + ufrag/pwd to
// the peer it names (the pion/ice signaling channel). It never inspects candidate
// strings beyond routing; connectivity checks + hole-punch happen agent↔agent
// over UDP. Ordering/restart robustness is handled at the AGENTS (they
// periodically re-announce until connected), so the gateway holds no signaling
// state to go stale. See docs/dataplane-libs-plan.md §3.3.
func (s *Server) handleAgentDisco(ws, fromNodeID string, d *genezav1.DiscoMsg) {
	dest := s.findNodeByWGPub(ws, d.GetPeerWgpub())
	if dest == nil {
		return // peer not found in this workspace
	}
	from, err := s.store.GetNode(ws, fromNodeID)
	if err != nil || len(from.WGPub) == 0 {
		return
	}
	// Forward to the destination, stamping the SOURCE's wgpub so the peer knows
	// which ICE agent the signaling belongs to. EndpointUpdate (our candidates)
	// becomes CallMeMaybe (the peer's candidates) on the receiving side.
	var out *genezav1.DiscoMsg
	switch b := d.GetBody().(type) {
	case *genezav1.DiscoMsg_Endpoints:
		out = &genezav1.DiscoMsg{Vni: d.GetVni(), PeerWgpub: from.WGPub,
			Body: &genezav1.DiscoMsg_CallMeMaybe{CallMeMaybe: &genezav1.CallMeMaybe{Candidates: b.Endpoints.GetLocalAddrs()}}}
	case *genezav1.DiscoMsg_IceCreds:
		out = &genezav1.DiscoMsg{Vni: d.GetVni(), PeerWgpub: from.WGPub,
			Body: &genezav1.DiscoMsg_IceCreds{IceCreds: b.IceCreds}}
	default:
		return // CallMeMaybe/PunchAt are gateway->agent only; ignore from an agent
	}
	if err := s.registry.SendDisco(dest.ID, out); err != nil {
		slog.Debug("disco relay not delivered (peer offline?)", "to", dest.ID, "err", err)
	}
}

func (s *Server) findNodeByWGPub(ws string, wgpub []byte) *NodeRecord {
	if len(wgpub) != 32 {
		return nil
	}
	nodes, err := s.store.ListNodes(ws)
	if err != nil {
		return nil
	}
	for _, n := range nodes {
		if bytes.Equal(n.WGPub, wgpub) {
			return n
		}
	}
	return nil
}
