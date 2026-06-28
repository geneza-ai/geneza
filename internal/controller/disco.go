package controller

import (
	"bytes"
	"log/slog"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// disco.go is the controller's ICE signaling relay: a pure, stateless forwarder. The
// controller is the trusted, always-connected coordinator both endpoints hold a
// control stream to, so it forwards each endpoint's ICE candidates + ufrag/pwd to
// the peer it names (the pion/ice signaling channel). It never inspects candidate
// strings beyond routing; connectivity checks + hole-punch happen agent↔agent
// over UDP. Ordering/restart robustness is handled at the AGENTS (they
// periodically re-announce until connected), so the controller holds no signaling
// state to go stale. See docs/dataplane-libs-plan.md.
func (s *Server) handleAgentDisco(ws, fromNodeID string, d *genezav1.DiscoMsg) {
	// Session p2p signaling is keyed by session_id, NOT the overlay wgpub path:
	// forward the agent's creds/candidates to the client's SessionSignal stream
	// (only for the session brokered to THIS node — see forwardAgentSignalToClient).
	if sid := d.GetSessionId(); sid != "" {
		// An agent re-home request: re-issue the session onto a surviving relay,
		// authorized to come only from the node the session was brokered to.
		if rr := d.GetRehomeRequest(); rr != nil {
			if e := s.sessionSignals.get(sid); e != nil && e.nodeID == fromNodeID && e.ws == ws {
				s.reissueSession(e, sid, rr.GetDeadRelayId(), rr.GetDeadRelayAddr(), rr.GetAppliedEpoch())
			}
			return
		}
		s.forwardAgentSignalToClient(ws, fromNodeID, sid, d)
		return
	}
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
		return // CallMeMaybe/PunchAt are controller->agent only; ignore from an agent
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
