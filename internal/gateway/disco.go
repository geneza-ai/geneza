package gateway

import (
	"bytes"
	"log/slog"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

// disco.go is the gateway's ICE signaling relay. The gateway is the trusted,
// always-connected coordinator both endpoints hold a control stream to, so it
// forwards each endpoint's ICE candidates + ufrag/pwd to the peer it names (the
// pion/ice signaling channel). It never inspects candidate strings beyond
// routing; connectivity checks + hole-punch happen agent↔agent over UDP.
//
// Signaling has no other retransmit, so the gateway CACHES each directed pair's
// latest creds + candidates and, whenever one side announces (proving its ICE
// agent for the peer is up), REPLAYS the peer's cached announce back to it. That
// makes a restarting or late-joining peer converge regardless of arrival order.
// See docs/dataplane-libs-plan.md §3.3.

type discoKey struct {
	vni  uint32
	from string // source node id
	to   string // destination node id
}

type cachedDisco struct {
	ufrag      string
	pwd        string
	candidates []string
}

func (s *Server) handleAgentDisco(ws, fromNodeID string, d *genezav1.DiscoMsg) {
	dest := s.findNodeByWGPub(ws, d.GetPeerWgpub())
	if dest == nil {
		return // peer not found in this workspace
	}
	from, err := s.store.GetNode(ws, fromNodeID)
	if err != nil || len(from.WGPub) == 0 {
		return
	}
	vni := d.GetVni()

	s.discoMu.Lock()
	if s.discoCache == nil {
		s.discoCache = map[discoKey]*cachedDisco{}
	}
	key := discoKey{vni: vni, from: from.ID, to: dest.ID}
	c := s.discoCache[key]
	if c == nil {
		c = &cachedDisco{}
		s.discoCache[key] = c
	}
	switch b := d.GetBody().(type) {
	case *genezav1.DiscoMsg_IceCreds:
		nu, np := b.IceCreds.GetUfrag(), b.IceCreds.GetPwd()
		if nu != c.ufrag || np != c.pwd { // new ICE agent (restart) -> reset candidates
			c.ufrag, c.pwd, c.candidates = nu, np, nil
		}
	case *genezav1.DiscoMsg_Endpoints:
		for _, cand := range b.Endpoints.GetLocalAddrs() {
			if !contains(c.candidates, cand) {
				c.candidates = append(c.candidates, cand)
			}
		}
	default:
		s.discoMu.Unlock()
		return // CallMeMaybe/PunchAt are gateway->agent only
	}
	// Snapshot the peer's cached announce (dest -> from) for replay/catch-up.
	var replay cachedDisco
	if pc := s.discoCache[discoKey{vni: vni, from: dest.ID, to: from.ID}]; pc != nil {
		replay = cachedDisco{ufrag: pc.ufrag, pwd: pc.pwd, candidates: append([]string(nil), pc.candidates...)}
	}
	s.discoMu.Unlock()

	// Forward the live message to the destination (immediate, if it's ready).
	s.forwardDisco(dest.ID, from.WGPub, vni, d)
	// Replay what the destination already announced back to the sender, so the
	// sender (just proven ready) gets the peer's creds+candidates even if they
	// arrived before this agent existed.
	if replay.ufrag != "" || len(replay.candidates) > 0 {
		s.sendCachedDisco(from.ID, dest.WGPub, vni, replay)
	}
}

// forwardDisco translates an agent's disco to the peer's frame and sends it.
func (s *Server) forwardDisco(toNodeID string, peerWGPub []byte, vni uint32, d *genezav1.DiscoMsg) {
	var out *genezav1.DiscoMsg
	switch b := d.GetBody().(type) {
	case *genezav1.DiscoMsg_Endpoints:
		out = &genezav1.DiscoMsg{Vni: vni, PeerWgpub: peerWGPub,
			Body: &genezav1.DiscoMsg_CallMeMaybe{CallMeMaybe: &genezav1.CallMeMaybe{Candidates: b.Endpoints.GetLocalAddrs()}}}
	case *genezav1.DiscoMsg_IceCreds:
		out = &genezav1.DiscoMsg{Vni: vni, PeerWgpub: peerWGPub,
			Body: &genezav1.DiscoMsg_IceCreds{IceCreds: b.IceCreds}}
	default:
		return
	}
	if err := s.registry.SendDisco(toNodeID, out); err != nil {
		slog.Debug("disco relay not delivered (peer offline?)", "to", toNodeID, "err", err)
	}
}

// sendCachedDisco replays a cached announce (creds + candidates) to a node.
func (s *Server) sendCachedDisco(toNodeID string, peerWGPub []byte, vni uint32, c cachedDisco) {
	if c.ufrag != "" {
		_ = s.registry.SendDisco(toNodeID, &genezav1.DiscoMsg{Vni: vni, PeerWgpub: peerWGPub,
			Body: &genezav1.DiscoMsg_IceCreds{IceCreds: &genezav1.IceCreds{Ufrag: c.ufrag, Pwd: c.pwd}}})
	}
	if len(c.candidates) > 0 {
		_ = s.registry.SendDisco(toNodeID, &genezav1.DiscoMsg{Vni: vni, PeerWgpub: peerWGPub,
			Body: &genezav1.DiscoMsg_CallMeMaybe{CallMeMaybe: &genezav1.CallMeMaybe{Candidates: c.candidates}}})
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
