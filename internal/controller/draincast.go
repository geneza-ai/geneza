package controller

import (
	"log/slog"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// draincast.go is the controller's PROACTIVE relay-drain hint: when a relay reports it
// is draining, the controller tells every live session to re-home OFF that relay NOW,
// instead of waiting for the draining relay to force-close its splices at the drain
// deadline. The notice carries only the draining relay's id; each endpoint already
// knows which relay it is using (the grant's floor head) and re-homes itself when —
// and only when — that is the relay being drained. The controller therefore needs no
// per-session relay tracking, and an endpoint not on the relay (or one that already
// migrated away) ignores the notice. The re-home itself runs the unchanged
// RehomeRequest -> ReissueGrant -> SessionRehome path, so the Noise + signed-grant
// gate re-runs end-to-end; a drain hint is never a trust shortcut.

// notifyRelayDraining fans a DrainNotice for drainingRelayID to every live session,
// so a session whose current relay is that one migrates immediately. It is called
// when a relay heartbeats unhealthy (draining). Idempotent: pushing the same notice
// each draining heartbeat is harmless — an endpoint already off the relay self-filters
// it, and a session mid-re-home dedups by epoch. Best-effort and off the data path:
// a push that does not reach an endpoint (offline node, full client buffer) is simply
// retried on the next draining heartbeat, and the endpoint's own transport-loss
// re-home remains the backstop when the relay finally force-closes.
func (s *Server) notifyRelayDraining(drainingRelayID, drainingRelayAddr string) {
	if drainingRelayID == "" && drainingRelayAddr == "" {
		return
	}
	sessions, err := s.store.ListAllSessions()
	if err != nil {
		slog.Debug("drain notice: list sessions", "relay", drainingRelayID, "err", err)
		return
	}
	pushed := 0
	for _, rec := range sessions {
		if rec.State != SessionActive && rec.State != SessionDetached {
			continue
		}
		if s.pushDrainNotice(rec, drainingRelayID, drainingRelayAddr) {
			pushed++
		}
	}
	if pushed > 0 {
		slog.Info("drain notice pushed", "relay", drainingRelayID, "addr", drainingRelayAddr, "sessions", pushed)
	}
}

// pushDrainNotice sends one session both ends a DrainNotice for a draining relay: the
// agent over its NodeControl disco path (routed to the controller holding it) and the
// client over its SessionSignal stream. Returns whether either end was reached. The
// notice carries both the relay id and its TCP rendezvous addr so an endpoint can match
// whichever it knows (a session p2p endpoint has the id; a relay-TCP-floor one has only
// the addr).
func (s *Server) pushDrainNotice(rec *SessionRecord, drainingRelayID, drainingRelayAddr string) bool {
	notice := &genezav1.DrainNotice{SessionId: rec.ID, DrainingRelayId: drainingRelayID, DrainingRelayAddr: drainingRelayAddr}
	agentOK, _ := s.router.BridgeToAgent(rec.NodeID, rec.ID, &genezav1.DiscoMsg{
		SessionId: rec.ID, Vni: 0,
		Body: &genezav1.DiscoMsg_DrainNotice{DrainNotice: notice},
	})
	clientOK := s.sessionSignals.deliverToClient(rec.ID, &genezav1.ControllerSignal{DrainNotice: notice})
	return agentOK || clientOK
}
