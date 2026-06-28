package controller

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"geneza.io/internal/ca"
	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// sessionEntryTTL bounds a signaling entry's lifetime independently of the
// session-lifecycle unregister hooks: even if a session never reports terminal,
// the entry is reaped (and its stream cut) after this window. >= the ICE setup
// window with margin.
const sessionEntryTTL = 3 * time.Minute

// sessionSigWindow bounds one SessionSignal stream server-side (so it never
// relies on the client closing). Aligned with the entry TTL.
const sessionSigWindow = sessionEntryTTL

// Session-scoped ICE signaling (session p2p). When the broker grants a session
// it registers a sigEntry keyed by session_id. The ephemeral client opens a
// UserAPI.SessionSignal stream and the agent uses its NodeControl disco path;
// the controller forwards ICE creds/candidates ONLY between the two principals
// named in the brokered grant, keyed by session_id — NEVER the overlay
// wgpub path. The controller never sees session data (E2E Noise stays the boundary).

// sigEntry is one brokered session's signaling state.
type sigEntry struct {
	ws          string
	nodeID      string // the agent holding the other ICE end
	controlling bool   // the CLIENT's controller-assigned ICE role
	// The principal that may attach to this session's signaling — captured from
	// the grant's creator (the durable subject when present, else the username).
	user, subject, provider string
	// toClient buffers agent->client signals until the SessionSignal stream
	// drains them; ICE re-trickles, so a full buffer drops rather than blocks.
	toClient chan *genezav1.ControllerSignal
	attached atomic.Bool // at most one live client SessionSignal stream per session
	// toControl buffers controller->client enforcement pushes (revoke/lease/delta) for
	// the client's SessionControl stream (belt-and-suspenders teardown). The sweep
	// re-pushes the current lease every tick, so a full buffer drops rather than
	// blocks; controlAttached caps it to one live SessionControl stream.
	toControl       chan *genezav1.ControllerEnforcement
	controlAttached atomic.Bool
	expiry          time.Time // independent lifetime backstop (sessionEntryTTL)
	// done is closed exactly once when the entry is torn down (revoke / session
	// end / expiry), so an attached SessionSignal stream stops forwarding and
	// returns immediately instead of relaying ICE for a dead session.
	done      chan struct{}
	closeOnce sync.Once
}

func (e *sigEntry) close() { e.closeOnce.Do(func() { close(e.done) }) }

// authorizes reports whether the SessionSignal caller is the grant's principal.
// When the creator is a keyable login (has a stable subject) it REQUIRES the
// caller to present a matching non-empty subject — never the mutable username —
// mirroring the suspension/presence fail-closed rule (an empty-subject caller
// must not match a subject-bearing creator via name). The name fallback applies
// only when the creator itself has no subject (an operational/break-glass cert).
func (e *sigEntry) authorizes(ident *ca.Identity) bool {
	if ident.Workspace != e.ws {
		return false
	}
	if e.subject != "" {
		return ident.Subject == e.subject && normProvider(ident.Provider) == normProvider(e.provider)
	}
	return ident.Name == e.user
}

func (e *sigEntry) attach() bool { return e.attached.CompareAndSwap(false, true) }
func (e *sigEntry) detach()      { e.attached.Store(false) }

func (e *sigEntry) attachControl() bool { return e.controlAttached.CompareAndSwap(false, true) }
func (e *sigEntry) detachControl()      { e.controlAttached.Store(false) }

type sessionSignalBroker struct {
	mu      sync.Mutex
	entries map[string]*sigEntry
}

func newSessionSignalBroker() *sessionSignalBroker {
	return &sessionSignalBroker{entries: map[string]*sigEntry{}}
}

func (b *sessionSignalBroker) register(sessionID, ws, nodeID string, controlling bool, user, subject, provider string) {
	b.mu.Lock()
	b.entries[sessionID] = &sigEntry{
		ws: ws, nodeID: nodeID, controlling: controlling,
		user: user, subject: subject, provider: provider,
		toClient:  make(chan *genezav1.ControllerSignal, 32),
		toControl: make(chan *genezav1.ControllerEnforcement, 16),
		expiry:    time.Now().Add(sessionEntryTTL),
		done:      make(chan struct{}),
	}
	b.mu.Unlock()
}

func (b *sessionSignalBroker) unregister(sessionID string) {
	b.mu.Lock()
	if e := b.entries[sessionID]; e != nil {
		e.close()
		delete(b.entries, sessionID)
	}
	b.mu.Unlock()
}

// get returns the live entry for a session, or nil if absent or EXPIRED (an
// expired entry is reaped + its stream cut on access).
func (b *sessionSignalBroker) get(sessionID string) *sigEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.entries[sessionID]
	if e == nil {
		return nil
	}
	if !time.Now().Before(e.expiry) {
		e.close()
		delete(b.entries, sessionID)
		return nil
	}
	return e
}

// touch extends a live session's entry expiry so the (whole-session) control
// channel is not reaped by the ICE-setup-sized TTL. Called each sweep tick for
// every leased session; when leasing stops (session terminal), the entry lapses.
func (b *sessionSignalBroker) touch(sessionID string) {
	b.mu.Lock()
	if e := b.entries[sessionID]; e != nil {
		e.expiry = time.Now().Add(sessionEntryTTL)
	}
	b.mu.Unlock()
}

// sweepExpired reaps entries past their TTL (the lifecycle-independent backstop,
// driven by the continuous-authz sweep). Closes each reaped entry's done so any
// attached stream returns.
func (b *sessionSignalBroker) sweepExpired() {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, e := range b.entries {
		if !now.Before(e.expiry) {
			e.close()
			delete(b.entries, id)
		}
	}
}

// deliverToClient hands an agent-originated signal to the waiting client stream
// (non-blocking). Returns false if no client is registered or the buffer is full.
func (b *sessionSignalBroker) deliverToClient(sessionID string, sig *genezav1.ControllerSignal) bool {
	e := b.get(sessionID)
	if e == nil {
		return false
	}
	select {
	case e.toClient <- sig:
		return true
	default:
		return false
	}
}

// deliverControl hands a controller enforcement push to the client's SessionControl
// stream (non-blocking; the sweep re-pushes the lease so a full buffer is fine).
func (b *sessionSignalBroker) deliverControl(sessionID string, ctl *genezav1.ControllerEnforcement) bool {
	e := b.get(sessionID)
	if e == nil {
		return false
	}
	select {
	case e.toControl <- ctl:
		return true
	default:
		return false
	}
}

// setupSession (the broker's sessionP2PHook) mints the client+agent TURN creds
// and registers the SessionSignal entry for a brokered session. The client is
// the controlling side (it Dials); the agent Accepts. Returns nil creds when
// session_p2p is off, leaving the session on the relay floor.
func (s *Server) setupSession(sessionID, ws, nodeID, user, subject, provider string) (clientTurn, agentTurn *genezav1.TurnCreds) {
	if !s.cfg.SessionP2P {
		return nil, nil
	}
	clientTurn, err := s.sessionTurnCreds(sessionID, true) // client controls (Dials)
	if err != nil {
		slog.Warn("session p2p: mint client turn creds", "session", sessionID, "err", err)
	}
	if clientTurn == nil {
		clientTurn = &genezav1.TurnCreds{Controlling: true} // host-only (no relay)
	}
	agentTurn, err = s.sessionTurnCreds(sessionID, false) // agent accepts
	if err != nil || agentTurn == nil {
		agentTurn = &genezav1.TurnCreds{Controlling: false}
	}
	s.sessionSignals.register(sessionID, ws, nodeID, true, user, subject, provider)
	return clientTurn, agentTurn
}

// armInitialLease mints + pushes the first signed lease for a freshly-accepted
// session (the sessionP2PHook seam called by the broker). It is refreshLease at
// epoch 1.
func (s *Server) armInitialLease(rec *SessionRecord) { s.refreshLease(rec) }

// teardownSession removes a session's signaling entry (offer rejected, or the
// session went terminal) and forgets its epoch so a recycled id starts fresh.
// Idempotent.
func (s *Server) teardownSession(sessionID string) {
	if s.sessionSignals != nil {
		s.sessionSignals.unregister(sessionID)
	}
}

// reissueSession re-homes a LIVE session onto a surviving relay after the relay it
// was using drained or died: it re-mints a fresh signed grant (same session id,
// lease, continuous-authz; new rendezvous coordinates) and fans it to BOTH ends so
// they re-rendezvous and re-handshake Noise under the SAME session. It is the
// controller side of the in-session re-home loop, triggered by a RehomeRequest from
// either endpoint over the already-open signaling channel. Idempotent: two requests
// at the same epoch mint at most one grant (the broker bumps RehomeEpoch once).
func (s *Server) reissueSession(e *sigEntry, sessionID, deadRelayID, deadRelayAddr string, appliedEpoch int64) {
	rg, err := s.broker.ReissueGrant(e.ws, sessionID, deadRelayID, deadRelayAddr, appliedEpoch)
	if err != nil {
		slog.Info("session re-home: re-issue declined", "session", sessionID, "err", err)
		return
	}
	// Fan the fresh grant to the agent over its disco path and to the client over
	// its SessionSignal stream, each with its own ICE role + ephemeral TURN creds.
	// The agent re-EvaluateOffers the grant; the client re-runs the Noise gate — a
	// re-home is never a "trust the controller" shortcut.
	agentTurn, _ := s.sessionTurnCreds(sessionID, false) // agent accepts
	clientTurn, _ := s.sessionTurnCreds(sessionID, true) // client controls (Dials)

	_, _ = s.router.BridgeToAgent(e.nodeID, sessionID, &genezav1.DiscoMsg{
		SessionId: sessionID, Vni: 0,
		Body: &genezav1.DiscoMsg_Rehome{Rehome: &genezav1.SessionRehome{
			Epoch:       rg.Epoch,
			SignedGrant: rg.SignedGrant,
			RelayAddr:   rg.RelayAddr,
			RelayFloor:  rg.RelayFloor,
			RelayToken:  rg.RelayToken,
			Turn:        agentTurn,
			RelayCandidates: relayCandidatesToProto(rg.Grant.RelayCandidates),
		}},
	})
	s.sessionSignals.deliverToClient(sessionID, &genezav1.ControllerSignal{
		Controlling: e.controlling,
		Rehome: &genezav1.SessionRehome{
			Epoch:       rg.Epoch,
			SignedGrant: rg.SignedGrant,
			RelayAddr:   rg.RelayAddr,
			RelayFloor:  rg.RelayFloor,
			RelayToken:  rg.RelayToken,
			Turn:        clientTurn,
			RelayCandidates: relayCandidatesToProto(rg.Grant.RelayCandidates),
		},
	})
	slog.Info("session re-home: re-issued grant", "session", sessionID, "epoch", rg.Epoch,
		"dead_relay", deadRelayID, "floor", rg.RelayFloor)
}

// forwardClientSignalToAgent relays the client's ICE creds/candidates to the
// agent over its NodeControl disco path, stamped with session_id (vni=0) so the
// agent routes it to the session ICE engine, not the overlay.
func (s *Server) forwardClientSignalToAgent(e *sigEntry, sessionID string, sig *genezav1.ClientSignal) {
	// A re-home request: re-issue the session onto a surviving relay and fan the
	// fresh grant to both ends (never forwarded as plain ICE).
	if rr := sig.GetRehomeRequest(); rr != nil {
		s.reissueSession(e, sessionID, rr.GetDeadRelayId(), rr.GetDeadRelayAddr(), rr.GetAppliedEpoch())
		return
	}
	if c := sig.GetIceCreds(); c != nil {
		_, _ = s.router.BridgeToAgent(e.nodeID, sessionID, &genezav1.DiscoMsg{
			SessionId: sessionID, Vni: 0,
			Body: &genezav1.DiscoMsg_IceCreds{IceCreds: c},
		})
	}
	for _, cand := range sig.GetCandidates() {
		if cand == "" {
			continue
		}
		_, _ = s.router.BridgeToAgent(e.nodeID, sessionID, &genezav1.DiscoMsg{
			SessionId: sessionID, Vni: 0,
			Body: &genezav1.DiscoMsg_Endpoints{Endpoints: &genezav1.EndpointUpdate{Vni: 0, LocalAddrs: []string{cand}}},
		})
	}
}

// forwardAgentSignalToClient relays an agent-originated session DiscoMsg to the
// client's SessionSignal stream. It requires the signaling to come from the SAME
// node the session was brokered to, in the same workspace, so one node cannot
// inject ICE signaling into another node's session.
func (s *Server) forwardAgentSignalToClient(ws, fromNodeID, sessionID string, d *genezav1.DiscoMsg) {
	// Build the client-facing signal. Controlling comes from the session entry when
	// it is held here; for a session whose client lives on another controller the
	// controlling bit was decided at broker time and rides through unchanged.
	controlling := false
	local := s.sessionSignals.get(sessionID)
	if local != nil {
		if local.nodeID != fromNodeID || local.ws != ws {
			return // one node cannot inject ICE into another node's session
		}
		controlling = local.controlling
	}
	var sig *genezav1.ControllerSignal
	switch b := d.GetBody().(type) {
	case *genezav1.DiscoMsg_IceCreds:
		sig = &genezav1.ControllerSignal{IceCreds: b.IceCreds, Controlling: controlling}
	case *genezav1.DiscoMsg_Endpoints:
		sig = &genezav1.ControllerSignal{Candidates: b.Endpoints.GetLocalAddrs(), Controlling: controlling}
	default:
		return // CallMeMaybe/PunchAt are controller->agent only
	}
	if local != nil {
		s.sessionSignals.deliverToClient(sessionID, sig)
	}
	// Otherwise the client's signaling stream is on a different controller — an agent
	// that re-homed mid-session, since the broker redirect co-locates client and
	// agent on the owner at setup. The live tunnel is unaffected; only this late ICE
	// update is dropped, and the client re-establishes the path if it still needs one.
}
