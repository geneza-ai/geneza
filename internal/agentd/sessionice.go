package agentd

import (
	"context"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/sessionconn"
)

// sessionSignaler drives sessionconn.Signaler over the agent's NodeControl disco path
// for ONE session: outbound creds/candidates are enqueued as session-keyed
// DiscoMsgs; inbound (forwarded by the controller from the client) are delivered on
// a buffered channel. rehome carries a controller-pushed in-session relay re-home (a
// fresh grant + rendezvous coordinates) to the session's re-home loop.
type sessionSignaler struct {
	w         *Worker
	sessionID string
	in        chan *sessionconn.Signal
	rehome    chan *genezav1.SessionRehome
}

// drainNotice names a relay the controller is draining: by id (session p2p) and/or by
// its TCP rendezvous addr (a relay-TCP-floor session knows only the addr). It is the
// argument to a session's drain trigger (see Worker.registerDrainTrigger).
type drainNotice struct{ relayID, relayAddr string }

func (s *sessionSignaler) SendCreds(ufrag, pwd string) error {
	s.w.enqueue(&genezav1.AgentMsg{Msg: &genezav1.AgentMsg_Disco{Disco: &genezav1.DiscoMsg{
		SessionId: s.sessionID, Vni: 0,
		Body: &genezav1.DiscoMsg_IceCreds{IceCreds: &genezav1.IceCreds{Ufrag: ufrag, Pwd: pwd}},
	}}})
	return nil
}

func (s *sessionSignaler) SendCandidate(cand string) error {
	s.w.enqueue(&genezav1.AgentMsg{Msg: &genezav1.AgentMsg_Disco{Disco: &genezav1.DiscoMsg{
		SessionId: s.sessionID, Vni: 0,
		Body: &genezav1.DiscoMsg_Endpoints{Endpoints: &genezav1.EndpointUpdate{Vni: 0, LocalAddrs: []string{cand}}},
	}}})
	return nil
}

func (s *sessionSignaler) Recv(ctx context.Context) (*sessionconn.Signal, error) {
	select {
	case sig := <-s.in:
		return sig, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// deliver hands a controller-forwarded signal to the waiting ICE agent (non-blocking;
// a full buffer drops since ICE re-trickles).
func (s *sessionSignaler) deliver(sig *sessionconn.Signal) {
	select {
	case s.in <- sig:
	default:
	}
}

// deliverRehome hands a controller-pushed re-home to the session's re-home loop
// (non-blocking; the loop only ever awaits one at a time, and a duplicate/older
// epoch is dropped there).
func (s *sessionSignaler) deliverRehome(r *genezav1.SessionRehome) {
	select {
	case s.rehome <- r:
	default:
	}
}

func (w *Worker) registerSessionICE(sessionID string) *sessionSignaler {
	s := &sessionSignaler{
		w: w, sessionID: sessionID,
		in:     make(chan *sessionconn.Signal, 32),
		rehome: make(chan *genezav1.SessionRehome, 4),
	}
	w.sessionICEMu.Lock()
	if w.sessionICE == nil {
		w.sessionICE = map[string]*sessionSignaler{}
	}
	w.sessionICE[sessionID] = s
	w.sessionICEMu.Unlock()
	return s
}

func (w *Worker) unregisterSessionICE(sessionID string) {
	w.sessionICEMu.Lock()
	delete(w.sessionICE, sessionID)
	w.sessionICEMu.Unlock()
}

func (w *Worker) sessionSignalerFor(sessionID string) *sessionSignaler {
	w.sessionICEMu.Lock()
	defer w.sessionICEMu.Unlock()
	return w.sessionICE[sessionID]
}

// Note: the session ICE handshake now carries the session DATA — see
// runSession/sessionTransport in offer.go (sessionconn.Accept). The signaler registry
// above routes the controller-forwarded creds/candidates to that handshake.
