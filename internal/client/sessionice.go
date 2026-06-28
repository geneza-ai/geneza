package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/flynn/noise"

	"geneza.io/internal/defaults"
	"geneza.io/internal/icewire"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/sessionconn"
)

// relayCredsFromProto converts the controller's relay candidate list to the ICE
// credential set. Empty leaves the dial on the scalar relay (single-node).
func relayCredsFromProto(cands []*genezav1.RelayCandidate) []icewire.RelayCred {
	out := make([]icewire.RelayCred, 0, len(cands))
	for _, c := range cands {
		out = append(out, icewire.RelayCred{
			TurnURL: c.GetTurnUrl(), TurnUser: c.GetUsername(),
			TurnPass: c.GetPassword(), Realm: c.GetRealm(),
		})
	}
	return out
}

// clientSignaler drives sessionconn.Signaler over a UserAPI.SessionSignal stream. Every
// ClientSignal carries the session_id so the controller routes it to the agent
// holding the other ICE end (and only that agent).
type clientSignaler struct {
	sessionID string
	stream    genezav1.UserAPI_SessionSignalClient
	pending   []string // extra candidates from a multi-candidate ControllerSignal
}

func (c *clientSignaler) SendCreds(ufrag, pwd string) error {
	return c.stream.Send(&genezav1.ClientSignal{
		SessionId: c.sessionID,
		IceCreds:  &genezav1.IceCreds{Ufrag: ufrag, Pwd: pwd},
	})
}

func (c *clientSignaler) SendCandidate(cand string) error {
	return c.stream.Send(&genezav1.ClientSignal{SessionId: c.sessionID, Candidates: []string{cand}})
}

func (c *clientSignaler) Recv(ctx context.Context) (*sessionconn.Signal, error) {
	if len(c.pending) > 0 {
		cand := c.pending[0]
		c.pending = c.pending[1:]
		return &sessionconn.Signal{Candidate: cand}, nil
	}
	g, err := c.stream.Recv()
	if err != nil {
		return nil, err
	}
	if ic := g.GetIceCreds(); ic != nil {
		return &sessionconn.Signal{Ufrag: ic.GetUfrag(), Pwd: ic.GetPwd()}, nil
	}
	// A proactive drain notice: the agent is the in-session re-home driver and tears
	// its transport off the draining relay, which breaks this conn and the client
	// reconnects/reattaches onto the re-issued rendezvous. There is nothing for the
	// ICE signaler to do with it, so treat it as an empty signal (re-read).
	if g.GetDrainNotice() != nil {
		return &sessionconn.Signal{}, nil
	}
	cands := g.GetCandidates()
	if len(cands) == 0 {
		return &sessionconn.Signal{}, nil // empty; the Connect loop ignores and re-reads
	}
	if len(cands) > 1 {
		// Bound the buffer so a peer can't grow it without limit; sessionconn.Connect caps
		// how many it actually ingests anyway.
		const maxPending = 64
		if extra := cands[1:]; len(c.pending)+len(extra) <= maxPending {
			c.pending = append(c.pending, extra...)
		}
	}
	return &sessionconn.Signal{Candidate: cands[0]}, nil
}

// dialSessionICE carries the session DATA over the ICE p2p path (direct or
// TURN-relayed): it opens the SessionSignal stream, runs sessionconn.Dial to get a
// reliable conn, and completes the UNCHANGED Noise+SSH stack on it. The stream
// stays open for the life of the session (ctx) for ICE re-nomination trickle.
// Returns an error (so the caller can fall back to the relay floor) rather than
// disturbing the relay path on failure.
func dialSessionICE(ctx context.Context, api genezav1.UserAPIClient, resp *genezav1.CreateSessionResponse, key noise.DHKey) (*Session, error) {
	t := resp.GetTurn()
	if t == nil {
		return nil, errSessionP2PUnavailable
	}
	stream, err := api.SessionSignal(ctx)
	if err != nil {
		return nil, fmt.Errorf("open session signal: %w", err)
	}
	sig := &clientSignaler{sessionID: resp.GetSessionId(), stream: stream}
	conn, path, err := sessionconn.Dial(ctx, sessionconn.Config{
		Controlling: t.GetControlling(), // client controls (Dials)
		TurnURL:     t.GetTurnUrl(),     // scalar fallback when no candidate list
		TurnUser:    t.GetUsername(),
		TurnPass:    t.GetPassword(),
		Candidates:  relayCredsFromProto(resp.GetRelayCandidates()),
		Gather:      12 * time.Second,
	}, sig)
	if err != nil {
		_ = stream.CloseSend()
		return nil, fmt.Errorf("session p2p dial: %w", err)
	}
	sess, err := dialGrantConn(resp, key, conn) // closes conn on failure
	if err != nil {
		_ = stream.CloseSend()
		return nil, err
	}
	// Belt-and-suspenders enforcement: on a DIRECT path the controller is off
	// the data path, so the client also honors revoke + lease-expiry over its own
	// SessionControl stream. If a compromised agent ignores a cut, the client still
	// closes its end; if the controller's lease stops refreshing, the client fails
	// closed on its own timer. The agent stays the primary gate.
	go sessionControlClient(ctx, api, sess)
	slog.Debug("session over p2p transport", "session", resp.GetSessionId(), "path", path)
	return sess, nil
}

// sessionControlClient runs the client end of realtime enforcement for a direct
// session. It trusts the mTLS channel to the controller (no per-message signature
// check needed client-side); it closes the session on an explicit revoke, on a
// full-cut delta, or when the controller's lease stops refreshing before expiry.
func sessionControlClient(ctx context.Context, api genezav1.UserAPIClient, sess *Session) {
	stream, err := api.SessionControl(ctx)
	if err != nil {
		slog.Debug("session control unavailable", "session", sess.ID, "err", err)
		return
	}
	if err := stream.Send(&genezav1.ClientControl{SessionId: sess.ID}); err != nil {
		return
	}
	go func() { // keepalive so the controller sees a live client end
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := stream.Send(&genezav1.ClientControl{SessionId: sess.ID}); err != nil {
					return
				}
			}
		}
	}()

	type rxMsg struct {
		ctl *genezav1.ControllerEnforcement
		err error
	}
	rxc := make(chan rxMsg, 8)
	go func() {
		for {
			ctl, err := stream.Recv()
			rxc <- rxMsg{ctl, err}
			if err != nil {
				return
			}
		}
	}()

	// Client-side fail-closed lease timer, mirroring the agent: if a fresh lease
	// does not arrive before the current one expires, tear the client end.
	lease := time.NewTimer(defaults.SessionLeaseTTL) // initial grace
	defer lease.Stop()
	resetLease := func(d time.Duration) {
		if !lease.Stop() {
			select {
			case <-lease.C:
			default:
			}
		}
		if d < 0 {
			d = 0
		}
		lease.Reset(d)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-lease.C:
			slog.Info("session lease starved (no controller lease); closing client end", "session", sess.ID)
			_ = sess.Close()
			return
		case m := <-rxc:
			if m.err != nil {
				return // stream closed (session ended / controller gone)
			}
			switch x := m.ctl.GetMsg().(type) {
			case *genezav1.ControllerEnforcement_SessionRevoke:
				slog.Info("session revoked by controller; closing client end", "session", sess.ID, "reason", x.SessionRevoke.GetReason())
				_ = sess.Close()
				return
			case *genezav1.ControllerEnforcement_SessionLease:
				exp := x.SessionLease.GetLeaseExpiryUnixMs()
				if exp > 0 && !time.Now().Before(time.UnixMilli(exp)) {
					_ = sess.Close()
					return
				}
				resetLease(time.Until(time.UnixMilli(exp)))
			case *genezav1.ControllerEnforcement_SessionPolicyDelta:
				if c := x.SessionPolicyDelta.GetCaps(); c != nil && !c.GetAllow() {
					slog.Info("session cut by controller delta; closing client end", "session", sess.ID)
					_ = sess.Close()
					return
				}
				if exp := x.SessionPolicyDelta.GetLeaseExpiryUnixMs(); exp > 0 {
					resetLease(time.Until(time.UnixMilli(exp)))
				}
			}
		}
	}
}

var errSessionP2PUnavailable = errors.New("session p2p not offered")
