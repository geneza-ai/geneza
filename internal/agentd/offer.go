package agentd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"geneza.io/internal/icewire"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/sessionconn"
	"geneza.io/internal/tunnel"
	"geneza.io/internal/types"
	"geneza.io/internal/wire"
)

const (
	relayDialTimeout  = 10 * time.Second
	relayRespTimeout  = 10 * time.Second
	handshakeDeadline = 30 * time.Second
)

// EvaluateOffer is the agent-side authorization gate for a session offer:
// signature by a currently trusted grant key, grant validity (node binding,
// noise key binding, expiry, action shape), the SCOPED-GRANT FLOOR (the grant
// must be for this agent's own enrolled workspace, and the signing key must be
// scoped to cover it), and local agent policy. Pure so the rejection paths are
// unit-testable. keyScopes maps key id -> allowed workspaces (nil/empty entry =
// all-workspaces); selfWorkspace is the agent's own enrolled workspace ("" =
// skip the workspace check, e.g. legacy/test).
func EvaluateOffer(signedGrant []byte, trusted map[string]ed25519.PublicKey, keyScopes map[string][]string, selfWorkspace, nodeID string, agentNoisePub []byte, pol types.AgentPolicy, now time.Time) (*types.SessionGrant, error) {
	env, err := types.DecodeSigned(signedGrant)
	if err != nil {
		return nil, err
	}
	grant, err := types.VerifyGrant(trusted, env)
	if err != nil {
		return nil, err
	}
	if err := grant.Validate(nodeID, agentNoisePub, now); err != nil {
		return nil, err
	}
	// Scoped-grant floor: a compromised/failed-over controller must not be able to
	// plant a grant for a workspace this node is not enrolled in, nor sign for a
	// workspace outside its key's declared scope.
	if selfWorkspace != "" && grant.WorkspaceID != selfWorkspace {
		return nil, fmt.Errorf("grant is for workspace %q, this agent is enrolled in %q", grant.WorkspaceID, selfWorkspace)
	}
	if !types.WorkspaceInScope(keyScopes[env.KeyID], grant.WorkspaceID) {
		return nil, fmt.Errorf("grant signing key %q is not scoped for workspace %q", env.KeyID, grant.WorkspaceID)
	}
	// A long-lived detached shell on a node whose policy forbids it is
	// exactly what agent-side enforcement exists to stop, even if the
	// controller (mistakenly or maliciously) granted it.
	if grant.AllowDetach && pol.ForbidDetach {
		return nil, errors.New("detachable sessions are forbidden by agent policy")
	}
	// Independent ceiling on session lifetime: never honor an unbounded or
	// absurdly long MaxSessionTTL from the controller. A compromised controller must
	// not be able to plant an effectively permanent session on a node — the
	// agent always arms a close timer at most maxAgentSessionTTL out.
	if grant.MaxSessionTTL <= 0 || grant.MaxSessionTTL > maxAgentSessionTTL {
		grant.MaxSessionTTL = maxAgentSessionTTL
	}
	return grant, nil
}

// maxAgentSessionTTL is the hard local ceiling the agent imposes on any single
// session, independent of the controller-asserted MaxSessionTTL.
const maxAgentSessionTTL = 24 * time.Hour

// ExecCommandAllowed enforces exec scope: the command the client requests
// over SSH must byte-equal the command in the signed grant.
func ExecCommandAllowed(grantCommand, requested string) bool {
	return grantCommand != "" && grantCommand == requested
}

// ForwardTargetAllowed enforces forward scope: the requested destination
// must equal the grant's host:port target exactly.
func ForwardTargetAllowed(grantTarget, destAddr string, destPort uint32) bool {
	if grantTarget == "" {
		return false
	}
	return net.JoinHostPort(destAddr, strconv.FormatUint(uint64(destPort), 10)) == grantTarget
}

// handleSessionOffer runs in the control-stream recv loop: verify, ack, and
// (if accepted) establish the data path in a goroutine.
func (w *Worker) handleSessionOffer(ctx context.Context, offer *genezav1.SessionOffer, send func(*genezav1.AgentMsg) error) {
	// Fail CLOSED if the agent cannot determine its own enrolled workspace
	// (a corrupt node cert): refuse the offer rather than skip the scoped-grant
	// floor's workspace check. A well-formed node cert always yields at least
	// "default", so this never fires in practice — it removes the fail-open shape.
	var grant *types.SessionGrant
	var err error
	selfWS := w.st.Workspace()
	if selfWS == "" {
		err = errors.New("agent cannot determine its enrolled workspace (corrupt node cert?); refusing offer")
	} else {
		grant, err = EvaluateOffer(offer.SignedGrant, w.trustedKeys(), w.keyScopes(), selfWS, w.st.NodeID, w.st.Noise.Public, w.agentPolicy(), time.Now())
	}

	ack := &genezav1.SessionOfferAck{Accepted: err == nil}
	if grant != nil {
		ack.SessionId = grant.ID
	}
	if err != nil {
		ack.Reason = err.Error()
		w.log.Warn("session offer rejected", "session", ack.SessionId, "err", err)
		w.emitEvent(&genezav1.SessionEvent{SessionId: ack.SessionId, Event: "rejected", Detail: err.Error()})
	} else {
		w.log.Info("session offer accepted",
			"session", grant.ID, "user", grant.User, "action", grant.Action, "relay", grant.RelayAddr)
	}
	if serr := send(&genezav1.AgentMsg{Msg: &genezav1.AgentMsg_OfferAck{OfferAck: ack}}); serr != nil {
		w.log.Warn("send offer ack", "err", serr)
		return
	}
	if err != nil {
		return
	}
	// Session p2p (opt-in): if the offer carried TURN coordinates, the session DATA
	// rides the ICE p2p path (direct or TURN-relayed) — gated HERE, after
	// EvaluateOffer accepted, so no ICE socket is gathered without a signed,
	// in-window grant. Register the signaler SYNCHRONOUSLY (before the
	// goroutine) so the buffered channel absorbs the client's earliest creds.
	turn := offer.GetTurn()
	var sig *sessionSignaler
	if turn != nil {
		sig = w.registerSessionICE(grant.ID)
	}
	go w.runSession(ctx, grant, turn, sig)
}

// tunnelAccept is the responder's handshake-acceptance payload.
type tunnelAccept struct {
	OK   bool   `json:"ok"`
	Node string `json:"node"`
}

// establishTunnel builds the data path for a grant: the transport (ICE p2p when
// session creds are present, else the relay-TCP floor) then the Noise IK responder
// handshake (which gates the handshake itself — an unauthorized initiator never
// sees a byte). It returns the raw transport (to close), the Noise conn, and the
// path class. Used at initial dial AND on every relay re-home (a relay change forces
// a fresh Noise handshake, so the whole transport is rebuilt each generation).
func (w *Worker) establishTunnel(ctx context.Context, grant *types.SessionGrant, turn *genezav1.TurnCreds, sig *sessionSignaler, log *slog.Logger) (net.Conn, net.Conn, string, error) {
	raw, path, err := w.sessionTransport(ctx, grant, turn, sig, log)
	if err != nil {
		return nil, nil, "", err
	}
	// Noise IK responder: the authorize callback gates the handshake itself —
	// an unauthorized initiator never sees a byte of application data.
	_ = raw.SetDeadline(time.Now().Add(handshakeDeadline))
	tconn, err := tunnel.Server(raw, w.st.Noise, grant.ID, func(remoteStatic, payload []byte) ([]byte, error) {
		env, err := types.DecodeSigned(payload)
		if err != nil {
			return nil, err
		}
		g2, err := types.VerifyGrant(w.trustedKeys(), env)
		if err != nil {
			return nil, err
		}
		// The handshake payload must be the very grant this rendezvous token
		// was offered for, presented by the client key bound into it.
		if g2.ID != grant.ID {
			return nil, fmt.Errorf("grant id mismatch: %q", g2.ID)
		}
		if !bytes.Equal(remoteStatic, grant.ClientNoisePub) {
			return nil, errors.New("initiator noise key does not match grant client_noise_pub")
		}
		return json.Marshal(tunnelAccept{OK: true, Node: w.st.NodeID})
	})
	if err != nil {
		_ = raw.Close()
		return nil, nil, "", fmt.Errorf("tunnel handshake: %w", err)
	}
	_ = raw.SetDeadline(time.Time{})
	return raw, tconn, path, nil
}

// runSession establishes the data path for an accepted grant and serves it, then
// drives the IN-SESSION relay re-home loop: when the relay a live session is using
// drains or dies, the session migrates to a surviving relay (a fresh controller-issued
// grant under the SAME session id) instead of being torn down. A detachable shell
// re-attaches its persisted host PTY seamlessly; other actions reconnect-fast.
func (w *Worker) runSession(ctx context.Context, grant *types.SessionGrant, turn *genezav1.TurnCreds, sig *sessionSignaler) {
	log := w.log.With("session", grant.ID, "action", grant.Action, "user", grant.User)
	if sig != nil {
		defer w.unregisterSessionICE(grant.ID)
	}

	raw, tconn, path, err := w.establishTunnel(ctx, grant, turn, sig, log)
	if err != nil {
		log.Error("session transport failed", "err", err)
		w.emitEvent(&genezav1.SessionEvent{SessionId: grant.ID, Event: "ended", Detail: "transport: " + err.Error()})
		return
	}

	w.emitEvent(&genezav1.SessionEvent{SessionId: grant.ID, Event: "established", PathClass: path})
	log.Info("tunnel established", "path", path)

	// The live-session enforcement state (lease, continuous-authz, revoke) is keyed
	// by session id and CONTINUES across a re-home: register it ONCE here, around the
	// whole re-home loop, not per transport generation. sctx cancels on worker
	// shutdown / explicit revoke and tears the current transport.
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	w.registerLive(grant.ID, cancel, grant, path)
	defer w.unregisterLive(grant.ID)
	if grant.MaxSessionTTL > 0 {
		t := time.AfterFunc(grant.MaxSessionTTL, func() {
			log.Info("max session TTL reached, closing tunnel", "ttl", grant.MaxSessionTTL)
			cancel()
		})
		defer t.Stop()
	}

	w.serveWithRehome(sctx, grant, sig, raw, tconn, log)
}

// sessionTransport returns the reliable transport conn for a session: the ICE
// p2p path (direct host/srflx hole-punch, or the TURN-UDP relay floor under hard
// NAT) when the offer carried session TURN creds, else the relay-TCP rendezvous
// floor. On ICE failure it falls back to the relay floor so a session still
// connects. The returned conn feeds tunnel.Server unchanged (Noise stays the gate).
func (w *Worker) sessionTransport(ctx context.Context, grant *types.SessionGrant, turn *genezav1.TurnCreds, sig *sessionSignaler, log *slog.Logger) (net.Conn, string, error) {
	if turn != nil && sig != nil {
		conn, path, err := sessionconn.Accept(ctx, sessionconn.Config{
			Controlling: turn.GetControlling(), // agent accepts
			TurnURL:     turn.GetTurnUrl(),     // scalar fallback
			TurnUser:    turn.GetUsername(),
			TurnPass:    turn.GetPassword(),
			// Prefer the candidate list from the SIGNED, agent-verified grant (a
			// tampered list would have failed grant verification), not the offer proto.
			Candidates: relayCredsFromGrant(grant.RelayCandidates),
			Gather:     12 * time.Second,
		}, sig)
		if err == nil {
			return conn, path, nil
		}
		log.Warn("session p2p failed; falling back to relay floor", "err", err)
	}
	raw, err := w.dialRelay(grant)
	if err != nil {
		return nil, "", err
	}
	return raw, "relay-tcp", nil
}

// pinRelayCert returns a TLS verify callback that, after the standard chain
// verification, requires the relay's leaf public key to equal one in the signed
// relay map — a relay outside the fleet is refused even with a valid relay cert.
func pinRelayCert(pins [][]byte) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("relay presented no certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		spki, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if err != nil {
			return err
		}
		for _, pin := range pins {
			if bytes.Equal(pin, spki) {
				return nil
			}
		}
		return fmt.Errorf("relay leaf key is not in the signed relay map")
	}
}

// relayCredsFromGrant converts the verified grant's relay candidate list to the
// ICE credential set. Empty leaves the dial on the scalar relay (single-node).
func relayCredsFromGrant(cands []types.RelayCandidate) []icewire.RelayCred {
	out := make([]icewire.RelayCred, 0, len(cands))
	for _, c := range cands {
		out = append(out, icewire.RelayCred{
			TurnURL: c.TurnURL, TurnUser: c.TurnUser, TurnPass: c.TurnPass, Realm: c.Realm,
		})
	}
	return out
}

// dialRelay dials the relay-TCP rendezvous floor and completes the responder hello.
// The floor is the grant's ordered set of HEALTHY relay picks (RelayFloor, first
// entry == RelayAddr); the agent tries them in turn so a relay that refuses
// (draining) does not strand the session. The client iterates the same ordered set
// with the same one-time token, so both converge on whichever relay answers.
func (w *Worker) dialRelay(grant *types.SessionGrant) (net.Conn, error) {
	tlsCfg := &tls.Config{RootCAs: w.rootPool(), MinVersion: tls.VersionTLS12}
	// Beyond chain-to-root, pin the relay's leaf to a key in the signed relay map,
	// so a relay that is not in the fleet (a rogue with an otherwise-valid relay
	// cert) is refused. Falls back to chain-to-root only when the map carries no
	// relay keys (an older config), preserving the prior behavior.
	if pins := w.relayCertPubs(); len(pins) > 0 {
		tlsCfg.VerifyPeerCertificate = pinRelayCert(pins)
	}
	floor := grant.RelayFloor
	if len(floor) == 0 {
		floor = []string{grant.RelayAddr}
	}
	var lastErr error
	for _, addr := range floor {
		raw, err := w.dialRelayOnce(addr, grant.RelayToken, tlsCfg)
		if err != nil {
			lastErr = err
			continue
		}
		return raw, nil
	}
	return nil, lastErr
}

func (w *Worker) dialRelayOnce(addr, token string, tlsCfg *tls.Config) (net.Conn, error) {
	raw, err := tls.DialWithDialer(&net.Dialer{Timeout: relayDialTimeout}, "tcp", addr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("relay dial %s: %w", addr, err)
	}
	if err := wire.WriteJSON(raw, wire.RelayHello{V: 1, Token: token, Role: wire.RoleResponder}); err != nil {
		raw.Close()
		return nil, fmt.Errorf("relay hello: %w", err)
	}
	_ = raw.SetDeadline(time.Now().Add(relayRespTimeout))
	var rresp wire.RelayResp
	if err := wire.ReadJSON(raw, &rresp); err != nil {
		raw.Close()
		return nil, fmt.Errorf("relay rendezvous: %w", err)
	}
	if !rresp.OK {
		raw.Close()
		return nil, fmt.Errorf("relay refused: %s", rresp.Error)
	}
	return raw, nil
}
