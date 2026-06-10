package agentd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
	"osie.cloud/geneza/internal/tunnel"
	"osie.cloud/geneza/internal/types"
	"osie.cloud/geneza/internal/wire"
)

const (
	relayDialTimeout  = 10 * time.Second
	relayRespTimeout  = 10 * time.Second
	handshakeDeadline = 30 * time.Second
)

// EvaluateOffer is the agent-side authorization gate for a session offer:
// signature by a currently trusted grant key, grant validity (node binding,
// noise key binding, expiry, action shape) and local agent policy. Pure so
// the rejection paths are unit-testable.
func EvaluateOffer(signedGrant []byte, trusted map[string]ed25519.PublicKey, nodeID string, agentNoisePub []byte, pol types.AgentPolicy, now time.Time) (*types.SessionGrant, error) {
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
	// A long-lived detached shell on a node whose policy forbids it is
	// exactly what agent-side enforcement exists to stop, even if the
	// gateway (mistakenly or maliciously) granted it.
	if grant.AllowDetach && pol.ForbidDetach {
		return nil, errors.New("detachable sessions are forbidden by agent policy")
	}
	return grant, nil
}

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
	grant, err := EvaluateOffer(offer.SignedGrant, w.trustedKeys(), w.st.NodeID, w.st.Noise.Public, w.agentPolicy(), time.Now())

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
	go w.runSession(ctx, grant)
}

// tunnelAccept is the responder's handshake-acceptance payload.
type tunnelAccept struct {
	OK   bool   `json:"ok"`
	Node string `json:"node"`
}

// runSession establishes the data path for an accepted grant: relay
// rendezvous over TLS, Noise IK as responder (authorizing the initiator's
// signed grant before any application data), then an SSH server scoped to
// the grant's action.
func (w *Worker) runSession(ctx context.Context, grant *types.SessionGrant) {
	log := w.log.With("session", grant.ID, "action", grant.Action, "user", grant.User)

	raw, err := tls.DialWithDialer(
		&net.Dialer{Timeout: relayDialTimeout}, "tcp", grant.RelayAddr,
		&tls.Config{RootCAs: w.rootPool(), MinVersion: tls.VersionTLS12})
	if err != nil {
		log.Error("relay dial failed", "relay", grant.RelayAddr, "err", err)
		w.emitEvent(&genezav1.SessionEvent{SessionId: grant.ID, Event: "ended", Detail: "relay dial: " + err.Error()})
		return
	}
	defer raw.Close()

	if err := wire.WriteJSON(raw, wire.RelayHello{V: 1, Token: grant.RelayToken, Role: wire.RoleResponder}); err != nil {
		log.Error("relay hello failed", "err", err)
		return
	}
	_ = raw.SetDeadline(time.Now().Add(relayRespTimeout))
	var rresp wire.RelayResp
	if err := wire.ReadJSON(raw, &rresp); err != nil {
		log.Error("relay rendezvous failed", "err", err)
		return
	}
	if !rresp.OK {
		log.Error("relay refused rendezvous", "err", rresp.Error)
		return
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
		log.Warn("tunnel handshake rejected", "err", err)
		w.emitEvent(&genezav1.SessionEvent{SessionId: grant.ID, Event: "rejected", Detail: "tunnel: " + err.Error()})
		return
	}
	_ = raw.SetDeadline(time.Time{})

	w.emitEvent(&genezav1.SessionEvent{SessionId: grant.ID, Event: "established"})
	log.Info("tunnel established")

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { // worker shutdown tears down the tunnel
		<-sctx.Done()
		_ = tconn.Close()
	}()
	if grant.MaxSessionTTL > 0 {
		t := time.AfterFunc(grant.MaxSessionTTL, func() {
			log.Info("max session TTL reached, closing tunnel", "ttl", grant.MaxSessionTTL)
			_ = tconn.Close()
		})
		defer t.Stop()
	}

	w.serveSSH(sctx, tconn, grant, log)
}
