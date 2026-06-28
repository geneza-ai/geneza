package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/ssh"

	"geneza.io/internal/tunnel"
	"geneza.io/internal/types"
	"geneza.io/internal/wire"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// SessionParams mirrors the CreateSessionRequest fields the CLI sets; the
// noise key and client_path are filled in by Establish.
type SessionParams struct {
	Node            string
	Action          string // types.ActionShell|Exec|SFTP|Forward|Attach|connect|vpn
	Command         string
	WantPTY         bool
	WantDetachable  bool
	AttachSessionID string
	ForwardTarget   string
	Service         string // action=connect|vpn: named service on the node
	// HomeRegion is the client's declared region; the controller uses it to pick the
	// client's nearest relay candidates for a cross-region session (advisory — an
	// unknown region falls back to the default region's relays). Empty in a
	// single-region deployment.
	HomeRegion string
}

// Session is one established end-to-end tunnel. For shell/exec/sftp/forward the
// SSH channel layer rides on top; for vpn there is no SSH layer and Tunnel is
// the raw Noise conn carrying IP packets. Close tears down the whole stack.
type Session struct {
	ID  string // controller session id
	SSH *ssh.Client
	// Tunnel is the raw Noise tunnel conn, set only for vpn sessions (SSH is
	// nil then). The VPN pump reads/writes IP-packet frames directly on it.
	Tunnel net.Conn
	// HostSessionID is reported by the agent in its acceptance payload when
	// it created/attached a persistent host session (may be empty).
	HostSessionID string
	// Resolved from the signed grant (the controller decides these for service
	// connect / vpn; the client reads them to drive the local end).
	Action        string
	ForwardTarget string
	Routes        []string
	OverlayIP     string

	// onClose tears down a controller connection the session owns — set only when the
	// client followed a cross-controller redirect, so the owner's control connection
	// (carrying the presence heartbeat and session signaling) lives exactly as long
	// as the session. nil on the common single-hop path.
	onClose func() error
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	var err error
	if s.SSH != nil {
		err = s.SSH.Close()
	} else if s.Tunnel != nil {
		err = s.Tunnel.Close()
	}
	if s.onClose != nil {
		if cerr := s.onClose(); err == nil {
			err = cerr
		}
	}
	return err
}

// acceptance is the agent's Noise-handshake response payload.
type acceptance struct {
	OK            bool   `json:"ok"`
	Error         string `json:"error,omitempty"`
	HostSessionID string `json:"host_session_id,omitempty"`
}

const (
	relayRendezvousTimeout = 15 * time.Second
	tunnelHandshakeTimeout = 30 * time.Second
)

// Establish brokers a session at the controller and builds the native E2E data
// path: ephemeral Noise key -> CreateSession -> TLS to the relay (verified
// against the pinned geneza CA) -> rendezvous -> Noise IK handshake carrying
// the signed grant -> SSH channel layer.
func Establish(ctx context.Context, api genezav1.UserAPIClient, pool *x509.CertPool, cert *tls.Certificate, p SessionParams) (*Session, error) {
	// One ephemeral tunnel keypair per session: the controller binds it into the
	// signed grant, so only this process can complete the handshake, and
	// nothing long-lived exists to steal.
	key, err := tunnel.GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("generate tunnel key: %w", err)
	}

	// A declared home region (flag or GENEZA_HOME_REGION) lets the controller pick
	// this client's nearest relay candidates for a cross-region session; unset in
	// a single-region deployment, where it canonicalizes to the default region.
	if p.HomeRegion == "" {
		p.HomeRegion = os.Getenv("GENEZA_HOME_REGION")
	}

	req := &genezav1.CreateSessionRequest{
		Node:            p.Node,
		Action:          p.Action,
		Command:         p.Command,
		WantPty:         p.WantPTY,
		WantDetachable:  p.WantDetachable,
		AttachSessionId: p.AttachSessionID,
		ForwardTarget:   p.ForwardTarget,
		Service:         p.Service,
		HomeRegion:      p.HomeRegion,
		ClientNoisePub:  key.Public,
		ClientPath:      types.PathNative,
	}
	resp, err := api.CreateSession(ctx, req)
	if err != nil {
		return nil, Humanize(err)
	}

	// Follow at most one cross-controller redirect: the target agent's control stream
	// is held by another controller, so re-dial that controller's signed endpoint and
	// re-broker there. The owner connection then carries the session's presence
	// heartbeat and ICE signaling, so it must outlive Establish — the resulting
	// Session owns it. A second redirect is a control-plane bug, not a retry.
	var ownerClose func() error
	if red := resp.GetControllerRedirect(); red != nil {
		ownerAPI, closeConn, derr := dialRedirect(red, pool, cert)
		if derr != nil {
			return nil, derr
		}
		resp, err = ownerAPI.CreateSession(ctx, req)
		if err != nil {
			_ = closeConn()
			return nil, Humanize(err)
		}
		if resp.GetControllerRedirect() != nil {
			_ = closeConn()
			return nil, fmt.Errorf("controller %q redirected again; refusing to chase a redirect loop", red.GetControllerId())
		}
		api = ownerAPI
		ownerClose = closeConn
	}

	// Build the data path through DialSession — the SINGLE transport entrypoint every
	// client uses — so the native CLI, the in-process web-shell proxy, and the desktop
	// can never diverge on how a session connects. A native client can hole-punch, so
	// it passes its signaling api; DialSession uses ICE when the controller offered it,
	// else the relay-TCP floor.
	sess, err := DialSession(ctx, api, pool, resp, key, "")
	if err != nil {
		if ownerClose != nil {
			_ = ownerClose()
		}
		return nil, err
	}
	// Continuous presence: if the controller requires it for this
	// session, beat the factor in the background — stopping (process killed / no
	// hardware) lets presence go stale and the controller drops the session.
	startPresenceHeartbeat(ctx, api, resp)
	sess.onClose = ownerClose // nil on the common single-hop path
	return sess, nil
}

// DialSession builds the E2E data path from a brokered CreateSessionResponse — THE
// single place a client selects its transport, so every caller (the native CLI via
// Establish, the in-process web-shell proxy, the desktop) takes the same path and a
// session's transport can never silently diverge from what the controller offered. It
// uses the ICE p2p path (direct hole-punch, or the TURN-UDP relay floor) when the
// controller offered it (resp.Turn != nil) AND this client can trickle ICE candidates
// (api != nil — an out-of-process client with a SessionSignal stream); otherwise, or
// on any ICE failure, it falls back to the relay-TCP rendezvous floor so a session
// always connects. relayDialAddr overrides the relay TCP target so the in-process
// web proxy can dial the relay LOCALLY (e.g. 127.0.0.1:7403) and avoid a NAT hairpin,
// while the grant's relay host stays the TLS ServerName; "" uses the advertised host.
// The data path is identical across callers: TLS to the relay (pinned geneza CA) ->
// rendezvous -> Noise IK carrying the signed grant -> SSH (or, for vpn, the bare
// tunnel conn). The Noise gate + signed grant stay the security boundary on every path.
func DialSession(ctx context.Context, api genezav1.UserAPIClient, pool *x509.CertPool, resp *genezav1.CreateSessionResponse, key noise.DHKey, relayDialAddr string) (*Session, error) {
	if resp.GetTurn() != nil && api != nil {
		if s, err := dialSessionICE(ctx, api, resp, key); err == nil {
			return s, nil
		} else {
			slog.Debug("session p2p unavailable; using relay floor", "err", err)
		}
	}
	raw, err := dialRelayClient(ctx, pool, resp, relayDialAddr)
	if err != nil {
		return nil, err
	}
	return dialGrantConn(resp, key, raw)
}

// dialRelayClient dials the relay-TCP rendezvous floor as the initiator and
// returns the raw stream once both endpoints have met. Closes the conn on any
// failure. Used by the in-process web-shell proxy and as the fallback floor for
// native sessions; native sessions prefer the ICE p2p transport (see Establish).
//
// The floor is the controller's ordered set of HEALTHY relay picks (relay_floor, first
// entry == relay_addr): each is tried in turn so a relay that refuses (draining)
// does not strand the session. The single one-time relay_token pairs on whichever
// answers. dialAddr, when set (the in-process web proxy dialing locally to avoid a
// NAT hairpin), overrides the dial target for the first floor entry while its host
// stays the TLS ServerName.
func dialRelayClient(ctx context.Context, pool *x509.CertPool, resp *genezav1.CreateSessionResponse, dialAddr string) (net.Conn, error) {
	floor := relayFloor(resp)
	if len(floor) == 0 || resp.GetRelayToken() == "" {
		return nil, errors.New("controller returned no relay floor for this session")
	}
	var lastErr error
	for i, addr := range floor {
		target := addr
		if i == 0 && dialAddr != "" {
			target = dialAddr // dial locally; ServerName stays the public relay host
		}
		raw, err := dialRelayFloorOnce(ctx, pool, addr, target, resp.GetRelayToken())
		if err != nil {
			lastErr = err
			continue
		}
		return raw, nil
	}
	return nil, lastErr
}

// relayFloor is the ordered relay-TCP rendezvous set to dial: the explicit
// relay_floor list when present, else the scalar relay_addr alone.
func relayFloor(resp *genezav1.CreateSessionResponse) []string {
	if f := resp.GetRelayFloor(); len(f) > 0 {
		return f
	}
	if a := resp.GetRelayAddr(); a != "" {
		return []string{a}
	}
	return nil
}

// dialRelayFloorOnce dials one relay floor address (host names its cert SAN /
// ServerName, target is where the TCP connect goes) and completes the initiator
// rendezvous. Closes the conn on any failure.
func dialRelayFloorOnce(ctx context.Context, pool *x509.CertPool, host, target, token string) (net.Conn, error) {
	sni, _, err := net.SplitHostPort(host)
	if err != nil {
		return nil, fmt.Errorf("relay address %q: %w", host, err)
	}
	dialer := &tls.Dialer{Config: &tls.Config{
		RootCAs:    pool, // relay certs are issued by the geneza CA
		ServerName: sni,  // always the grant's relay host (matches the cert SAN)
		MinVersion: tls.VersionTLS12,
	}}
	raw, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("relay connect %s: %w", target, err)
	}
	if err := wire.WriteJSON(raw, wire.RelayHello{V: 1, Token: token, Role: wire.RoleInitiator}); err != nil {
		raw.Close()
		return nil, fmt.Errorf("relay hello: %w", err)
	}
	// The relay answers once both endpoints arrive; bound the wait if the agent
	// never shows (offline, grant rejected pre-dial).
	if err := raw.SetReadDeadline(time.Now().Add(relayRendezvousTimeout)); err != nil {
		raw.Close()
		return nil, err
	}
	var rresp wire.RelayResp
	if err := wire.ReadJSON(raw, &rresp); err != nil {
		raw.Close()
		if isTimeout(err) {
			return nil, errors.New("relay rendezvous timed out (node did not connect — is it online?)")
		}
		return nil, fmt.Errorf("relay rendezvous: %w", err)
	}
	if !rresp.OK {
		raw.Close()
		return nil, fmt.Errorf("relay refused rendezvous: %s", rresp.Error)
	}
	return raw, nil
}

// dialGrantConn completes a session over an already-established transport conn —
// the ICE p2p reliable stream OR the relay-TCP rendezvous: the Noise IK handshake
// (which the agent independently verifies against the signed grant), then the SSH
// channel layer (or the bare tunnel conn for vpn). Owns raw — closes it on any
// failure. The transport below is interchangeable; the Noise gate is the security
// boundary either way.
func dialGrantConn(resp *genezav1.CreateSessionResponse, key noise.DHKey, raw net.Conn) (*Session, error) {
	if len(resp.GetAgentNoisePub()) != 32 {
		raw.Close()
		return nil, errors.New("controller returned an incomplete session grant")
	}
	// Decode the (controller-signed) grant payload for its resolved scope (forward
	// target, routes, overlay IP); the agent verifies it, we only read it.
	resolved := &types.SessionGrant{}
	if env, derr := types.DecodeSigned(resp.GetSignedGrant()); derr == nil {
		_ = json.Unmarshal(env.Payload, resolved)
	}
	ok := false
	defer func() {
		if !ok {
			raw.Close()
		}
	}()

	// Noise IK both authenticates the agent (its static key is pinned from
	// CreateSessionResponse) and carries the signed grant to it in msg1.
	if err := raw.SetReadDeadline(time.Now().Add(tunnelHandshakeTimeout)); err != nil {
		return nil, err
	}
	tconn, acceptPayload, err := tunnel.Client(raw, key, resp.GetAgentNoisePub(), resp.GetSessionId(), resp.GetSignedGrant())
	if err != nil {
		if isTimeout(err) {
			return nil, errors.New("tunnel handshake timed out (agent did not answer)")
		}
		return nil, fmt.Errorf("tunnel handshake: %w", err)
	}
	if err := raw.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	var acc acceptance
	if err := json.Unmarshal(acceptPayload, &acc); err != nil {
		return nil, fmt.Errorf("agent acceptance: %w", err)
	}
	if !acc.OK {
		if acc.Error == "" {
			acc.Error = "no reason given"
		}
		return nil, fmt.Errorf("agent rejected grant: %s", acc.Error)
	}

	// VPN sessions carry raw IP packets, not an SSH transport: hand back the
	// bare tunnel conn for the packet pump and skip the SSH channel layer.
	if resolved.Action == types.ActionVPN {
		ok = true
		return &Session{
			ID:        resp.GetSessionId(),
			Tunnel:    tconn,
			Action:    resolved.Action,
			Routes:    resolved.Routes,
			OverlayIP: resolved.OverlayIP,
		}, nil
	}

	// SECURITY NOTE: the SSH layer here is used ONLY for its channel/session
	// semantics (pty/exec/sftp/direct-tcpip multiplexing). Authentication is
	// complete before the first SSH byte: the Noise IK handshake mutually
	// authenticated both static keys, and the agent independently verified
	// the controller-signed grant binding this client key to this session.
	// InsecureIgnoreHostKey is therefore correct — there is no host key to
	// verify, and adding one would be security theater.
	sshConn, chans, reqs, err := ssh.NewClientConn(tconn, "", &ssh.ClientConfig{
		User:            "geneza",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         tunnelHandshakeTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("session layer handshake: %w", err)
	}
	ok = true
	sshClient := ssh.NewClient(sshConn, chans, reqs)
	// Over a UDP p2p path there is no instant TCP RST when the peer dies or
	// actively closes (a revoke), so an idle client could hang waiting on a dead
	// conn. SSH-level keepalive is the standard detector: ping the peer and drop
	// the session when pings stop being answered. Harmless on the relay path too.
	go sshKeepalive(sshClient)
	return &Session{
		ID:            resp.GetSessionId(),
		SSH:           sshClient,
		HostSessionID: acc.HostSessionID,
		Action:        resolved.Action,
		ForwardTarget: resolved.ForwardTarget,
		Routes:        resolved.Routes,
		OverlayIP:     resolved.OverlayIP,
	}, nil
}

// sshKeepalive pings the peer over the SSH control channel and closes the client
// when the peer stops answering — so a dead or actively-closed (revoked) p2p
// session is torn down promptly instead of hanging on a transport that gives no
// instant FIN. It self-terminates when the session is closed normally (the
// request then errors). The agent's SSH server answers the unknown global
// request with a failure reply, which still proves liveness.
const (
	sshKeepaliveInterval = 2 * time.Second
	sshKeepaliveMaxFail  = 2 // ~interval*N before declaring the peer dead
	sshKeepaliveTimeout  = 3 * time.Second
)

func sshKeepalive(c *ssh.Client) {
	t := time.NewTicker(sshKeepaliveInterval)
	defer t.Stop()
	fails := 0
	for range t.C {
		// Bound the request: over a dead UDP/SCTP conduit the agent's close may be
		// lost (no instant FIN), and SendRequest would otherwise block forever
		// waiting for a reply. A timeout counts as a failure so a silently-dead path
		// is detected in ~interval*N, not never.
		done := make(chan error, 1)
		go func() { _, _, err := c.SendRequest("keepalive@geneza", true, nil); done <- err }()
		var err error
		select {
		case err = <-done:
		case <-time.After(sshKeepaliveTimeout):
			err = errors.New("keepalive timed out")
		}
		if err != nil {
			if fails++; fails >= sshKeepaliveMaxFail {
				_ = c.Close() // unblocks any parked SendRequest goroutine
				return
			}
			continue
		}
		fails = 0
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, os.ErrDeadlineExceeded) ||
		strings.Contains(err.Error(), "i/o timeout") // wrapped by wire/tunnel
}
