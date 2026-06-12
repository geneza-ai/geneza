package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/ssh"

	"osie.cloud/geneza/internal/tunnel"
	"osie.cloud/geneza/internal/types"
	"osie.cloud/geneza/internal/wire"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
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
}

// Session is one established end-to-end tunnel. For shell/exec/sftp/forward the
// SSH channel layer rides on top; for vpn there is no SSH layer and Tunnel is
// the raw Noise conn carrying IP packets. Close tears down the whole stack.
type Session struct {
	ID  string // gateway session id
	SSH *ssh.Client
	// Tunnel is the raw Noise tunnel conn, set only for vpn sessions (SSH is
	// nil then). The VPN pump reads/writes IP-packet frames directly on it.
	Tunnel net.Conn
	// HostSessionID is reported by the agent in its acceptance payload when
	// it created/attached a persistent host session (may be empty).
	HostSessionID string
	// Resolved from the signed grant (the gateway decides these for service
	// connect / vpn; the client reads them to drive the local end).
	Action        string
	ForwardTarget string
	Routes        []string
	OverlayIP     string
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	if s.SSH != nil {
		return s.SSH.Close()
	}
	if s.Tunnel != nil {
		return s.Tunnel.Close()
	}
	return nil
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

// Establish brokers a session at the gateway and builds the native E2E data
// path: ephemeral Noise key -> CreateSession -> TLS to the relay (verified
// against the pinned geneza CA) -> rendezvous -> Noise IK handshake carrying
// the signed grant -> SSH channel layer.
func Establish(ctx context.Context, api genezav1.UserAPIClient, pool *x509.CertPool, p SessionParams) (*Session, error) {
	// One ephemeral tunnel keypair per session: the gateway binds it into the
	// signed grant, so only this process can complete the handshake, and
	// nothing long-lived exists to steal.
	key, err := tunnel.GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("generate tunnel key: %w", err)
	}

	resp, err := api.CreateSession(ctx, &genezav1.CreateSessionRequest{
		Node:            p.Node,
		Action:          p.Action,
		Command:         p.Command,
		WantPty:         p.WantPTY,
		WantDetachable:  p.WantDetachable,
		AttachSessionId: p.AttachSessionID,
		ForwardTarget:   p.ForwardTarget,
		Service:         p.Service,
		ClientNoisePub:  key.Public,
		ClientPath:      types.PathNative,
	})
	if err != nil {
		return nil, Humanize(err)
	}
	return DialGrant(ctx, pool, resp, key)
}

// DialGrant builds the E2E data path from a brokered CreateSessionResponse and
// the ephemeral noise key bound into its grant: TLS to the relay (pinned geneza
// CA) -> rendezvous -> Noise IK handshake carrying the signed grant -> SSH (or,
// for vpn, the bare tunnel conn). Factored out of Establish so a server-side
// initiator (the web-shell proxy) can reuse the exact same client data path
// after brokering a session in-process instead of over gRPC.
func DialGrant(ctx context.Context, pool *x509.CertPool, resp *genezav1.CreateSessionResponse, key noise.DHKey) (*Session, error) {
	return DialGrantVia(ctx, pool, resp, key, "")
}

// DialGrantVia is DialGrant with an optional dialAddr that overrides the TCP
// target while keeping the grant's relay host as the TLS ServerName. The
// in-process web-shell proxy uses this to reach the relay LOCALLY
// (e.g. 127.0.0.1:7403) instead of NAT-hairpinning to the public relay address
// the grant advertises to external clients.
func DialGrantVia(ctx context.Context, pool *x509.CertPool, resp *genezav1.CreateSessionResponse, key noise.DHKey, dialAddr string) (*Session, error) {
	// Decode the (gateway-signed) grant payload for its resolved scope. We do
	// not verify it here — the agent does — we just read what the gateway chose
	// for a service connect / vpn (forward target, routes, overlay IP).
	resolved := &types.SessionGrant{}
	if env, derr := types.DecodeSigned(resp.GetSignedGrant()); derr == nil {
		_ = json.Unmarshal(env.Payload, resolved)
	}
	if resp.GetRelayAddr() == "" || resp.GetRelayToken() == "" || len(resp.GetAgentNoisePub()) != 32 {
		return nil, errors.New("gateway returned an incomplete session grant")
	}

	host, _, err := net.SplitHostPort(resp.GetRelayAddr())
	if err != nil {
		return nil, fmt.Errorf("relay address %q: %w", resp.GetRelayAddr(), err)
	}
	dialer := &tls.Dialer{Config: &tls.Config{
		RootCAs:    pool, // relay certs are issued by the geneza CA
		ServerName: host, // always the grant's relay host (matches the cert SAN)
		MinVersion: tls.VersionTLS12,
	}}
	target := resp.GetRelayAddr()
	if dialAddr != "" {
		target = dialAddr // dial locally; ServerName stays the public relay host
	}
	raw, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("relay connect %s: %w", target, err)
	}
	ok := false
	defer func() {
		if !ok {
			raw.Close()
		}
	}()

	if err := wire.WriteJSON(raw, wire.RelayHello{V: 1, Token: resp.GetRelayToken(), Role: wire.RoleInitiator}); err != nil {
		return nil, fmt.Errorf("relay hello: %w", err)
	}
	// The relay answers once both endpoints arrive; if the agent never shows
	// up (offline, grant rejected pre-dial) we bound the wait.
	if err := raw.SetReadDeadline(time.Now().Add(relayRendezvousTimeout)); err != nil {
		return nil, err
	}
	var rresp wire.RelayResp
	if err := wire.ReadJSON(raw, &rresp); err != nil {
		if isTimeout(err) {
			return nil, errors.New("relay rendezvous timed out (node did not connect — is it online?)")
		}
		return nil, fmt.Errorf("relay rendezvous: %w", err)
	}
	if !rresp.OK {
		return nil, fmt.Errorf("relay refused rendezvous: %s", rresp.Error)
	}

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
	// the gateway-signed grant binding this client key to this session.
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
	return &Session{
		ID:            resp.GetSessionId(),
		SSH:           ssh.NewClient(sshConn, chans, reqs),
		HostSessionID: acc.HostSessionID,
		Action:        resolved.Action,
		ForwardTarget: resolved.ForwardTarget,
		Routes:        resolved.Routes,
		OverlayIP:     resolved.OverlayIP,
	}, nil
}

func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, os.ErrDeadlineExceeded) ||
		strings.Contains(err.Error(), "i/o timeout") // wrapped by wire/tunnel
}
