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
	Action          string // types.ActionShell|Exec|SFTP|Forward|Attach
	Command         string
	WantPTY         bool
	WantDetachable  bool
	AttachSessionID string
	ForwardTarget   string
}

// Session is one established end-to-end tunnel with the SSH channel layer on
// top. Close tears down the whole stack (ssh -> noise -> relay TCP).
type Session struct {
	ID  string // gateway session id
	SSH *ssh.Client
	// HostSessionID is reported by the agent in its acceptance payload when
	// it created/attached a persistent host session (may be empty).
	HostSessionID string
}

func (s *Session) Close() error {
	if s == nil || s.SSH == nil {
		return nil
	}
	return s.SSH.Close()
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
		ClientNoisePub:  key.Public,
		ClientPath:      types.PathNative,
	})
	if err != nil {
		return nil, Humanize(err)
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
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}}
	raw, err := dialer.DialContext(ctx, "tcp", resp.GetRelayAddr())
	if err != nil {
		return nil, fmt.Errorf("relay connect %s: %w", resp.GetRelayAddr(), err)
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
