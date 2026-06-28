// Package clientcore is the shared, UI-agnostic engine behind the geneza client:
// it loads a profile, dials the controller over mTLS, and orchestrates sessions
// over the direct end-to-end tunnel. Both the CLI (cmd/geneza) and the desktop
// app drive sessions through it, so the session logic lives in one place instead
// of being inlined per command. It pulls in no terminal or GUI dependencies — a
// CLI TTY wraps the result with client.RunAttached, the desktop wraps it with
// Session.OpenAttachChannel + internal/attachbridge.
package clientcore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"

	"google.golang.org/grpc"

	"geneza.io/internal/client"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

// Client is a logged-in geneza client: the mTLS controller connection plus the
// loaded profile and trust pool.
type Client struct {
	store   *client.Store
	profile *client.Profile
	pool    *x509.CertPool
	cert    *tls.Certificate
	cc      *grpc.ClientConn
	api     genezav1.UserAPIClient
}

// Open loads the named profile (empty = "default"), dials the controller over mTLS,
// and returns a ready Client. Close it when done.
func Open(profile string) (*Client, error) {
	if profile == "" {
		profile = "default"
	}
	st, err := client.NewStore(profile)
	if err != nil {
		return nil, err
	}
	prof, err := st.LoadProfile()
	if err != nil {
		return nil, err
	}
	pool, err := st.LoadCAPool(prof.CASHA256)
	if err != nil {
		return nil, err
	}
	cert, _, err := st.ClientCert()
	if err != nil {
		return nil, err
	}
	cc, err := client.DialController(prof.ControllerGRPC, pool, cert)
	if err != nil {
		return nil, err
	}
	return &Client{store: st, profile: prof, pool: pool, cert: cert, cc: cc, api: genezav1.NewUserAPIClient(cc)}, nil
}

// Close releases the controller connection.
func (c *Client) Close() error { return c.cc.Close() }

// API exposes the controller UserAPI for callers needing RPCs beyond the helpers
// here (sessions, policy, audit, metrics, tokens).
func (c *Client) API() genezav1.UserAPIClient { return c.api }

// Profile returns the loaded profile (controller addresses, identity, trust pin).
func (c *Client) Profile() *client.Profile { return c.profile }

// ControllerHTTP is the controller's HTTPS base (host:7402) — the listener that mounts
// the cert-authed console /api/v1 the desktop app proxies to.
func (c *Client) ControllerHTTP() string { return c.profile.ControllerHTTP }

// HTTPClient returns an http.Client that authenticates to the controller HTTPS
// listener with this identity's mTLS user cert (pinned to the same CA the gRPC
// path trusts). The desktop app proxies the console API through it.
func (c *Client) HTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{*c.cert},
				RootCAs:      c.pool,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}
}

// OpenSession establishes a session over the direct, end-to-end Noise tunnel —
// the same path `geneza ssh` uses (client_path=native; the controller brokers the
// grant but is not in the data path). The caller drives the result:
// client.RunAttached for a CLI TTY, or Session.OpenAttachChannel +
// internal/attachbridge for the desktop UI.
func (c *Client) OpenSession(ctx context.Context, p client.SessionParams) (*client.Session, error) {
	return client.Establish(ctx, c.api, c.pool, c.cert, p)
}

// Reattacher returns a hook that re-establishes a detachable session by ID after
// a tunnel blip, suitable for client.AttachOptions.Reattach.
func (c *Client) Reattacher(node, sessionID string, pty bool) func(context.Context) (*client.Session, error) {
	return func(ctx context.Context) (*client.Session, error) {
		return c.OpenSession(ctx, client.SessionParams{
			Node:            node,
			Action:          types.ActionAttach,
			AttachSessionID: sessionID,
			WantPTY:         pty,
			WantDetachable:  true,
		})
	}
}

// ListNodes returns the fleet visible to this identity.
func (c *Client) ListNodes(ctx context.Context, limit, offset int) (*genezav1.ListNodesResponse, error) {
	return c.api.ListNodes(ctx, &genezav1.ListNodesRequest{Limit: int32(limit), Offset: int32(offset)})
}
