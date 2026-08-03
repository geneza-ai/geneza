package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"

	"geneza.io/internal/ca"
	"geneza.io/internal/client"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

// Cross-controller web shell (HA). Controllers are leaderless, but only the one
// holding an agent's control stream can push it a session offer — so a broker
// call for a node owned elsewhere comes back as a ControllerRedirect carrying no
// grant and no relay floor.
//
// The native CLI already handles this (internal/client/session.go): it re-dials
// the owning controller with its user cert and re-brokers there. The web proxy
// does the same, with one necessary difference: the CLI *is* the user and holds
// their cert, while the proxy is the controller acting on their behalf. So it
// mints a short-TTL leaf for that console user from its own CA — the owner then
// authenticates an ordinary mTLS user session and needs no special case.
//
// The cert carries a WEB client-path pin. Without it the owner's CreateSession
// would classify the re-brokered session as native (the path is decided by the
// server, never from req.client_path) and a `require_native` rule — the policy
// that reserves sensitive targets for the native client — would be bypassed by
// the web shell whenever the LB happened to land on a non-owner controller. The
// pin only ever narrows, so it is safe in the one direction that matters.

// webRedirectCertTTL bounds the ephemeral cert. It only has to survive dialing
// the owner and re-brokering, so it is deliberately far shorter than a login cert.
const webRedirectCertTTL = 2 * time.Minute

// brokerWebSession brokers a web-path session for a console user, following at
// most one cross-controller redirect. It returns the response to build the data
// path from, plus a closer for any owner connection the caller must keep alive.
//
// A second redirect is a control-plane bug, not a retry — same rule as the CLI.
func (c *consoleAPI) brokerWebSession(ctx context.Context, u *consoleUser, req *genezav1.CreateSessionRequest) (*genezav1.CreateSessionResponse, func() error, error) {
	ident := &ca.Identity{
		Kind: ca.KindUser, Workspace: u.Workspace, Name: u.Name,
		Roles: u.Roles, Provider: u.Provider, Subject: u.Subject,
	}
	resp, err := c.s.broker.CreateSessionWeb(ctx, ident, req)
	if err != nil {
		return nil, nil, err
	}
	red := resp.GetControllerRedirect()
	if red == nil {
		return resp, nil, nil
	}

	// The target agent is homed on another controller. Become the user (briefly,
	// and only for the web path) and re-broker there.
	cert, err := c.s.mintWebProxyCert(u)
	if err != nil {
		return nil, nil, fmt.Errorf("mint proxy cert: %w", err)
	}
	pool, err := ca.PoolFromPEM(c.s.ca.RootsPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("ca pool: %w", err)
	}
	ownerAPI, closeConn, err := client.DialRedirect(red, pool, cert)
	if err != nil {
		return nil, nil, err
	}
	resp, err = ownerAPI.CreateSession(ctx, req)
	if err != nil {
		_ = closeConn()
		return nil, nil, err
	}
	if resp.GetControllerRedirect() != nil {
		_ = closeConn()
		return nil, nil, fmt.Errorf("controller %q redirected again; refusing to chase a redirect loop", red.GetControllerId())
	}
	return resp, closeConn, nil
}

// mintWebProxyCert issues a short-TTL client cert bearing the console user's
// identity and a web client-path pin, for one cross-controller re-broker. The
// key never leaves this process and the cert is not persisted.
func (s *Server) mintWebProxyCert(u *consoleUser) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: u.Name},
	}, key)
	if err != nil {
		return nil, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	certPEM, _, err := s.issueUserCertPath(u.Provider, u.Name, u.Subject, u.Workspace,
		types.PathWeb, u.Roles, csrPEM, webRedirectCertTTL)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &pair, nil
}
