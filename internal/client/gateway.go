package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"geneza.io/internal/ca"
	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// LoadCAPool loads (and pin-checks) the profile's trust bundle as a CertPool.
func (s *Store) LoadCAPool(pin string) (*x509.CertPool, error) {
	pemBytes, err := s.LoadCA(pin)
	if err != nil {
		return nil, err
	}
	return ca.PoolFromPEM(pemBytes)
}

// ClientCert loads the operator's mTLS keypair and rejects expired certs
// early with an actionable message (the controller would reject them anyway).
func (s *Store) ClientCert() (*tls.Certificate, *x509.Certificate, error) {
	certPEM, err := os.ReadFile(s.CertPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, errors.New("not logged in (run 'geneza login')")
	}
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(s.KeyPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, errors.New("not logged in (run 'geneza login')")
	}
	if err != nil {
		return nil, nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("load client credentials: %w", err)
	}
	leaf, err := parseLeaf(certPEM)
	if err != nil {
		return nil, nil, err
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, nil, fmt.Errorf("certificate expired %s — run 'geneza login'", leaf.NotAfter.Local().Format(time.RFC3339))
	}
	return &pair, leaf, nil
}

func parseLeaf(certPEM []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		return nil, errors.New("user.crt: no PEM block")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// DialController opens a gRPC connection to the controller. clientCert may be nil
// for the cert-less RPCs (Login); everything else requires user mTLS.
// Server verification is always against the pinned CA pool — never WebPKI.
func DialController(addr string, pool *x509.CertPool, clientCert *tls.Certificate) (*grpc.ClientConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("controller address %q: %w", addr, err)
	}
	tc := &tls.Config{
		RootCAs:    pool,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}
	if clientCert != nil {
		tc.Certificates = []tls.Certificate{*clientCert}
	}
	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tc)))
	if err != nil {
		return nil, fmt.Errorf("dial controller: %w", err)
	}
	return cc, nil
}

// dialRedirect connects to the controller a CreateSession redirect points at, trying
// its signed addresses in order. It returns a UserAPI client plus a closer the
// caller ties to the session lifetime (the connection carries the session's
// presence heartbeat and signaling after the redirect is followed).
func dialRedirect(red *genezav1.ControllerRedirect, pool *x509.CertPool, cert *tls.Certificate) (genezav1.UserAPIClient, func() error, error) {
	var lastErr error
	for _, addr := range red.GetAddrs() {
		cc, err := DialController(addr, pool, cert)
		if err != nil {
			lastErr = err
			continue
		}
		return genezav1.NewUserAPIClient(cc), cc.Close, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("redirect carried no addresses")
	}
	return nil, nil, fmt.Errorf("dial redirect controller %q: %w", red.GetControllerId(), lastErr)
}

// Humanize turns gRPC transport/status errors into operator-readable ones
// (no "rpc error: code = ..." noise). The mapping is intentionally small —
// the controller already writes human messages.
func Humanize(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("timed out talking to the controller")
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	msg := st.Message()
	switch st.Code() {
	case codes.PermissionDenied:
		if strings.Contains(strings.ToLower(msg), "denied") {
			return errors.New(msg)
		}
		return fmt.Errorf("policy denied: %s", msg)
	case codes.Unauthenticated:
		return fmt.Errorf("not authenticated: %s (run 'geneza login')", msg)
	case codes.Unavailable:
		return fmt.Errorf("controller unreachable: %s", msg)
	case codes.DeadlineExceeded:
		return errors.New("timed out talking to the controller")
	default:
		return errors.New(msg)
	}
}
