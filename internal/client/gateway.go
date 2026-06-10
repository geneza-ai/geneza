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

	"osie.cloud/geneza/internal/ca"
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
// early with an actionable message (the gateway would reject them anyway).
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

// DialGateway opens a gRPC connection to the gateway. clientCert may be nil
// for the cert-less RPCs (Login); everything else requires user mTLS.
// Server verification is always against the pinned CA pool — never WebPKI.
func DialGateway(addr string, pool *x509.CertPool, clientCert *tls.Certificate) (*grpc.ClientConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("gateway address %q: %w", addr, err)
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
		return nil, fmt.Errorf("dial gateway: %w", err)
	}
	return cc, nil
}

// Humanize turns gRPC transport/status errors into operator-readable ones
// (no "rpc error: code = ..." noise). The mapping is intentionally small —
// the gateway already writes human messages.
func Humanize(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("timed out talking to the gateway")
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
		return fmt.Errorf("gateway unreachable: %s", msg)
	case codes.DeadlineExceeded:
		return errors.New("timed out talking to the gateway")
	default:
		return errors.New(msg)
	}
}
