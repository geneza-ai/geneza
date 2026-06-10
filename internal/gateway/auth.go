package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"osie.cloud/geneza/internal/ca"
)

// One listener, three trust levels. VerifyClientCertIfGiven lets Enrollment
// and UserAPI.Login in without a client cert while everything else is gated
// per-RPC on the verified peer identity. A presented-but-invalid cert still
// fails the TLS handshake outright.
func (s *Server) grpcTLSConfig() (*tls.Config, error) {
	pool, err := ca.PoolFromPEM(s.ca.RootsPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{s.tlsCert},
		ClientCAs:    pool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

type peerInfoKey struct{}

// peerInfo is the verified caller identity placed in the request context.
type peerInfo struct {
	identity *ca.Identity
	leaf     *x509.Certificate
}

func identityFrom(ctx context.Context) (*ca.Identity, *x509.Certificate, bool) {
	pi, ok := ctx.Value(peerInfoKey{}).(*peerInfo)
	if !ok || pi == nil || pi.identity == nil {
		return nil, nil, false
	}
	return pi.identity, pi.leaf, true
}

// extractPeer pulls the verified leaf cert (if any) out of the TLS state.
func extractPeer(ctx context.Context) *peerInfo {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil
	}
	if len(ti.State.VerifiedChains) == 0 || len(ti.State.VerifiedChains[0]) == 0 {
		return nil
	}
	leaf := ti.State.VerifiedChains[0][0]
	ident, err := ca.PeerIdentity(leaf)
	if err != nil {
		// A cert our CA signed but without a parseable Geneza identity is
		// treated as anonymous; identity-requiring methods then fail closed.
		slog.Warn("client cert without usable geneza identity", "err", err)
		return nil
	}
	return &peerInfo{identity: ident, leaf: leaf}
}

func hasRole(ident *ca.Identity, role string) bool {
	for _, r := range ident.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// authorize enforces the per-method trust level and returns the context
// enriched with the peer identity. Unknown methods are denied (fail closed).
func authorize(ctx context.Context, fullMethod string) (context.Context, error) {
	pi := extractPeer(ctx)
	if pi != nil {
		ctx = context.WithValue(ctx, peerInfoKey{}, pi)
	}
	switch {
	case strings.HasPrefix(fullMethod, "/geneza.v1.Enrollment/"),
		fullMethod == "/geneza.v1.UserAPI/Login":
		return ctx, nil
	case strings.HasPrefix(fullMethod, "/geneza.v1.NodeControl/"):
		if pi == nil {
			return nil, status.Error(codes.Unauthenticated, "node certificate required")
		}
		if pi.identity.Kind != ca.KindNode {
			return nil, status.Error(codes.PermissionDenied, "node certificate required")
		}
		return ctx, nil
	case strings.HasPrefix(fullMethod, "/geneza.v1.UserAPI/"):
		if pi == nil {
			return nil, status.Error(codes.Unauthenticated, "user certificate required")
		}
		if pi.identity.Kind != ca.KindUser {
			return nil, status.Error(codes.PermissionDenied, "user certificate required")
		}
		return ctx, nil
	case strings.HasPrefix(fullMethod, "/geneza.v1.AdminAPI/"):
		if pi == nil {
			return nil, status.Error(codes.Unauthenticated, "admin certificate required")
		}
		if pi.identity.Kind != ca.KindUser || !hasRole(pi.identity, "admin") {
			return nil, status.Error(codes.PermissionDenied, "admin role required")
		}
		return ctx, nil
	default:
		return nil, status.Errorf(codes.PermissionDenied, "method %s not allowed", fullMethod)
	}
}

func unaryAuthInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, err := authorize(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }

func streamAuthInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := authorize(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
	}
}
