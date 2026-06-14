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

// Geneza role names. platform-admin is the cloud-operator root: it gates
// hub-graph mutations (bindings, cloud registration) and is issued ONLY
// out-of-band (break-glass), never derivable from an IdP/policy mapping
// (security #11). admin is the per-deployment fleet admin (IdP-grantable).
const (
	roleAdmin         = "admin"
	rolePlatformAdmin = "platform-admin"
)

func hasRole(ident *ca.Identity, role string) bool {
	for _, r := range ident.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// stripReservedRoles removes platform-admin from a set of IdP/policy-resolved
// roles (security #11): platform-admin is the out-of-band cloud-operator root and
// must NEVER be derivable from a login/policy mapping, no matter how policy is
// (mis)configured. Break-glass cert issuance is the only path that grants it.
func stripReservedRoles(roles []string) []string {
	out := roles[:0:0]
	for _, r := range roles {
		if r == rolePlatformAdmin {
			slog.Warn("policy attempted to grant a reserved role; stripped", "role", r)
			continue
		}
		out = append(out, r)
	}
	return out
}

// serialHex renders a leaf cert's serial as the revocation-denylist key.
func serialHex(c *x509.Certificate) string {
	if c == nil || c.SerialNumber == nil {
		return ""
	}
	return c.SerialNumber.Text(16)
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

// checkNotRevoked fails the call if the authenticated peer's leaf cert is on the
// revocation denylist (security #6). Unauthenticated paths (no peer cert) skip
// it — they carry no identity to revoke.
func (s *Server) checkNotRevoked(ctx context.Context) error {
	_, leaf, ok := identityFrom(ctx)
	if !ok || leaf == nil {
		return nil
	}
	if s.store.IsCertRevoked(serialHex(leaf)) {
		return status.Error(codes.PermissionDenied, "credential revoked")
	}
	return nil
}

func (s *Server) unaryAuthInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, err := authorize(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		if err := s.checkNotRevoked(ctx); err != nil {
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

func (s *Server) streamAuthInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := authorize(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		if err := s.checkNotRevoked(ctx); err != nil {
			return err
		}
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
	}
}
