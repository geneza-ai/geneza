package controller

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

	"geneza.io/internal/ca"
)

// One listener, three trust levels. VerifyClientCertIfGiven lets Enrollment
// and WorkspaceAPI.Login in without a client cert while everything else is gated
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

// Geneza role names and the trust boundary between them.
//
//   - platform-admin: the cloud-operator root — gates hub-graph mutations
//     (bindings, cloud registration).
//   - admin: the CLUSTER/fleet super-admin — the only role the gRPC ClusterAPI
//     gate accepts (cross-workspace fleet management).
//
// BOTH are RESERVED: they are issued ONLY out-of-band via a break-glass cert,
// and are NEVER derivable from any login / policy / keystone role_map / store
// membership path, no matter how (mis)configured. A
// login — being inherently workspace-scoped — must never mint a cross-workspace
// cluster credential. The most a login can grant is ws-admin (workspace admin):
// it satisfies the console mutation gate but NOT the gRPC ClusterAPI gate.
const (
	roleAdmin         = "admin"
	rolePlatformAdmin = "platform-admin"
	roleWSAdmin       = "ws-admin"
	// roleWSMember is the ordinary operating role in a workspace: it can run and
	// observe the fleet (above the read-only ws-viewer, below ws-admin). It is the
	// floor for reading the workspace's vulnerability surface.
	roleWSMember = "ws-member"
	// roleWSAuditor is the workspace-scoped audit/replay capability: it may list
	// and fetch session recordings for its workspace. Replaying someone's shell is
	// privileged and is NOT implied by ordinary operator membership, so it is its
	// own role rather than folded into ws-member; an operator grants it explicitly
	// (keystone role_map / membership). It carries no other mutation authority.
	roleWSAuditor = "ws-auditor"
)

// reservedRoles are stripped from every login/policy/membership-resolved role
// set. Cluster authority comes only from a break-glass cert (whose roles are
// baked in at issuance and never re-resolved through this path).
var reservedRoles = map[string]bool{roleAdmin: true, rolePlatformAdmin: true}

func hasRole(ident *ca.Identity, role string) bool {
	for _, r := range ident.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// canReplayRecordings reports whether an identity may list/fetch session
// recordings. The dedicated ws-auditor role grants it within its workspace; the
// workspace admin (ws-admin) holds it for its workspace, and the break-glass
// cluster admins (admin / platform-admin) hold it everywhere. The user-cert is
// already workspace-scoped, so a ws-auditor / ws-admin grant is implicitly
// confined to that workspace; only a cluster admin spans workspaces.
func canReplayRecordings(ident *ca.Identity) bool {
	return hasRole(ident, roleWSAuditor) || hasRole(ident, roleWSAdmin) ||
		hasRole(ident, roleAdmin) || hasRole(ident, rolePlatformAdmin)
}

// canViewVulns reports whether an identity may read the workspace's vulnerability
// surface (a node's CVEs, the nodes a CVE affects, a node's inventory). The data
// reveals a fleet's exploitable surface, so a read-only ws-viewer is too low: it
// takes operating standing — ws-member — or higher (ws-admin / the audit role /
// the break-glass cluster admins). The user-cert is already workspace-scoped, so
// every grant here is implicitly confined to that workspace; only a cluster admin
// spans workspaces, and even then each query is scoped to the calling cert's
// workspace at the call site.
func canViewVulns(ident *ca.Identity) bool {
	return hasRole(ident, roleWSMember) || hasRole(ident, roleWSAuditor) ||
		hasRole(ident, roleWSAdmin) || hasRole(ident, roleAdmin) ||
		hasRole(ident, rolePlatformAdmin)
}

// stripReservedRoles removes the reserved cluster roles (admin, platform-admin)
// from any IdP/policy/keystone/membership-resolved role set: these are
// out-of-band cluster-operator roots and must NEVER be derivable from a login,
// no matter how policy/role_map is (mis)configured. Break-glass cert issuance is
// the only path that grants them.
func stripReservedRoles(roles []string) []string {
	out := roles[:0:0]
	for _, r := range roles {
		if reservedRoles[r] {
			slog.Warn("policy attempted to grant a reserved cluster role; stripped", "role", r)
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
	case strings.HasPrefix(fullMethod, "/geneza.v1.Enrollment/"):
		// Enrollment is the ONLY cert-less gRPC surface. Human login is no longer
		// a gRPC RPC — it is the RFC 8628 device grant over HTTP (:7402), which
		// yields the user cert. So everything else requires a verified cert.
		return ctx, nil
	case strings.HasPrefix(fullMethod, "/geneza.v1.NodeControl/"):
		if pi == nil {
			return nil, status.Error(codes.Unauthenticated, "node certificate required")
		}
		if pi.identity.Kind != ca.KindNode {
			return nil, status.Error(codes.PermissionDenied, "node certificate required")
		}
		return ctx, nil
	case strings.HasPrefix(fullMethod, "/geneza.v1.RelayRegistry/"):
		if pi == nil {
			return nil, status.Error(codes.Unauthenticated, "relay certificate required")
		}
		if pi.identity.Kind != ca.KindRelay {
			return nil, status.Error(codes.PermissionDenied, "relay certificate required")
		}
		return ctx, nil
	case strings.HasPrefix(fullMethod, "/geneza.v1.WorkspaceAPI/"):
		if pi == nil {
			return nil, status.Error(codes.Unauthenticated, "user certificate required")
		}
		if pi.identity.Kind != ca.KindUser {
			return nil, status.Error(codes.PermissionDenied, "user certificate required")
		}
		return ctx, nil
	case strings.HasPrefix(fullMethod, "/geneza.v1.ClusterAPI/"):
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
// revocation denylist. Unauthenticated paths (no peer cert) skip it — they carry
// no identity to revoke.
func (s *Server) checkNotRevoked(ctx context.Context) error {
	_, leaf, ok := identityFrom(ctx)
	if !ok || leaf == nil {
		return nil
	}
	serial := serialHex(leaf)
	if s.deny.certRevoked(serial, func() (bool, error) { return s.store.IsCertRevokedE(serial) }) {
		return status.Error(codes.PermissionDenied, "credential revoked")
	}
	return nil
}

// checkNotSuspended fails the call if the authenticated peer's principal has had
// its AUTHORIZATION revoked (suspended) — independent of the cert still being
// cryptographically valid (authentication). Checked on every authenticated RPC,
// like checkNotRevoked, so suspension takes effect IMMEDIATELY (not 15s later at
// the next sweep). Operational certs (no Subject: break-glass / node) are not
// member-suspendable and pass.
func (s *Server) checkNotSuspended(ctx context.Context) error {
	ident, _, ok := identityFrom(ctx)
	if !ok || ident == nil || ident.Kind != ca.KindUser {
		return nil
	}
	key := principalKey(ident.Workspace, ident.Provider, ident.Subject)
	if s.deny.suspended(key, func() (bool, error) {
		return s.store.IsSuspendedE(ident.Workspace, ident.Provider, ident.Subject)
	}) {
		return status.Error(codes.PermissionDenied, "authorization suspended")
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
		if err := s.checkNotSuspended(ctx); err != nil {
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
		if err := s.checkNotSuspended(ctx); err != nil {
			return err
		}
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
	}
}
