package gateway

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"osie.cloud/geneza/internal/ca"
	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

// A syntactically valid bcrypt hash compared against when the username is
// unknown, so unknown-user and wrong-password take comparable time.
const dummyBcryptHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// identityAuth authenticates Login requests. OIDC discovery happens lazily
// on first login and is cached, so the gateway starts (and local login
// works) even while the IdP is down.
type identityAuth struct {
	oidcCfg   *OIDCConfig
	local     []LocalUser
	verifier  *oidcVerifier // nil unless OIDC is configured
	dummyHash []byte        // bcrypt hash compared on unknown user (cost matches configured users)
}

func newIdentityAuth(cfg *Config) *identityAuth {
	ia := &identityAuth{oidcCfg: cfg.OIDC, local: cfg.LocalUsers}
	if cfg.OIDC != nil {
		ia.verifier = newOIDCVerifier(cfg.OIDC.Issuer, cfg.OIDC.ClientID)
	}
	// Compare unknown-username logins against a dummy hash at the SAME bcrypt
	// cost as the configured users, so response time does not leak whether a
	// username exists (a fixed cost-10 dummy is a timing oracle when users are
	// hashed at a different cost).
	ia.dummyHash = []byte(dummyBcryptHash)
	for _, u := range cfg.LocalUsers {
		if c, err := bcrypt.Cost([]byte(u.PasswordBcrypt)); err == nil {
			if h, err := bcrypt.GenerateFromPassword([]byte("geneza-dummy-password"), c); err == nil {
				ia.dummyHash = h
			}
			break
		}
	}
	return ia
}

// authenticate verifies the caller's credentials and returns the asserted
// username and IdP groups. It performs no authorization.
func (ia *identityAuth) authenticate(ctx context.Context, req *genezav1.LoginRequest) (user string, groups []string, err error) {
	switch req.GetProvider() {
	case "oidc":
		return ia.authenticateOIDC(ctx, req.GetOidcIdToken())
	case "local":
		return ia.authenticateLocal(req.GetUsername(), req.GetPassword())
	default:
		return "", nil, fmt.Errorf("unknown login provider %q", req.GetProvider())
	}
}

func (ia *identityAuth) authenticateOIDC(ctx context.Context, rawIDToken string) (string, []string, error) {
	if ia.oidcCfg == nil {
		return "", nil, fmt.Errorf("oidc login is not configured")
	}
	if rawIDToken == "" {
		return "", nil, fmt.Errorf("missing oidc id token")
	}
	claims, err := ia.verifier.verify(ctx, rawIDToken)
	if err != nil {
		return "", nil, fmt.Errorf("oidc token verification: %w", err)
	}
	username, _ := claims[ia.oidcCfg.UsernameClaim].(string)
	if username == "" {
		return "", nil, fmt.Errorf("oidc token has no usable %q claim", ia.oidcCfg.UsernameClaim)
	}
	var groups []string
	switch v := claims[ia.oidcCfg.GroupsClaim].(type) {
	case []any:
		for _, g := range v {
			if s, ok := g.(string); ok && s != "" {
				groups = append(groups, s)
			}
		}
	case string:
		if v != "" {
			groups = []string{v}
		}
	}
	return username, groups, nil
}

func (ia *identityAuth) authenticateLocal(username, password string) (string, []string, error) {
	if len(ia.local) == 0 {
		return "", nil, fmt.Errorf("local login is not configured")
	}
	var found *LocalUser
	for i := range ia.local {
		if ia.local[i].Username == username {
			found = &ia.local[i]
			break
		}
	}
	if found == nil {
		_ = bcrypt.CompareHashAndPassword(ia.dummyHash, []byte(password))
		return "", nil, fmt.Errorf("invalid username or password")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(found.PasswordBcrypt), []byte(password)); err != nil {
		return "", nil, fmt.Errorf("invalid username or password")
	}
	return found.Username, found.Groups, nil
}

func (ia *identityAuth) localEnabled() bool { return len(ia.local) > 0 }

// handleLogin: authenticate -> resolve roles -> issue a short-TTL user cert.
// Users with no roles are denied outright: a cert without roles cannot pass
// any policy, so refusing the cert keeps the system legible.
func (s *Server) handleLogin(ctx context.Context, req *genezav1.LoginRequest) (*genezav1.LoginResponse, error) {
	provider := req.GetProvider()
	user, groups, err := s.identity.authenticate(ctx, req)
	if err != nil {
		if aerr := s.audit.Append("login_denied", req.GetUsername(), "", "", map[string]string{
			"provider": provider, "reason": err.Error(),
		}); aerr != nil {
			return nil, status.Errorf(codes.Internal, "audit append: %v", aerr)
		}
		return nil, status.Errorf(codes.Unauthenticated, "login failed: %v", err)
	}
	// Resolve the workspace to mint a cert for, validated against membership.
	// A requested workspace must be one the user belongs to; if none requested
	// and the user belongs to exactly one, use it; if several, return the
	// candidates so the client re-logs in with a choice; if none, deny.
	cands := s.workspacesForUser(user, groups)
	ws := req.GetWorkspace()
	if ws != "" {
		if !contains(cands, ws) {
			if aerr := s.audit.Append("login_denied", user, "", "", map[string]string{
				"provider": provider, "reason": "not a member of workspace " + ws,
			}); aerr != nil {
				return nil, status.Errorf(codes.Internal, "audit append: %v", aerr)
			}
			return nil, status.Errorf(codes.PermissionDenied, "user %q is not a member of workspace %q", user, ws)
		}
	} else {
		switch len(cands) {
		case 0:
			return nil, status.Errorf(codes.PermissionDenied, "user %q belongs to no workspace", user)
		case 1:
			ws = cands[0]
		default:
			// Ambiguous: let the client pick from the candidates and retry.
			return &genezav1.LoginResponse{User: user, AvailableWorkspaces: cands}, nil
		}
	}
	roles := s.policyFor(ws).RolesFor(user, groups)
	if len(roles) == 0 {
		if aerr := s.audit.Append("login_denied", user, "", "", map[string]string{
			"provider": provider, "reason": "no roles bound to user/groups",
			"groups": strings.Join(groups, ","),
		}); aerr != nil {
			return nil, status.Errorf(codes.Internal, "audit append: %v", aerr)
		}
		return nil, status.Errorf(codes.PermissionDenied, "user %q has no roles in policy", user)
	}
	if len(req.GetCsrPem()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "csr_pem is required")
	}
	certPEM, err := s.ca.IssueFromCSR(req.GetCsrPem(), ca.Profile{
		Kind:      ca.KindUser,
		Workspace: ws,
		Name:      user,
		TTL:       s.cfg.CertTTL.User.D(),
		Claims:    &ca.IdentityClaims{Roles: roles, Provider: provider},
	})
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "issue user cert: %v", err)
	}
	expires, err := leafNotAfter(certPEM)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "parse issued cert: %v", err)
	}
	if err := s.audit.Append("login_success", user, "", "", map[string]string{
		"provider": provider, "roles": strings.Join(roles, ","),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit append: %v", err)
	}
	return &genezav1.LoginResponse{
		UserCertPem: certPEM,
		CaRootsPem:  s.ca.RootsPEM,
		User:        user,
		Roles:       roles,
		ExpiresUnix: expires,
		Workspace:   ws,
	}, nil
}

func leafNotAfter(certPEM []byte) (int64, error) {
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		return 0, fmt.Errorf("no PEM block in issued cert")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return 0, err
	}
	return c.NotAfter.Unix(), nil
}
