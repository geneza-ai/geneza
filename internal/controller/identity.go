package controller

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"geneza.io/internal/ca"
)

// Identity provider names. These are the canonical `provider` values that key
// member rows, sessions, and cert claims. keystone identities are resolved
// against a cloud's Keystone and get roles only from store membership; local/
// oidc are the config-identity providers whose policy bindings still apply.
const (
	providerLocal    = "local"
	providerOIDC     = "oidc"
	providerKeystone = "keystone"
)

// A syntactically valid bcrypt hash compared against when the username is
// unknown, so unknown-user and wrong-password take comparable time.
const dummyBcryptHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// identityAuth authenticates LOCAL (bcrypt) console logins. OIDC verification
// for the console lives on consoleAPI (its own audience/verifier); keystone is
// the cloud verifier. This type is now local-only.
type identityAuth struct {
	local     []LocalUser
	dummyHash []byte // bcrypt hash compared on unknown user (cost matches configured users)
}

func newIdentityAuth(cfg *Config) *identityAuth {
	ia := &identityAuth{local: cfg.LocalUsers}
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

// oidcIdentity is the full set of claims the console session needs from a
// verified id_token: the display name, the STABLE subject id (the member key),
// the groups, and the token expiry (which caps the session TTL).
type oidcIdentity struct {
	User    string
	Subject string
	Groups  []string
	Exp     int64
}

// extractOIDCIdentity pulls the session-relevant fields out of verified id_token
// claims (used by the console's verifyConsoleOIDC). The verifier that produced
// `claims` must already have checked the audience.
func extractOIDCIdentity(cfg *OIDCConfig, claims map[string]any) (oidcIdentity, error) {
	user, _ := claims[cfg.UsernameClaim].(string)
	if user == "" {
		return oidcIdentity{}, fmt.Errorf("oidc token has no usable %q claim", cfg.UsernameClaim)
	}
	subject, _ := claims["sub"].(string)
	if subject == "" {
		subject = user // fall back to the display name if the IdP omits sub
	}
	var groups []string
	switch v := claims[cfg.GroupsClaim].(type) {
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
	exp, _ := claims["exp"].(float64)
	return oidcIdentity{User: user, Subject: subject, Groups: groups, Exp: int64(exp)}, nil
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

// issueUserCert mints a short-TTL user cert from a CSR, baking in the resolved
// workspace + roles + provider. It is the SOLE cert-issuance core, shared by the
// device-grant redeem (the only login that yields a CLI cert). Roles are
// reserved-stripped at the boundary as defense-in-depth.
func (s *Server) issueUserCert(provider, user, subject, ws string, roles []string, csrPEM []byte, ttl time.Duration) (certPEM []byte, expiresUnix int64, err error) {
	if len(csrPEM) == 0 {
		return nil, 0, fmt.Errorf("csr is required")
	}
	if ttl <= 0 || ttl > s.cfg.CertTTL.User.D() {
		ttl = s.cfg.CertTTL.User.D()
	}
	certPEM, err = s.ca.IssueFromCSR(csrPEM, ca.Profile{
		Kind:      ca.KindUser,
		Workspace: ws,
		Name:      user,
		TTL:       ttl,
		Claims:    &ca.IdentityClaims{Roles: stripReservedRoles(roles), Provider: provider, Subject: subject},
	})
	if err != nil {
		return nil, 0, fmt.Errorf("issue user cert: %w", err)
	}
	expiresUnix, err = leafNotAfter(certPEM)
	if err != nil {
		return nil, 0, fmt.Errorf("parse issued cert: %w", err)
	}
	return certPEM, expiresUnix, nil
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
