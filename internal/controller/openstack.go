package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"
)

// serviceUserDenylist are Keystone service-account usernames the ACCESS plane
// rejects outright (defense-in-depth on top of the project-scope/service-role
// checks): a human login is never one of these.
var serviceUserDenylist = map[string]bool{
	"nova": true, "neutron": true, "glance": true, "cinder": true,
	"placement": true, "heat": true, "keystone": true, "ceilometer": true,
}

// validateHumanKeystoneToken enforces the access-plane guards on a validated
// Keystone identity (reject a service token; require project scope). It
// FAILS CLOSED: any ambiguity about scope or service-ness is a rejection.
func validateHumanKeystoneToken(caller osCaller, cl CloudConfig) error {
	// Must be strictly project-scoped (not domain/system/unscoped).
	if !caller.ScopeProject || caller.ProjectID == "" {
		return fmt.Errorf("token is not project-scoped (the access plane requires a project-scoped human token)")
	}
	if caller.ScopeDomain {
		return fmt.Errorf("token is domain-scoped (the access plane requires a project-scoped human token)")
	}
	// Reject anything that smells like a service credential. The service
	// project name is operator-configured; the `service` role and the well-known
	// service usernames are defense-in-depth. (UUID-pinning the service project
	// is a documented hardening over the name check.)
	if strings.EqualFold(caller.ProjectName, cl.serviceProject()) {
		return fmt.Errorf("service-project-scoped tokens are not accepted on the access plane")
	}
	if serviceUserDenylist[strings.ToLower(caller.UserName)] {
		return fmt.Errorf("service account %q may not use the access plane", caller.UserName)
	}
	for _, r := range caller.Roles {
		if strings.EqualFold(r, "service") {
			return fmt.Errorf("tokens carrying the keystone 'service' role are not accepted on the access plane")
		}
	}
	return nil
}

// The OpenStack client validates third-party Keystone tokens and reads Nova's
// authoritative view of an instance. It is the trust anchor for the enrollment
// plane: every credential is checked against the configured Keystone, and the
// instance→project mapping comes from Nova's server record, NEVER from the
// (attacker-controllable) vendordata body. See
// docs/openstack-integration.md

// osCaller is the validated identity behind a presented Keystone token.
type osCaller struct {
	UserName    string
	UserID      string // STABLE keystone user id — the member/session subject
	ProjectID   string
	ProjectName string
	Roles       []string
	ExpiresAt   time.Time
	// Scope detection for the ACCESS plane guards. A human token MUST be
	// project-scoped; a service/domain/system token is rejected.
	ScopeProject bool
	ScopeDomain  bool
	// TokenID is the raw Keystone token string (for a future token-revocation reaper).
	TokenID string
	// IssuerHost is the Keystone host that validated this token (for the
	// trusted_dashboard svc-uid pin).
	IssuerHost string
}

// passwordAuth carries the human login-form fields for a Keystone password grant.
type passwordAuth struct {
	Username    string
	Password    string
	DomainName  string // user + default project domain (default "Default")
	ProjectID   string // optional explicit project scope
	ProjectName string // optional explicit project scope (by name, within DomainName)
}

// osProjectRef is a project a user may scope to (returned for the picker when a
// user belongs to several projects and none was chosen).
type osProjectRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// osServer is Nova's authoritative record for an instance.
type osServer struct {
	TenantID string // the AUTHORITATIVE project — use this, not the body
	Status   string
}

// osProject is the human-facing project metadata (for naming an auto-provisioned
// workspace), resolved only when needed.
type osProject struct {
	Name     string
	DomainID string
}

// cloudVerifier validates a token and yields a session bound to that token for
// the follow-up Nova/Keystone callbacks. An interface so the vendordata handler
// is unit-testable with a fake (no live Keystone).
type cloudVerifier interface {
	Validate(ctx context.Context, token string) (cloudSession, error)
	// PasswordLogin authenticates a human (login-form) and returns their
	// project-scoped identity. If the user has several projects and none was
	// requested, it returns the project list (caller zero-valued) for a picker.
	PasswordLogin(ctx context.Context, in passwordAuth) (osCaller, []osProjectRef, error)
}

// errOSMultipleProjects signals the user must choose a project (the returned
// slice is non-empty); the handler turns it into a picker response.
var errOSNoProjects = fmt.Errorf("user has no projects")

type cloudSession interface {
	Caller() osCaller
	// GetServer reads Nova's record for instanceID: the authoritative
	// tenant_id. Returns a not-found error if the instance does not exist.
	GetServer(ctx context.Context, instanceID string) (osServer, error)
	// ResolveProject fetches a project's name/domain for workspace naming.
	ResolveProject(ctx context.Context, projectID string) (osProject, error)
}

// errOSNotFound is returned when Keystone/Nova reports 404 (unknown token target
// or instance). The handler maps it to a 404/401 toward Nova.
type errOSNotFound struct{ what string }

func (e errOSNotFound) Error() string { return e.what + ": not found" }

func isOSNotFound(err error) bool {
	if err == nil {
		return false
	}
	var nf errOSNotFound
	if errors.As(err, &nf) {
		return true
	}
	return gophercloud.ResponseCodeIs(err, http.StatusNotFound)
}

// openstackClient is the live (gophercloud-backed) verifier for one cloud.
type openstackClient struct {
	svcUID      string
	keystoneURL string // ends with /
	endpointAvl gophercloud.Availability
	httpClient  *http.Client
}

// newOpenstackClient builds a verifier for one clouds-registry entry. It sets up
// the HTTP transport (timeout + TLS trust) once; per-request it constructs a
// short-lived ProviderClient carrying the presented token.
func newOpenstackClient(svcUID string, cl CloudConfig) (*openstackClient, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cl.InsecureSkipVerify {
		tlsCfg.InsecureSkipVerify = true // #nosec G402 -- LAB ONLY, gated by config
	} else if cl.CAFile != "" {
		pem, err := os.ReadFile(cl.CAFile)
		if err != nil {
			return nil, fmt.Errorf("cloud %q: read ca_file: %w", svcUID, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("cloud %q: ca_file %s has no usable certificates", svcUID, cl.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	hc := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	avl := gophercloud.AvailabilityPublic
	switch cl.endpointInterface() {
	case "internal":
		avl = gophercloud.AvailabilityInternal
	case "admin":
		avl = gophercloud.AvailabilityAdmin
	}
	return &openstackClient{
		svcUID:      svcUID,
		keystoneURL: ensureTrailingSlash(cl.KeystoneURL),
		endpointAvl: avl,
		httpClient:  hc,
	}, nil
}

func ensureTrailingSlash(s string) string {
	if strings.HasSuffix(s, "/") {
		return s
	}
	return s + "/"
}

// provider builds a ProviderClient pre-loaded with the presented token (used as
// the X-Auth-Token for the validation + callbacks). No Authenticate() round-trip
// is needed: the service token is already valid and can validate itself + read
// Nova as an admin/service-scoped credential.
func (c *openstackClient) provider(token string) *gophercloud.ProviderClient {
	p := &gophercloud.ProviderClient{}
	p.HTTPClient = *c.httpClient
	p.SetToken(token)
	return p
}

func (c *openstackClient) identityClient(p *gophercloud.ProviderClient) *gophercloud.ServiceClient {
	return &gophercloud.ServiceClient{ProviderClient: p, Endpoint: c.keystoneURL}
}

// osLiveSession implements cloudSession against gophercloud.
type osLiveSession struct {
	cli      *openstackClient
	provider *gophercloud.ProviderClient
	identity *gophercloud.ServiceClient
	catalog  *tokens.ServiceCatalog
	caller   osCaller
}

func (c *openstackClient) Validate(ctx context.Context, token string) (cloudSession, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token")
	}
	p := c.provider(token)
	ic := c.identityClient(p)
	res := tokens.Get(ctx, ic, token)
	if res.Err != nil {
		if gophercloud.ResponseCodeIs(res.Err, http.StatusNotFound) || gophercloud.ResponseCodeIs(res.Err, http.StatusUnauthorized) {
			return nil, errOSNotFound{"token"}
		}
		return nil, fmt.Errorf("validate token: %w", res.Err)
	}
	tok, err := res.ExtractToken()
	if err != nil {
		return nil, fmt.Errorf("extract token: %w", err)
	}
	proj, err := res.ExtractProject()
	if err != nil {
		return nil, fmt.Errorf("extract project: %w", err)
	}
	user, _ := res.ExtractUser()
	roles, _ := res.ExtractRoles()
	cat, _ := res.ExtractServiceCatalog()
	caller := osCaller{ProjectID: "", ExpiresAt: tok.ExpiresAt, TokenID: token, IssuerHost: hostOf(c.keystoneURL)}
	if proj != nil && proj.ID != "" {
		caller.ProjectID = proj.ID
		caller.ProjectName = proj.Name
		caller.ScopeProject = true
	}
	if dom, _ := res.ExtractDomain(); dom != nil && dom.ID != "" {
		caller.ScopeDomain = true
	}
	if user != nil {
		caller.UserName = user.Name
		caller.UserID = user.ID
	}
	for _, r := range roles {
		caller.Roles = append(caller.Roles, r.Name)
	}
	return &osLiveSession{cli: c, provider: p, identity: ic, catalog: cat, caller: caller}, nil
}

func (s *osLiveSession) Caller() osCaller { return s.caller }

func (s *osLiveSession) computeClient() (*gophercloud.ServiceClient, error) {
	if s.catalog == nil {
		return nil, fmt.Errorf("token has no service catalog (unscoped token?)")
	}
	url, err := openstack.V3EndpointURL(s.catalog, gophercloud.EndpointOpts{
		Type:         "compute",
		Availability: s.cli.endpointAvl,
	})
	if err != nil {
		return nil, fmt.Errorf("locate nova endpoint: %w", err)
	}
	return &gophercloud.ServiceClient{ProviderClient: s.provider, Endpoint: ensureTrailingSlash(url)}, nil
}

func (s *osLiveSession) GetServer(ctx context.Context, instanceID string) (osServer, error) {
	cc, err := s.computeClient()
	if err != nil {
		return osServer{}, err
	}
	srv, err := servers.Get(ctx, cc, instanceID).Extract()
	if err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return osServer{}, errOSNotFound{"instance"}
		}
		return osServer{}, fmt.Errorf("get server: %w", err)
	}
	return osServer{TenantID: srv.TenantID, Status: srv.Status}, nil
}

// PasswordLogin performs a Keystone password grant (the ACCESS plane). When the
// caller specifies a project it scopes directly; otherwise it gets an unscoped
// token, lists the user's projects, and either auto-scopes (one project) or
// returns the list (several) for a picker.
func (c *openstackClient) PasswordLogin(ctx context.Context, in passwordAuth) (osCaller, []osProjectRef, error) {
	domain := in.DomainName
	if domain == "" {
		domain = "Default"
	}
	if in.ProjectID != "" || in.ProjectName != "" {
		caller, err := c.createToken(ctx, tokens.AuthOptions{
			Username: in.Username, Password: in.Password, DomainName: domain,
			Scope: scopeFor(in.ProjectID, in.ProjectName, domain),
		})
		return caller, nil, err
	}
	// No project chosen: unscoped auth, then enumerate the user's projects.
	unscoped, err := c.createToken(ctx, tokens.AuthOptions{Username: in.Username, Password: in.Password, DomainName: domain})
	if err != nil {
		return osCaller{}, nil, err
	}
	projects, err := c.listAuthProjects(ctx, unscoped.TokenID)
	if err != nil {
		return osCaller{}, nil, fmt.Errorf("list projects: %w", err)
	}
	switch len(projects) {
	case 0:
		return osCaller{}, nil, errOSNoProjects
	case 1:
		caller, err := c.createToken(ctx, tokens.AuthOptions{
			Username: in.Username, Password: in.Password, DomainName: domain,
			Scope: scopeFor(projects[0].ID, "", domain),
		})
		return caller, nil, err
	default:
		return osCaller{}, projects, nil
	}
}

// scopeFor builds a Keystone scope. A project ID is globally unique and MUST be
// supplied ALONE (gophercloud rejects ID+domain together); a project NAME needs
// its domain to disambiguate.
func scopeFor(projectID, projectName, domain string) tokens.Scope {
	if projectID != "" {
		return tokens.Scope{ProjectID: projectID}
	}
	if projectName != "" {
		return tokens.Scope{ProjectName: projectName, DomainName: domain}
	}
	return tokens.Scope{}
}

// createToken runs tokens.Create and extracts the scope, roles, and raw token.
func (c *openstackClient) createToken(ctx context.Context, opts tokens.AuthOptions) (osCaller, error) {
	p := &gophercloud.ProviderClient{}
	p.HTTPClient = *c.httpClient
	sc := &gophercloud.ServiceClient{ProviderClient: p, Endpoint: c.keystoneURL}
	res := tokens.Create(ctx, sc, &opts)
	if res.Err != nil {
		if gophercloud.ResponseCodeIs(res.Err, http.StatusUnauthorized) || gophercloud.ResponseCodeIs(res.Err, http.StatusForbidden) {
			return osCaller{}, errOSNotFound{"credentials"}
		}
		return osCaller{}, fmt.Errorf("keystone password auth: %w", res.Err)
	}
	tok, err := res.ExtractToken()
	if err != nil {
		return osCaller{}, fmt.Errorf("extract token: %w", err)
	}
	caller := osCaller{ExpiresAt: tok.ExpiresAt, TokenID: tok.ID, IssuerHost: hostOf(c.keystoneURL)}
	if proj, _ := res.ExtractProject(); proj != nil && proj.ID != "" {
		caller.ScopeProject = true
		caller.ProjectID = proj.ID
		caller.ProjectName = proj.Name
	}
	if dom, _ := res.ExtractDomain(); dom != nil && dom.ID != "" {
		caller.ScopeDomain = true
	}
	if user, _ := res.ExtractUser(); user != nil {
		caller.UserName = user.Name
		caller.UserID = user.ID
	}
	if roles, _ := res.ExtractRoles(); roles != nil {
		for _, r := range roles {
			caller.Roles = append(caller.Roles, r.Name)
		}
	}
	return caller, nil
}

// listAuthProjects enumerates the projects the token's user may scope to
// (GET /v3/auth/projects). Done with a raw request because gophercloud's
// projects.List is the admin "all projects" call, not the user's own.
func (c *openstackClient) listAuthProjects(ctx context.Context, token string) ([]osProjectRef, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.keystoneURL+"auth/projects", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth/projects: status %d", resp.StatusCode)
	}
	var body struct {
		Projects []osProjectRef `json:"projects"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return body.Projects, nil
}

func (s *osLiveSession) ResolveProject(ctx context.Context, projectID string) (osProject, error) {
	p, err := projects.Get(ctx, s.identity, projectID).Extract()
	if err != nil {
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return osProject{}, errOSNotFound{"project"}
		}
		return osProject{}, fmt.Errorf("get project: %w", err)
	}
	return osProject{Name: p.Name, DomainID: p.DomainID}, nil
}
