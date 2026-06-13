package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

// The OpenStack client validates third-party Keystone tokens and reads Nova's
// authoritative view of an instance. It is the trust anchor for the enrollment
// plane: every credential is checked against the configured Keystone, and the
// instance→project mapping comes from Nova's server record, NEVER from the
// (attacker-controllable) vendordata body (security #1). See
// docs/openstack-integration.md §2, §5, §10, §15.

// osCaller is the validated identity behind a presented Keystone token.
type osCaller struct {
	UserName    string
	ProjectID   string
	ProjectName string
	Roles       []string
	ExpiresAt   time.Time
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
}

type cloudSession interface {
	Caller() osCaller
	// GetServer reads Nova's record for instanceID (security #1: authoritative
	// tenant_id). Returns a not-found error if the instance does not exist.
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
	caller := osCaller{ProjectID: "", ExpiresAt: tok.ExpiresAt}
	if proj != nil {
		caller.ProjectID = proj.ID
		caller.ProjectName = proj.Name
	}
	if user != nil {
		caller.UserName = user.Name
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
