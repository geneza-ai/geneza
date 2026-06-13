// Package gateway implements the Geneza control plane: enrollment, identity
// brokering, policy evaluation, certificate issuance, session brokering,
// fleet/version desired-state and the tamper-evident audit sink. One mTLS
// gRPC listener carries three trust levels (enforced per-RPC by the auth
// interceptor); a separate HTTPS listener serves artifact blobs and the
// bootstrap reconcile loop. The gateway never holds the artifact signing key
// and never carries session payload — it brokers and authorizes only.
package gateway

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"osie.cloud/geneza/internal/types"
)

// Duration decodes YAML strings like "8h30m" via time.ParseDuration.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string like \"8h\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

// Advertise lists the SANs stamped into the gateway/relay server certs.
type Advertise struct {
	DNSNames []string `yaml:"dns_names"`
	IPs      []string `yaml:"ips"`
}

type CertTTLConfig struct {
	Node Duration `yaml:"node"`
	User Duration `yaml:"user"`
}

type OIDCConfig struct {
	Issuer        string `yaml:"issuer"`
	ClientID      string `yaml:"client_id"`
	UsernameClaim string `yaml:"username_claim"`
	GroupsClaim   string `yaml:"groups_claim"`
}

type LocalUser struct {
	Username       string   `yaml:"username"`
	PasswordBcrypt string   `yaml:"password_bcrypt"`
	Groups         []string `yaml:"groups"`
}

// AgentPolicyConfig mirrors types.AgentPolicy with YAML tags (the shared type
// only carries JSON tags and must not be modified).
type AgentPolicyConfig struct {
	ForbidDetach    bool   `yaml:"forbid_detach"`
	MaxSessions     uint32 `yaml:"max_sessions"`
	MaxDetached     uint32 `yaml:"max_detached"`
	RingBufferBytes uint32 `yaml:"ring_buffer_bytes"`
	DetachedTTLSec  uint32 `yaml:"detached_ttl_sec"`
	IdleReapSec     uint32 `yaml:"idle_reap_sec"`
}

func (a AgentPolicyConfig) toTypes() types.AgentPolicy {
	return types.AgentPolicy{
		ForbidDetach:    a.ForbidDetach,
		MaxSessions:     a.MaxSessions,
		MaxDetached:     a.MaxDetached,
		RingBufferBytes: a.RingBufferBytes,
		DetachedTTLSec:  a.DetachedTTLSec,
		IdleReapSec:     a.IdleReapSec,
	}
}

// Config is the gateway YAML configuration. See
// internal/gateway/testdata/gateway.example.yaml for a commented example.
type Config struct {
	DataDir     string    `yaml:"data_dir"`
	GRPCListen  string    `yaml:"grpc_listen"`
	HTTPListen  string    `yaml:"http_listen"`
	ClusterName string    `yaml:"cluster_name"`
	Advertise   Advertise `yaml:"advertise"`
	RelayAddrs  []string  `yaml:"relay_addrs"`
	// RelayDataAddrs is where agents send WireGuard data-plane UDP (the blind
	// DERP-lite forwarder). Distinct from relay_addrs (TCP rendezvous) because
	// the data port (7404) may be reached on a different address — e.g. an
	// internal address for same-site agents vs the public FQDN for rendezvous.
	// Empty falls back to host(relay_addrs[0]):RelayDataPort.
	RelayDataAddrs []string `yaml:"relay_data_addrs"`
	// RelaySharedSecret is the coturn-style REST shared secret the gateway uses to
	// MINT ephemeral TURN credentials; it MUST match the relay's shared_secret.
	RelaySharedSecret string `yaml:"relay_shared_secret"`
	// RelayRealm is the TURN realm (default "geneza"); MUST match the relay.
	RelayRealm           string            `yaml:"relay_realm"`
	PolicyFile           string            `yaml:"policy_file"`
	CertTTL              CertTTLConfig     `yaml:"cert_ttl"`
	GrantTTL             Duration          `yaml:"grant_ttl"`
	DefaultMaxSessionTTL Duration          `yaml:"default_max_session_ttl"`
	ReauthInterval       Duration          `yaml:"reauth_interval"`   // continuous-authz sweep period (default 15s)
	MetricsRetention     Duration          `yaml:"metrics_retention"` // embedded-TSDB retention (default 15d)
	OIDC                 *OIDCConfig       `yaml:"oidc"`
	LocalUsers           []LocalUser       `yaml:"local_users"`
	AgentPolicy          AgentPolicyConfig `yaml:"agent_policy"`
	ArtifactPubkeyFile   string            `yaml:"artifact_pubkey_file"`
	// RootKeysFile points at the offline-signed root-keys.json (TUF-lite trust
	// root authorizing the current release-signing key SET). When set, the
	// gateway attaches it to every desired-version response so agents verify
	// manifests against the rotatable signing set anchored to their pinned root
	// key. The file is re-read per request, so rotating the fleet's trust is a
	// single atomic file swap — the gateway holds no private key either way.
	RootKeysFile string `yaml:"root_keys_file"`
	// RootPubkeyFile is the PUBLIC half of the TUF-lite root key (safe to serve).
	// The curl|bash installer fetches it and FINGERPRINT-checks it against the
	// --root-fp the operator pasted, so a compromised gateway cannot swap the
	// trust anchor at bootstrap (verify-on-first-use, not blind trust-on-first-use).
	RootPubkeyFile string `yaml:"root_pubkey_file"`
	// DNSZone is the tenant DNS suffix machine names live under (default
	// "geneza"): <machine>.<DNSZone> resolves to the machine's overlay IP, gated
	// by policy. The `geneza vpn` client points its split-DNS resolver here.
	DNSZone string `yaml:"dns_zone"`
	// InstallDir holds the stage-1 binaries the curl|bash installer serves:
	// geneza-bootstrap-<os>-<arch> and geneza-agent-<os>-<arch>. The agent copy is
	// used only to run `enroll`; the first WORKER binary is pulled by the
	// bootstrap through the full rooted update chain. Empty = installer disabled.
	InstallDir string `yaml:"install_dir"`
	// Workspaces declares the tenants this gateway hosts (multi-tenancy). Empty =
	// a single synthesized "default" workspace whose policy is PolicyFile and whose
	// membership is open (single-tenant behavior, unchanged). Each workspace has
	// its own policy and membership; a user's workspace is validated against this
	// at login and is then carried in the cert.
	Workspaces []WorkspaceConfig `yaml:"workspaces"`
	// AuditSink optionally mirrors every audit record to an append-only
	// off-box destination (the only real tamper-evidence against a host
	// compromise that can rewrite the local chain). Empty = local chain only.
	AuditSink AuditSinkConfig `yaml:"audit_sink"`
	// Console optionally enables the web control panel (plain-HTTP listener,
	// TLS terminated by a front proxy). Empty Listen = disabled.
	Console ConsoleConfig `yaml:"console"`
	// Clouds is the OpenStack (and future cloud) registry: each entry is one
	// Keystone Geneza validates tokens against, keyed by a STABLE operator slug
	// (the service-uid — NOT the Keystone FQDN, which is mutable and lives in
	// KeystoneURL). The slug rides the vendordata path suffix as a routing key
	// and qualifies every binding (openstack:project:<service-uid>:<uuid>). See
	// docs/openstack-integration.md §7.
	Clouds map[string]CloudConfig `yaml:"clouds,omitempty"`
}

// CloudConfig is one entry in the clouds registry (§7): a Keystone trust anchor
// plus the policy for VMs that enroll through it. The map key (service-uid) is
// the stable identity; this struct carries the mutable details.
type CloudConfig struct {
	Kind        string `yaml:"kind"`         // "openstack" (only kind supported today)
	KeystoneURL string `yaml:"keystone_url"` // identity v3 base, e.g. https://kc:5000/v3
	// EndpointInterface selects which catalog endpoint (public|internal|admin)
	// Geneza uses for the Nova callback; defaults to "public".
	EndpointInterface string `yaml:"endpoint_interface,omitempty"`
	// ServiceProject is the Keystone project name a Nova service token is scoped
	// to (default "service"); the enrollment guard requires the presented token
	// be scoped to it (security #4).
	ServiceProject string `yaml:"service_project,omitempty"`
	// RequireNovaServiceToken is FORCED true for kind:openstack (security #4):
	// the enrollment plane accepts only a Nova service-scoped token, never an
	// arbitrary tenant token. Explicitly setting it false is a load error.
	RequireNovaServiceToken bool `yaml:"require_nova_service_token,omitempty"`
	// AutoProvision: an unbound but token-valid project gets its OWN isolated
	// workspace (§6). Default false (operator pre-binds); the lab sets true.
	AutoProvision bool `yaml:"auto_provision,omitempty"`
	// AutoApprove skips the human admission gate for VMs enrolled via this cloud
	// (PoC convenience; per-project isolation bounds the blast radius). Default
	// false (PENDING until approved).
	AutoApprove bool `yaml:"auto_approve,omitempty"`
	// DefaultLabels are stamped on every node enrolled through this cloud.
	DefaultLabels map[string]string `yaml:"default_labels,omitempty"`
	// RoleMap translates Keystone roles to Geneza policy roles on the ACCESS
	// plane (§8/§13, design-only today). Unused by the enrollment plane.
	RoleMap map[string]string `yaml:"role_map,omitempty"`
	// CAFile is a PEM bundle Geneza trusts for the Keystone/Nova TLS connection.
	CAFile string `yaml:"ca_file,omitempty"`
	// InsecureSkipVerify disables TLS verification of Keystone/Nova — LAB ONLY.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify,omitempty"`
	// JoinTokenTTL bounds the minted join token (default 1h, covers boot).
	JoinTokenTTL Duration `yaml:"join_token_ttl,omitempty"`
	// GatewayURL is the base HTTPS URL an enrolling VM uses to reach Geneza
	// (install.sh, stage-1 binaries, ca-roots, updates). Falls back to the
	// vendordata request's own Host when empty.
	GatewayURL string `yaml:"gateway_url,omitempty"`
	// GatewayGRPC is the host:port the agent dials for the enroll RPC; falls back
	// to host(GatewayURL):7401.
	GatewayGRPC string `yaml:"gateway_grpc,omitempty"`
}

func (c CloudConfig) endpointInterface() string {
	if c.EndpointInterface == "" {
		return "public"
	}
	return c.EndpointInterface
}

func (c CloudConfig) serviceProject() string {
	if c.ServiceProject == "" {
		return "service"
	}
	return c.ServiceProject
}

func (c CloudConfig) joinTokenTTL() time.Duration {
	if c.JoinTokenTTL == 0 {
		return time.Hour
	}
	return c.JoinTokenTTL.D()
}

// WorkspaceConfig declares one tenant. A user is a MEMBER of the workspace iff
// their username is in Members OR one of their IdP groups is in MemberGroups; a
// workspace with NEITHER set is OPEN (every authenticated user) — which is what
// keeps the synthesized "default" workspace single-tenant-compatible.
type WorkspaceConfig struct {
	ID           string   `yaml:"id"`
	Name         string   `yaml:"name,omitempty"`
	PolicyFile   string   `yaml:"policy_file,omitempty"`   // defaults to the top-level policy_file
	OverlayCIDR  string   `yaml:"overlay_cidr,omitempty"`  // defaults to 100.64.0.0/24
	Members      []string `yaml:"members,omitempty"`       // usernames
	MemberGroups []string `yaml:"member_groups,omitempty"` // IdP groups
	// Bindings are cloud-qualified SOURCE bindings (§6) that resolve to this
	// workspace, e.g. "openstack:project:kolla1:<project-uuid>". Declaring them
	// here is the config-driven equivalent of an operator pre-binding a project:
	// a VM in that project enrolls into THIS workspace, and (cross-source) so do
	// this workspace's member users — one binding serves both planes.
	Bindings []string `yaml:"bindings,omitempty"`
}

// open reports whether the workspace admits any authenticated user (no explicit
// membership configured).
func (w WorkspaceConfig) open() bool { return len(w.Members) == 0 && len(w.MemberGroups) == 0 }

// ConsoleConfig configures the web control panel.
type ConsoleConfig struct {
	Listen       string `yaml:"listen"`         // e.g. ":7406"; empty = disabled
	StaticDir    string `yaml:"static_dir"`     // built SPA (dist/) to serve at /
	ExternalURL  string `yaml:"external_url"`   // public origin, e.g. https://geneza.example.com
	OIDCClientID string `yaml:"oidc_client_id"` // browser OIDC client; defaults to OIDC.ClientID
}

func (c *Config) ConsoleEnabled() bool { return c.Console.Listen != "" }

// dnsZone is the tenant DNS suffix (default "geneza").
func (c *Config) dnsZone() string {
	if c.DNSZone == "" {
		return "geneza"
	}
	return c.DNSZone
}

// AuditSinkConfig configures the off-box audit mirror.
//
//	type: "" | "none" — local chain only (default)
//	type: "file"      — append each record to Path (use a different mount/host)
//	type: "http"      — POST each record (JSON line) to URL (e.g. a SIEM intake)
type AuditSinkConfig struct {
	Type string `yaml:"type"`
	Path string `yaml:"path"`
	URL  string `yaml:"url"`
}

// LoadConfig reads, defaults and validates the gateway configuration.
// Unknown YAML keys are rejected so typos fail loudly rather than silently
// weakening the configuration.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := unmarshalStrict(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func unmarshalStrict(b []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	return dec.Decode(out)
}

func (c *Config) applyDefaults() {
	if c.GRPCListen == "" {
		c.GRPCListen = ":7401"
	}
	if c.HTTPListen == "" {
		c.HTTPListen = ":7402"
	}
	if c.CertTTL.Node == 0 {
		c.CertTTL.Node = Duration(24 * time.Hour)
	}
	if c.CertTTL.User == 0 {
		c.CertTTL.User = Duration(8 * time.Hour)
	}
	if c.GrantTTL == 0 {
		c.GrantTTL = Duration(2 * time.Minute)
	}
	if c.DefaultMaxSessionTTL == 0 {
		c.DefaultMaxSessionTTL = Duration(12 * time.Hour)
	}
	if c.OIDC != nil {
		if c.OIDC.UsernameClaim == "" {
			c.OIDC.UsernameClaim = "preferred_username"
		}
		if c.OIDC.GroupsClaim == "" {
			c.OIDC.GroupsClaim = "groups"
		}
	}
	// Single-tenant compatibility: no workspaces declared = one open "default"
	// workspace whose policy is the top-level policy_file.
	if len(c.Workspaces) == 0 {
		c.Workspaces = []WorkspaceConfig{{ID: defaultWorkspace, Name: "Default"}}
	}
	for i := range c.Workspaces {
		if c.Workspaces[i].PolicyFile == "" {
			c.Workspaces[i].PolicyFile = c.PolicyFile
		}
		if c.Workspaces[i].OverlayCIDR == "" {
			c.Workspaces[i].OverlayCIDR = defaultOverlayCIDR
		}
	}
	// Clouds registry (§7). require_nova_service_token is NON-OVERRIDABLE for
	// kind:openstack (security #4): the enrollment plane must only ever accept a
	// Nova service-scoped token, so we force it true here regardless of the file.
	for uid, cl := range c.Clouds {
		if cl.Kind == "" {
			cl.Kind = "openstack"
		}
		cl.RequireNovaServiceToken = true
		c.Clouds[uid] = cl
	}
}

func (c *Config) validate() error {
	if c.DataDir == "" {
		return fmt.Errorf("data_dir is required")
	}
	if c.ClusterName == "" {
		return fmt.Errorf("cluster_name is required")
	}
	for _, ip := range c.Advertise.IPs {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("advertise.ips: invalid IP %q", ip)
		}
	}
	if c.OIDC != nil {
		if c.OIDC.Issuer == "" || c.OIDC.ClientID == "" {
			return fmt.Errorf("oidc: issuer and client_id are required when the oidc block is present")
		}
	}
	for i, u := range c.LocalUsers {
		if u.Username == "" || u.PasswordBcrypt == "" {
			return fmt.Errorf("local_users[%d]: username and password_bcrypt are required", i)
		}
	}
	seen := map[string]bool{}
	hasDefault := false
	for i, w := range c.Workspaces {
		if w.ID == "" {
			return fmt.Errorf("workspaces[%d]: id is required", i)
		}
		if seen[w.ID] {
			return fmt.Errorf("workspaces: duplicate id %q", w.ID)
		}
		seen[w.ID] = true
		if w.ID == defaultWorkspace {
			hasDefault = true
		}
		if w.PolicyFile == "" {
			return fmt.Errorf("workspaces[%q]: policy_file is required (no top-level policy_file to inherit)", w.ID)
		}
	}
	if !hasDefault {
		return fmt.Errorf("workspaces: a %q workspace is required (legacy certs + break-glass resolve to it)", defaultWorkspace)
	}
	// Clouds registry (§7). Reject configurations that would break the trust
	// model: an unknown kind, a missing Keystone, or — critically — two service
	// uids sharing one Keystone (security #18: that collapses the routing≠auth
	// guarantee and lets a token-holder choose which namespace to bind into).
	keystoneSeen := map[string]string{}
	for uid, cl := range c.Clouds {
		if uid == "" {
			return fmt.Errorf("clouds: empty service-uid key")
		}
		if cl.Kind != "openstack" {
			return fmt.Errorf("clouds[%q]: unsupported kind %q (only \"openstack\")", uid, cl.Kind)
		}
		if cl.KeystoneURL == "" {
			return fmt.Errorf("clouds[%q]: keystone_url is required", uid)
		}
		ks := strings.TrimRight(cl.KeystoneURL, "/")
		if other, dup := keystoneSeen[ks]; dup {
			return fmt.Errorf("clouds[%q] and clouds[%q] share keystone_url %q: forbidden — a shared Keystone breaks routing≠auth (security #18); give each its own Keystone or merge them", uid, other, cl.KeystoneURL)
		}
		keystoneSeen[ks] = uid
		switch cl.endpointInterface() {
		case "public", "internal", "admin":
		default:
			return fmt.Errorf("clouds[%q]: endpoint_interface must be public|internal|admin", uid)
		}
	}
	return nil
}

// validateForServe checks the parts only the daemon needs (issue-user-cert
// and audit-verify must work with a partial config).
func (c *Config) validateForServe() error {
	if c.PolicyFile == "" {
		return fmt.Errorf("policy_file is required to serve")
	}
	if len(c.RelayAddrs) == 0 {
		return fmt.Errorf("relay_addrs must list at least one relay")
	}
	for _, a := range c.RelayAddrs {
		if _, _, err := net.SplitHostPort(a); err != nil {
			return fmt.Errorf("relay_addrs: %q is not host:port: %w", a, err)
		}
	}
	return nil
}

// Filesystem layout under data_dir.

func (c *Config) CADir() string           { return filepath.Join(c.DataDir, "ca") }
func (c *Config) GrantKeyPath() string    { return filepath.Join(c.DataDir, "grant.key") }
func (c *Config) GrantKeyIDPath() string  { return filepath.Join(c.DataDir, "grant.keyid") }
func (c *Config) TLSDir() string          { return filepath.Join(c.DataDir, "tls") }
func (c *Config) StatePath() string       { return filepath.Join(c.DataDir, "state.db") }
func (c *Config) AuditPath() string       { return filepath.Join(c.DataDir, "audit.jsonl") }
func (c *Config) AuditKeyPath() string    { return filepath.Join(c.DataDir, "audit.key") }
func (c *Config) AuditCheckpoint() string { return filepath.Join(c.DataDir, "audit.jsonl.chk") }
func (c *Config) ArtifactsDir() string    { return filepath.Join(c.DataDir, "artifacts") }
func (c *Config) RecordingsDir() string   { return filepath.Join(c.DataDir, "recordings") }
func (c *Config) MetricsDir() string      { return filepath.Join(c.DataDir, "metrics-tsdb") }

func (c *Config) gatewayCertPath() string { return filepath.Join(c.TLSDir(), "gateway.crt") }
func (c *Config) gatewayKeyPath() string  { return filepath.Join(c.TLSDir(), "gateway.key") }
func (c *Config) relayCertPath() string   { return filepath.Join(c.TLSDir(), "relay.crt") }
func (c *Config) relayKeyPath() string    { return filepath.Join(c.TLSDir(), "relay.key") }

func (c *Config) advertiseIPs() []net.IP {
	out := make([]net.IP, 0, len(c.Advertise.IPs))
	for _, s := range c.Advertise.IPs {
		if ip := net.ParseIP(s); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}
