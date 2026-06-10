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
	DataDir              string            `yaml:"data_dir"`
	GRPCListen           string            `yaml:"grpc_listen"`
	HTTPListen           string            `yaml:"http_listen"`
	ClusterName          string            `yaml:"cluster_name"`
	Advertise            Advertise         `yaml:"advertise"`
	RelayAddrs           []string          `yaml:"relay_addrs"`
	PolicyFile           string            `yaml:"policy_file"`
	CertTTL              CertTTLConfig     `yaml:"cert_ttl"`
	GrantTTL             Duration          `yaml:"grant_ttl"`
	DefaultMaxSessionTTL Duration          `yaml:"default_max_session_ttl"`
	OIDC                 *OIDCConfig       `yaml:"oidc"`
	LocalUsers           []LocalUser       `yaml:"local_users"`
	AgentPolicy          AgentPolicyConfig `yaml:"agent_policy"`
	ArtifactPubkeyFile   string            `yaml:"artifact_pubkey_file"`
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

func (c *Config) CADir() string          { return filepath.Join(c.DataDir, "ca") }
func (c *Config) GrantKeyPath() string   { return filepath.Join(c.DataDir, "grant.key") }
func (c *Config) GrantKeyIDPath() string { return filepath.Join(c.DataDir, "grant.keyid") }
func (c *Config) TLSDir() string         { return filepath.Join(c.DataDir, "tls") }
func (c *Config) StatePath() string      { return filepath.Join(c.DataDir, "state.db") }
func (c *Config) AuditPath() string      { return filepath.Join(c.DataDir, "audit.jsonl") }
func (c *Config) ArtifactsDir() string   { return filepath.Join(c.DataDir, "artifacts") }
func (c *Config) RecordingsDir() string  { return filepath.Join(c.DataDir, "recordings") }

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
