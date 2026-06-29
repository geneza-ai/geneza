// Package controller implements the Geneza control plane: enrollment, identity
// brokering, policy evaluation, certificate issuance, session brokering,
// fleet/version desired-state and the tamper-evident audit sink. One mTLS
// gRPC listener carries three trust levels (enforced per-RPC by the auth
// interceptor); a separate HTTPS listener serves artifact blobs and the
// bootstrap reconcile loop. The controller never holds the artifact signing key
// and never carries session payload — it brokers and authorizes only.
package controller

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"geneza.io/internal/defaults"
	"geneza.io/internal/keysource"
	"geneza.io/internal/webpki"

	"gopkg.in/yaml.v3"

	"geneza.io/internal/types"
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

// PresenceConfig governs the continuous-presence factor. TTL == 0
// disables presence enforcement globally (back-compat); otherwise a presence-
// required session whose heartbeat goes stale (no beat for > TTL) is dropped by
// the continuous sweep. AllowSoftware is a *bool so an omitted value defaults to
// true (lab); set `allow_software: false` once a real hardware factor exists.
type PresenceConfig struct {
	HeartbeatInterval Duration `yaml:"heartbeat_interval,omitempty"`
	TTL               Duration `yaml:"ttl,omitempty"`
	AllowSoftware     *bool    `yaml:"allow_software,omitempty"`
}

// SoftwareAllowed reports whether the software presence stub is permitted globally
// (the per-principal gate still refuses it once a hardware credential is enrolled).
func (p PresenceConfig) SoftwareAllowed() bool { return p.AllowSoftware == nil || *p.AllowSoftware }

// Advertise lists the SANs stamped into the controller/relay server certs.
type Advertise struct {
	DNSNames []string `yaml:"dns_names"`
	IPs      []string `yaml:"ips"`
}

type CertTTLConfig struct {
	Node Duration `yaml:"node"`
	User Duration `yaml:"user"`
}

// AgentReleaseConfig controls pulling the signed geneza-node release archives
// (agent + bootstrap) from GitHub into InstallDir.
type AgentReleaseConfig struct {
	Pull    bool     `yaml:"pull"`    // pull on startup (and on Refresh, if set)
	Tag     string   `yaml:"tag"`     // pin a release tag; empty = latest
	Refresh Duration `yaml:"refresh"` // re-pull interval; 0 = startup only
}

// VulnFeedConfig selects and schedules the CVE-affectedness vulnerability feed.
// Unset (Source empty) = no feed: an inventory report still stores the SBOM and
// re-indexes components, but no advisories are synced and no verdicts are written
// — today's behaviour. The open sources carry the SAME OSV records:
//   - "osv_dir":  Dir is a local directory of OSV JSON (offline/airgapped).
//   - "osv_bulk": BulkURL is the OSV.dev GCS bucket base (empty = the live
//     bucket); Ecosystems names the per-ecosystem all.zip files to fetch
//     (empty = the built-in distro + language set).
//
// The paid source is a config-only drop-in upgrade behind the same seam:
//   - "geneza-paid": PaidEndpoint serves a signed, monotonically-versioned curated
//     advisory bundle the client verifies against PaidPubKey (the pinned vendor
//     ed25519 public key, base64) before ingesting, authenticating with
//     PaidLicenseKey. The core stays fully functional on the open feeds alone; the
//     paid feed is purely additive and off unless selected.
//
// When a source is set, the controller runs a debounced, advisory-lock-shared daily
// sync chore (every SyncInterval, default 6h) that fetches the feed and re-matches
// only the changed advisories' nodes.
//
// Two optional overlays ride the same chore, each off unless configured:
//   - VEXDir is a directory of OpenVEX JSON; a not_affected statement for a
//     (CVE, purl) downgrades that component's verdict with the recorded
//     justification. Documents under the root are global; documents under a
//     "<VEXDir>/<workspace>" subdirectory scope to that workspace.
//   - KEV/EPSS overlay the prioritization signal onto verdicts: KEVURL is the CISA
//     Known-Exploited-Vulnerabilities catalog, EPSSURL the FIRST EPSS scores
//     export. Each defaults to its public endpoint when set to "default", is off
//     when empty, and is fetched + applied to existing node_cve rows on each sync.
type VulnFeedConfig struct {
	Source       string   `yaml:"source"`                  // "" (off) | "osv_dir" | "osv_bulk" | "geneza-paid"
	Dir          string   `yaml:"dir,omitempty"`           // osv_dir: directory of OSV JSON
	BulkURL      string   `yaml:"bulk_url,omitempty"`      // osv_bulk: GCS bucket base; empty = live OSV.dev
	Ecosystems   []string `yaml:"ecosystems,omitempty"`    // osv_bulk: ecosystems to fetch; empty = built-in set
	PaidEndpoint string   `yaml:"paid_endpoint,omitempty"` // geneza-paid: signed-bundle URL
	PaidLicense  string   `yaml:"paid_license_key,omitempty"`
	PaidPubKey   string   `yaml:"paid_pubkey,omitempty"`   // geneza-paid: pinned vendor ed25519 public key, base64
	SyncInterval Duration `yaml:"sync_interval,omitempty"` // chore period; 0 = default 6h
	VEXDir       string   `yaml:"vex_dir,omitempty"`       // directory of OpenVEX JSON; empty = no suppression
	KEVURL       string   `yaml:"kev_url,omitempty"`       // CISA KEV feed; "default" = public URL; empty = off
	EPSSURL      string   `yaml:"epss_url,omitempty"`      // FIRST EPSS feed; "default" = public URL; empty = off
}

// Enabled reports whether a feed source is configured (so the sync chore runs).
func (v VulnFeedConfig) Enabled() bool { return v.Source != "" }

// EnrichEnabled reports whether either prioritization feed is configured, so the
// enrichment pass runs only when a KEV or EPSS source is set.
func (v VulnFeedConfig) EnrichEnabled() bool { return v.KEVURL != "" || v.EPSSURL != "" }

// paidPubKey decodes the pinned vendor ed25519 public key from its base64 config
// value, validating its length so a malformed key fails at config load rather than
// at the first bundle verify. An empty value is an error: the paid feed cannot
// verify a signature without a pinned key, and running it unpinned would defeat the
// anti-suppression guarantee.
func (v VulnFeedConfig) paidPubKey() (ed25519.PublicKey, error) {
	if v.PaidPubKey == "" {
		return nil, fmt.Errorf("a pinned vendor public key is required")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v.PaidPubKey))
	if err != nil {
		return nil, fmt.Errorf("not valid base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
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
	// Subject is the stable principal id used everywhere durable (member key,
	// suspension, presence, the cert Subject claim). Defaults to Username, so a
	// rename is editing Username while keeping Subject — the rename then can't fork
	// the identity or slip a suspension. Set it explicitly to decouple the two.
	Subject string `yaml:"subject"`
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

// defaultRegion is the canonical region id for a single-region deployment. An
// empty region is normalized to this so the "<expiry>:<region>:<id>" TURN
// username never has an empty middle segment (which would be parse-ambiguous).
const defaultRegion = "default"

// canonicalRegion normalizes an empty region to the default region id.
func canonicalRegion(region string) string {
	if region == "" {
		return defaultRegion
	}
	return region
}

// RegionSecret is one region's TURN-minting secret. Current is the active
// minting secret; the relay validates against this same single key (pion/turn
// hands its AuthHandler one integrity key per username), so rotating a region's
// secret is a synchronized flag-day — controller and relays swap Current together.
type RegionSecret struct {
	Current string `yaml:"current"`
}

// KeySourceConfig selects where one of the two online crown-jewel keys (the
// issuing-CA key and the grant key) is held. An absent or backend-empty block
// means the on-disk key under data_dir (the default, unchanged behavior). With
// backend: pkcs11 the key lives on an HSM/SoftHSM/YubiHSM token and signing runs
// on the token — the private bytes never enter the controller, so a host compromise
// cannot exfiltrate the key.
//
// The CA key is ECDSA P-256 and works on every PKCS#11 token. The grant key is
// Ed25519; backing it on a token needs both CKM_EDDSA on the token and Ed25519
// support in the PKCS#11 binding, and the binding does not surface Edwards keys
// yet — so a pkcs11 grant key is not usable today and the file backend stays the
// default. The CA pkcs11 path is fully supported.
type KeySourceConfig struct {
	// Backend is "" / "file" (on-disk PEM, default) or "pkcs11".
	Backend string `yaml:"backend,omitempty"`
	// Module is the PKCS#11 shared-library path (backend: pkcs11).
	Module string `yaml:"module,omitempty"`
	// TokenLabel selects the token by label; or use Slot.
	TokenLabel string `yaml:"token_label,omitempty"`
	// Slot selects the token by slot number (used when token_label is empty).
	Slot *int `yaml:"slot,omitempty"`
	// PIN is the token user PIN.
	PIN string `yaml:"pin,omitempty"`
	// KeyLabel finds the private key object by CKA_LABEL.
	KeyLabel string `yaml:"key_label,omitempty"`
	// KeyID finds the private key object by CKA_ID (hex).
	KeyID string `yaml:"key_id,omitempty"`
}

// spec converts the config block into a keysource.Spec. defaultPath is the
// on-disk key file used when the backend is file/empty and no explicit path is
// configured (file-backed keys live under data_dir, so the path is fixed, not
// operator-set; only the backend choice is exposed in YAML).
func (k KeySourceConfig) spec(defaultPath string) keysource.Spec {
	s := keysource.Spec{
		Backend:    k.Backend,
		Path:       defaultPath,
		Module:     k.Module,
		TokenLabel: k.TokenLabel,
		Slot:       k.Slot,
		PIN:        k.PIN,
		KeyLabel:   k.KeyLabel,
		KeyID:      k.KeyID,
	}
	return s
}

// usesPKCS11 reports whether this block selects the token backend.
func (k KeySourceConfig) usesPKCS11() bool { return k.Backend == keysource.BackendPKCS11 }

// validate checks a key-source block. file/empty needs nothing; pkcs11 needs a
// module, a token selector, and a key selector — a half-configured token would
// otherwise fail only at startup with a less obvious error.
func (k KeySourceConfig) validate(what string) error {
	switch k.Backend {
	case "", keysource.BackendFile:
		return nil
	case keysource.BackendPKCS11:
		if k.Module == "" {
			return fmt.Errorf("%s.module is required for backend: pkcs11", what)
		}
		if k.TokenLabel == "" && k.Slot == nil {
			return fmt.Errorf("%s: token_label or slot is required for backend: pkcs11", what)
		}
		if k.KeyLabel == "" && k.KeyID == "" {
			return fmt.Errorf("%s: key_label or key_id is required for backend: pkcs11", what)
		}
		return nil
	default:
		return fmt.Errorf("%s.backend %q is invalid (want \"file\" or \"pkcs11\")", what, k.Backend)
	}
}

// Config is the controller YAML configuration. See
// internal/controller/testdata/controller.example.yaml for a commented example.
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
	// RelaySharedSecret is the coturn-style REST shared secret the controller uses to
	// MINT ephemeral TURN credentials; it MUST match the relay's shared_secret.
	// Single-region shorthand: it is synthesized into RelaySecrets["default"] at
	// load so the multi-region minting path has one uniform source.
	RelaySharedSecret string `yaml:"relay_shared_secret"`
	// RelaySecrets is the per-region coturn-REST secret used to mint TURN
	// credentials, keyed by region id. Current is the region's active minting
	// secret; the region's relays validate against the same single key, so a
	// rotation is a synchronized flag-day. Empty region canonicalizes to "default".
	RelaySecrets map[string]RegionSecret `yaml:"relay_secrets,omitempty"`
	// RelayRealm is the TURN realm (default "geneza"); MUST match the relay.
	RelayRealm string `yaml:"relay_realm"`
	// SessionP2P opts sessions into the session-scoped ICE signaling path (the
	// controller mints session TURN creds, registers the SessionSignal broker entry,
	// and the client/agent run an ICE handshake alongside the relay session). It
	// is the staging flag for the p2p session transport; default OFF keeps every
	// session on the relay floor unchanged. The data transport swap is not yet
	// wired — with this flag the ICE path only establishes + reports its pair.
	SessionP2P           bool          `yaml:"session_p2p"`
	PolicyFile           string        `yaml:"policy_file"`
	CertTTL              CertTTLConfig `yaml:"cert_ttl"`
	GrantTTL             Duration      `yaml:"grant_ttl"`
	DefaultMaxSessionTTL Duration      `yaml:"default_max_session_ttl"`
	ReauthInterval       Duration      `yaml:"reauth_interval"` // continuous-authz sweep period (default 15s)
	// MetricsURL points at an external VictoriaMetrics (e.g. http://victoriametrics:8428).
	// The controller proxies agent metric pushes to its import endpoint and console
	// PromQL to its query API; empty = metrics disabled. Retention is configured on
	// VictoriaMetrics itself (-retentionPeriod), not here.
	MetricsURL string `yaml:"metrics_url"`
	// Storage selects the backend for the controller's general-purpose blob store
	// (recordings today; other per-node artifacts later). Empty / "fs" stores blobs
	// on local disk (the default, unchanged); "s3" stores them in an S3-compatible
	// object store. Either way the controller can still read older local blobs.
	Storage StorageConfig `yaml:"storage,omitempty"`
	// MetricsRetention is accepted but ignored — kept so existing configs still
	// parse under strict (KnownFields) loading. Retention now lives on the external
	// metrics backend.
	MetricsRetention   Duration          `yaml:"metrics_retention"`
	Presence           PresenceConfig    `yaml:"presence"` // continuous-presence factor
	OIDC               *OIDCConfig       `yaml:"oidc"`
	LocalUsers         []LocalUser       `yaml:"local_users"`
	AgentPolicy        AgentPolicyConfig `yaml:"agent_policy"`
	ArtifactPubkeyFile string            `yaml:"artifact_pubkey_file"`
	// RootKeysFile points at the offline-signed root-keys.json (TUF-lite trust
	// root authorizing the current release-signing key SET). When set, the
	// controller attaches it to every desired-version response so agents verify
	// manifests against the rotatable signing set anchored to their pinned root
	// key. The file is re-read per request, so rotating the fleet's trust is a
	// single atomic file swap — the controller holds no private key either way.
	RootKeysFile string `yaml:"root_keys_file"`
	// RootPubkeyFile is the PUBLIC half of the TUF-lite root key (safe to serve).
	// The curl|bash installer fetches it and FINGERPRINT-checks it against the
	// --root-fp the operator pasted, so a compromised controller cannot swap the
	// trust anchor at bootstrap (verify-on-first-use, not blind trust-on-first-use).
	RootPubkeyFile string `yaml:"root_pubkey_file"`
	// DNSZone is the tenant DNS suffix machine names live under (default
	// "geneza"): <machine>.<DNSZone> resolves to the machine's overlay IP, gated
	// by policy. The `geneza vpn` client points its split-DNS resolver here.
	DNSZone string `yaml:"dns_zone"`
	// ManagedDomain optionally enables publicly-trusted certificates for an
	// operator-owned public domain (see docs/managed-domain-spec.md): the controller
	// mints a wildcard per workspace via ACME DNS-01. Empty base = disabled.
	ManagedDomain ManagedDomainConfig `yaml:"managed_domain,omitempty"`
	// InstallDir holds the stage-1 binaries the curl|bash installer serves:
	// geneza-bootstrap-<os>-<arch> and geneza-agent-<os>-<arch>. The agent copy is
	// used only to run `enroll`; the first WORKER binary is pulled by the
	// bootstrap through the full rooted update chain. Empty = installer disabled.
	InstallDir string `yaml:"install_dir"`
	// AgentRelease optionally keeps InstallDir populated by pulling the signed
	// geneza-node release archives from GitHub into it (so a containerized controller
	// serves enrollment without baking binaries in, and the agent version is
	// decoupled from the controller version). Disabled by default.
	AgentRelease AgentReleaseConfig `yaml:"agent_release"`
	// VulnFeed selects + schedules the CVE-affectedness vulnerability feed. Empty
	// Source = no feed (today's behaviour: SBOMs stored, no verdicts written).
	VulnFeed VulnFeedConfig `yaml:"vuln_feed,omitempty"`
	// Workspaces declares the tenants this controller hosts (multi-tenancy). Empty =
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
	// ClusterConsole optionally enables the cluster-operator (super-admin) read
	// plane on its OWN mTLS listener, served at /clusterconsole/v1. It is gated on the
	// break-glass cluster admin cert OR an OIDC login in the required cluster-admin
	// group, so it is kept off the broadly-reachable listeners. Empty Listen = disabled.
	ClusterConsole ClusterConsoleConfig `yaml:"cluster_console"`
	// AutoProvisionPolicyFile is the policy a dynamically-provisioned workspace
	// loads (both VM-enrollment and human access-plane auto-provision). It grants
	// by ROLE NAME (ws-admin/ws-member/ws-viewer) with NO user/group bindings,
	// because auto-provisioned members get their roles from store membership, not
	// policy bindings. Empty falls back to PolicyFile.
	AutoProvisionPolicyFile string `yaml:"auto_provision_policy_file,omitempty"`
	// Clouds is the OpenStack (and future cloud) registry: each entry is one
	// Keystone Geneza validates tokens against, keyed by a STABLE operator slug
	// (the service-uid — NOT the Keystone FQDN, which is mutable and lives in
	// KeystoneURL). The slug rides the vendordata path suffix as a routing key
	// and qualifies every binding (openstack:project:<service-uid>:<uuid>). See
	// docs/openstack-integration.md
	Clouds map[string]CloudConfig `yaml:"clouds,omitempty"`
	// StoreBackend selects the persistence engine. "" / "bbolt" is the
	// zero-dependency single-node default the controller has always run. "postgres"
	// selects the SQL store on a Postgres-wire server; "mariadb" / "mysql" select
	// it on a MySQL-protocol server. All three SQL backends are behaviourally
	// identical (the same JSON records, the same SERIALIZABLE invariants).
	StoreBackend string `yaml:"store,omitempty"`
	// StoreDSN is the connection string for the SQL backend. Postgres uses a libpq
	// URL ("postgres://user:pw@host:5432/geneza?sslmode=verify-full"); MariaDB/MySQL
	// use a Go MySQL DSN ("user:pw@tcp(host:3306)/geneza?parseTime=true&multiStatements=true").
	// Ignored for bbolt and never defaulted: a SQL backend with no DSN is a hard
	// error, never a silent localhost fallback.
	StoreDSN string `yaml:"store_dsn,omitempty"`
	// Router and Region are parsed now but only take effect once multi-controller
	// routing and regional cells exist. Selecting either against the single-node
	// bbolt store is refused at validation so a split-brain config fails loudly
	// instead of running. "" / "inproc" router and "" region are today's defaults.
	Router string `yaml:"router,omitempty"`
	Region string `yaml:"region,omitempty"`
	// ControllerID is this controller's stable identity in a multi-controller deployment:
	// the affinity-directory owner value, the per-controller bus subject, and the
	// audit label. Defaults to the hostname; in a multi-controller deploy each
	// controller MUST set a globally-unique value.
	ControllerID string `yaml:"controller_id,omitempty"`
	// ClusterControlListen optionally moves the controller↔relay control plane (the
	// relay registrar today) onto its OWN mTLS gRPC listener, so an operator can
	// firewall that channel to the relay/management subnet — independently of the
	// broadly-reachable agent/user channel on grpc_listen. The same cert-kind auth
	// still gates it (only relay certs may register). Empty keeps the registrar on
	// grpc_listen (the single-node default, byte-for-byte).
	ClusterControlListen string `yaml:"cluster_control_listen,omitempty"`
	// CAKeySource optionally backs the issuing-CA private key by an HSM/KMS token
	// (backend: pkcs11) instead of issuing-ca.key on disk. Empty = on-disk (default).
	CAKeySource KeySourceConfig `yaml:"ca_key_source,omitempty"`
	// GrantKeySource optionally backs the grant private key by an HSM/KMS token
	// (backend: pkcs11) instead of grant.key on disk. The grant key is Ed25519, so a
	// pkcs11 grant key requires an EdDSA-capable token. Empty = on-disk (default).
	GrantKeySource KeySourceConfig `yaml:"grant_key_source,omitempty"`
	// RequireSplitTrust is the final migration flip: once every node has pinned the
	// offline anchor, set this so a split-mode controller stops serving the legacy
	// fallback config and serves ONLY the anchor + routine-map pair. An un-upgraded
	// node then fails to verify (rather than silently riding the grant-key-only legacy
	// path), so it must adopt the anchored trust set. Default false keeps the legacy
	// fallback for a mixed fleet; it has no effect on an un-split (legacy) cluster.
	RequireSplitTrust bool `yaml:"require_split_trust,omitempty"`
}

// caKeySource resolves the issuing-CA key source; the on-disk default reads
// issuing-ca.key under the CA dir.
func (c *Config) caKeySource() keysource.Spec {
	return c.CAKeySource.spec(filepath.Join(c.CADir(), "issuing-ca.key"))
}

// grantKeySource resolves the grant key source; the on-disk default reads
// grant.key under data_dir.
func (c *Config) grantKeySource() keysource.Spec {
	return c.GrantKeySource.spec(c.GrantKeyPath())
}

// ManagedDomainConfig enables publicly-trusted certificates for one or more
// operator-owned public domains. The controller runs an ACME DNS-01 client
// (internal/webpki) under a single account and mints a wildcard per reserved
// workspace subdomain (*.<label>.<base>). DNS-01 providers are declared once in
// DNSProviders, keyed by name, and referenced by each domain — so domains can
// live on different providers under one account. No domains = feature disabled.
type ManagedDomainConfig struct {
	// AccountKeyFile holds the stable ACME account key; empty defaults to
	// <data_dir>/managed-domain/account.key. Generated on first start if absent.
	AccountKeyFile string `yaml:"account_key_file,omitempty"`
	// RenewInterval is how often the renewal reconcile runs; default 6h. Renewal
	// itself fires per cert at ~2/3 of its lifetime, not every tick.
	RenewInterval Duration `yaml:"renew_interval,omitempty"`
	// ACME is the shared issuer account (Let's Encrypt staging by default). The
	// account key is filled from AccountKeyFile at startup.
	ACME webpki.Account `yaml:"acme,omitempty"`
	// DNSProviders declares DNS-01 providers by name; domains reference them.
	DNSProviders map[string]webpki.DNS01Config `yaml:"dns_providers,omitempty"`
	// Domains are the public base domains workspaces reserve subdomains under.
	Domains []ManagedDomainEntry `yaml:"domains,omitempty"`
}

// ManagedDomainEntry binds a public base domain to a named DNS-01 provider.
type ManagedDomainEntry struct {
	Base        string `yaml:"base"`         // e.g. "geneza.app"
	DNSProvider string `yaml:"dns_provider"` // key into DNSProviders
}

func (m ManagedDomainConfig) enabled() bool { return len(m.Domains) > 0 }

// isManagedDomain reports whether base is one of the configured domains (the
// guard a subdomain reservation checks before accepting an admin's choice).
func (m ManagedDomainConfig) isManagedDomain(base string) bool {
	for _, d := range m.Domains {
		if d.Base == base {
			return true
		}
	}
	return false
}

// managedAccountKeyPath resolves the ACME account key path (config override or
// the default under data_dir).
func (c *Config) managedAccountKeyPath() string {
	if c.ManagedDomain.AccountKeyFile != "" {
		return c.ManagedDomain.AccountKeyFile
	}
	return filepath.Join(c.DataDir, "managed-domain", "account.key")
}

// validate checks the managed-domain block is coherent before any network call.
// The full account validation (which needs the loaded key) runs at startup; this
// catches operator typos — bad domains, dangling provider references — at load.
func (m ManagedDomainConfig) validate() error {
	if len(m.Domains) == 0 {
		return nil // disabled
	}
	if m.ACME.Email == "" {
		return errors.New("managed_domain.acme.email is required")
	}
	for name, p := range m.DNSProviders {
		if err := p.Validate(); err != nil {
			return fmt.Errorf("managed_domain.dns_providers[%q]: %w", name, err)
		}
	}
	seen := map[string]bool{}
	for i, d := range m.Domains {
		if strings.ContainsAny(d.Base, "/ *") || !strings.Contains(d.Base, ".") || strings.HasPrefix(d.Base, ".") {
			return fmt.Errorf("managed_domain.domains[%d].base %q is not a bare domain", i, d.Base)
		}
		if seen[d.Base] {
			return fmt.Errorf("managed_domain.domains: duplicate base %q", d.Base)
		}
		seen[d.Base] = true
		if d.DNSProvider == "" {
			return fmt.Errorf("managed_domain.domains[%d] (%s) needs a dns_provider", i, d.Base)
		}
		if _, ok := m.DNSProviders[d.DNSProvider]; !ok {
			return fmt.Errorf("managed_domain.domains[%d] (%s) references unknown dns_provider %q", i, d.Base, d.DNSProvider)
		}
	}
	return nil
}

// CloudConfig is one entry in the clouds registry: a Keystone trust anchor
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
	// be scoped to it, so only Nova can enroll a VM, not an arbitrary tenant.
	ServiceProject string `yaml:"service_project,omitempty"`
	// RequireNovaServiceToken is FORCED true for kind:openstack so the enrollment
	// plane accepts only a Nova service-scoped token, never an arbitrary tenant
	// token. Explicitly setting it false is a load error.
	RequireNovaServiceToken bool `yaml:"require_nova_service_token,omitempty"`
	// AutoProvision: an unbound but token-valid project gets its OWN isolated
	// workspace. Default false (operator pre-binds); the lab sets true.
	// This governs the VM ENROLLMENT plane only.
	AutoProvision bool `yaml:"auto_provision,omitempty"`
	// AllowHumanAutoProvision is the SEPARATE access-plane switch: when a
	// human logs in (or arrives via trusted_dashboard) for an UNBOUND project, do
	// we create a workspace and make them ws-admin? Default false (no implicit
	// workspace for humans — an unbound project is a 403, surfaced to the operator).
	AllowHumanAutoProvision bool `yaml:"allow_human_auto_provision,omitempty"`
	// AllowPasswordLogin gates the login-form keystone password path for this
	// cloud (default true: a registered cloud is loginable unless disabled).
	AllowPasswordLogin *bool `yaml:"allow_password_login,omitempty"`
	// AllowTrustedDashboard gates the Horizon websso handoff for this cloud
	//. Default false (opt-in, since it accepts a raw token).
	AllowTrustedDashboard bool `yaml:"allow_trusted_dashboard,omitempty"`
	// DefaultDomain is the Keystone user/project domain assumed when the login
	// form omits one (default "Default").
	DefaultDomain string `yaml:"default_domain,omitempty"`
	// AutoApprove skips the human admission gate for VMs enrolled via this cloud
	// (PoC convenience; per-project isolation bounds the blast radius). Default
	// false (PENDING until approved).
	AutoApprove bool `yaml:"auto_approve,omitempty"`
	// DefaultLabels are stamped on every node enrolled through this cloud.
	DefaultLabels map[string]string `yaml:"default_labels,omitempty"`
	// RoleMap translates Keystone roles to Geneza workspace roles on the ACCESS
	// plane: e.g. {admin: ws-admin, member: ws-viewer}. A value may
	// NEVER be a reserved cluster role (admin/platform-admin) — that fails config
	// load. Unmapped keystone roles fall back to DefaultRole.
	RoleMap map[string]string `yaml:"role_map,omitempty"`
	// DefaultRole is the geneza workspace role granted when a human's keystone
	// roles map to nothing in RoleMap (least-privilege default: ws-viewer).
	DefaultRole string `yaml:"default_role,omitempty"`
	// CAFile is a PEM bundle Geneza trusts for the Keystone/Nova TLS connection.
	CAFile string `yaml:"ca_file,omitempty"`
	// InsecureSkipVerify disables TLS verification of Keystone/Nova — LAB ONLY.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify,omitempty"`
	// JoinTokenTTL bounds the minted join token (default 1h, covers boot).
	JoinTokenTTL Duration `yaml:"join_token_ttl,omitempty"`
	// ControllerURL is the base HTTPS URL an enrolling VM uses to FETCH the installer
	// + stage-1 binaries + ca-roots (curl must trust this cert — typically a
	// public/LE front). Falls back to the vendordata request's own Host when empty.
	ControllerURL string `yaml:"controller_url,omitempty"`
	// ControllerRuntimeURL is the controller HTTP endpoint the bootstrap/agent use at
	// RUNTIME (the update API), verified against the controller's own cert via the
	// ca-roots the installer fetched. Set this when ControllerURL is a public TLS
	// front whose cert differs from the controller's: e.g. installer over the LE
	// front, runtime over the direct :7402 lab-cert endpoint. Empty = ControllerURL.
	ControllerRuntimeURL string `yaml:"controller_runtime_url,omitempty"`
	// ControllerGRPC is the host:port the agent dials for the enroll RPC; falls back
	// to host(ControllerURL):7401.
	ControllerGRPC string `yaml:"controller_grpc,omitempty"`
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

func (c CloudConfig) allowPasswordLogin() bool {
	return c.AllowPasswordLogin == nil || *c.AllowPasswordLogin
}

func (c CloudConfig) defaultDomain() string {
	if c.DefaultDomain == "" {
		return "Default"
	}
	return c.DefaultDomain
}

// roleForKeystone maps a single Keystone role to a Geneza workspace role via the
// cloud's role_map, or "" if unmapped.
func (c CloudConfig) roleForKeystone(ksRole string) string {
	if c.RoleMap != nil {
		if v, ok := c.RoleMap[ksRole]; ok {
			return v
		}
	}
	// Built-in least-privilege defaults when the operator omits a mapping.
	switch strings.ToLower(ksRole) {
	case "admin":
		return roleWSAdmin
	case "member", "_member_", "reader":
		return "ws-viewer"
	}
	return ""
}

// mapKeystoneRoles translates a human's Keystone roles into Geneza workspace
// roles (least-privilege; reserved cluster roles can never be produced — the
// config loader rejects a role_map that tries). Falls back to
// default_role when nothing maps.
func (c CloudConfig) mapKeystoneRoles(ksRoles []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, kr := range ksRoles {
		if gz := c.roleForKeystone(kr); gz != "" && !reservedRoles[gz] && !seen[gz] {
			seen[gz] = true
			out = append(out, gz)
		}
	}
	if len(out) == 0 {
		def := c.DefaultRole
		if def == "" {
			def = "ws-viewer"
		}
		if !reservedRoles[def] {
			out = []string{def}
		}
	}
	return out
}

// autoProvisionPolicyFile is the policy a dynamically-provisioned workspace uses
// (role-name grants); falls back to the top-level policy file.
func (c *Config) autoProvisionPolicyFile() string {
	if c.AutoProvisionPolicyFile != "" {
		return c.AutoProvisionPolicyFile
	}
	return c.PolicyFile
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
	// Bindings are cloud-qualified SOURCE bindings that resolve to this
	// workspace, e.g. "openstack:project:kolla1:<project-uuid>". Declaring them
	// here is the config-driven equivalent of an operator pre-binding a project:
	// a VM in that project enrolls into THIS workspace, and (cross-source) so do
	// this workspace's member users — one binding serves both planes.
	Bindings []string `yaml:"bindings,omitempty"`
}

// open reports whether the workspace admits any authenticated user (no explicit
// membership configured).
func (w WorkspaceConfig) open() bool { return len(w.Members) == 0 && len(w.MemberGroups) == 0 }

// ClusterConsoleConfig configures the cluster-operator read plane. Listen is its
// dedicated mTLS address (e.g. ":7407"); empty disables it. The surface authorizes
// two principals: a break-glass cluster admin cert (presented at the optional-client-
// cert handshake), or — when no cert is presented — an OIDC browser login whose token
// carries the required cluster-admin group. It is still served apart from the tenant
// console and gRPC listeners.
type ClusterConsoleConfig struct {
	Listen    string `yaml:"listen"`     // e.g. ":7407"; empty = disabled
	StaticDir string `yaml:"static_dir"` // built operator SPA (dist/) served at /, reachable without a cert so the SPA can drive OIDC login
	// ExternalURL is the public origin the operator browser reaches this console at
	// (e.g. https://cluster.geneza.example.com); it forms the OIDC redirect_uri the
	// SPA advertises. Empty falls back to Listen-derived behaviour (the SPA uses its
	// own origin), which is enough for the single-origin lab deploy.
	ExternalURL string `yaml:"external_url,omitempty"`
	// OIDC opts the cluster console into a browser OIDC login alongside the break-glass
	// cert. Empty = cert-only (today's behaviour). When set, a browser with no client
	// cert authenticates by OIDC and must carry RequiredGroup.
	OIDC *ClusterConsoleOIDCConfig `yaml:"oidc,omitempty"`
	// RequiredGroup is the IdP group a cluster-console OIDC login MUST carry to be
	// admitted; a valid token without it is rejected (403). Empty defaults to
	// "geneza-cluster-admins". It has no effect on the break-glass cert path.
	RequiredGroup string `yaml:"required_group,omitempty"`
}

// ClusterConsoleOIDCConfig is the cluster console's OWN OIDC client. Issuer falls
// back to the top-level controller oidc issuer when empty (so a single Keycloak realm
// serves both consoles); ClientID is the cluster console's audience and MUST be set
// when the oidc block is present, because the cluster admin gate is a distinct
// audience from the tenant console's client.
type ClusterConsoleOIDCConfig struct {
	Issuer        string `yaml:"issuer,omitempty"` // empty = inherit the top-level oidc.issuer
	ClientID      string `yaml:"client_id"`        // required: the cluster console's OIDC audience
	UsernameClaim string `yaml:"username_claim,omitempty"`
	GroupsClaim   string `yaml:"groups_claim,omitempty"`
}

// defaultClusterAdminGroup is the IdP group a cluster-console OIDC login must carry
// when required_group is not explicitly configured.
const defaultClusterAdminGroup = "geneza-cluster-admins"

// requiredGroup is the cluster-admin group a console OIDC login must carry.
func (cc ClusterConsoleConfig) requiredGroup() string {
	if cc.RequiredGroup != "" {
		return cc.RequiredGroup
	}
	return defaultClusterAdminGroup
}

// oidcIssuer resolves the cluster console's OIDC issuer: its own override, else the
// top-level controller issuer. Returns "" when neither is set (oidc disabled).
func (c *Config) clusterConsoleOIDCIssuer() string {
	if c.ClusterConsole.OIDC == nil {
		return ""
	}
	if c.ClusterConsole.OIDC.Issuer != "" {
		return c.ClusterConsole.OIDC.Issuer
	}
	if c.OIDC != nil {
		return c.OIDC.Issuer
	}
	return ""
}

// clusterConsoleOIDCEnabled reports whether the cluster console has a usable OIDC
// login configured (a client_id and a resolvable issuer).
func (c *Config) clusterConsoleOIDCEnabled() bool {
	return c.ClusterConsole.OIDC != nil && c.ClusterConsole.OIDC.ClientID != "" && c.clusterConsoleOIDCIssuer() != ""
}

// clusterConsoleUsernameClaim / clusterConsoleGroupsClaim resolve the claim names
// the cluster console reads from a verified id_token, defaulting like the tenant
// console's oidc block.
func (c *Config) clusterConsoleUsernameClaim() string {
	if c.ClusterConsole.OIDC != nil && c.ClusterConsole.OIDC.UsernameClaim != "" {
		return c.ClusterConsole.OIDC.UsernameClaim
	}
	return "preferred_username"
}

func (c *Config) clusterConsoleGroupsClaim() string {
	if c.ClusterConsole.OIDC != nil && c.ClusterConsole.OIDC.GroupsClaim != "" {
		return c.ClusterConsole.OIDC.GroupsClaim
	}
	return "groups"
}

// ConsoleConfig configures the web control panel.
type ConsoleConfig struct {
	Listen       string            `yaml:"listen"`         // e.g. ":7406"; empty = disabled
	StaticDir    string            `yaml:"static_dir"`     // built SPA (dist/) to serve at /
	ExternalURL  string            `yaml:"external_url"`   // public origin, e.g. https://geneza.example.com
	OIDCClientID string            `yaml:"oidc_client_id"` // browser OIDC client; defaults to OIDC.ClientID
	Auth         ConsoleAuthConfig `yaml:"auth"`           // login mechanisms + session/device/handoff TTLs
}

// ConsoleAuthConfig declares which browser login mechanisms the operator enables
// and the lifetimes of the controller-minted credentials. An absent block derives
// the enabled flags from what is configured (oidc block / local_users / clouds).
type ConsoleAuthConfig struct {
	// Enabled* gate which login cards the SPA renders and which session endpoints
	// accept requests. nil (unset) means "derive from configured mechanisms".
	KeystoneEnabled *bool `yaml:"keystone_enabled,omitempty"`
	OIDCEnabled     *bool `yaml:"oidc_enabled,omitempty"`
	LocalEnabled    *bool `yaml:"local_enabled,omitempty"`
	// SessionTTL bounds a browser session (effective = min(this, upstream exp)).
	SessionTTL Duration `yaml:"session_ttl,omitempty"`
	// DeviceCodeTTL bounds an in-flight CLI device login (default 10m).
	DeviceCodeTTL Duration `yaml:"device_code_ttl,omitempty"`
	// DevicePollInterval is the RFC 8628 minimum poll interval (default 5s).
	DevicePollInterval Duration `yaml:"device_poll_interval,omitempty"`
	// HandoffCodeTTL bounds a trusted-dashboard handoff code (default 30s).
	HandoffCodeTTL Duration `yaml:"handoff_code_ttl,omitempty"`
	// Keystone lists the clouds exposed in the login-form dropdown. Each cloud's
	// `cloud` MUST exist in the top-level clouds registry. Empty (with keystone
	// enabled) = expose every registered cloud, labelled by its service-uid.
	Keystone []ConsoleKeystoneCloud `yaml:"keystone,omitempty"`
}

// ConsoleKeystoneCloud is one cloud offered in the login form's dropdown.
type ConsoleKeystoneCloud struct {
	Cloud         string `yaml:"cloud"`                    // service-uid; must be in clouds registry
	Label         string `yaml:"label,omitempty"`          // human label (defaults to Cloud)
	DefaultDomain string `yaml:"default_domain,omitempty"` // Keystone user/project domain (default "Default")
}

func (k ConsoleKeystoneCloud) label() string {
	if k.Label != "" {
		return k.Label
	}
	return k.Cloud
}

func (k ConsoleKeystoneCloud) domain() string {
	if k.DefaultDomain != "" {
		return k.DefaultDomain
	}
	return "Default"
}

// consoleKeystoneClouds returns the clouds to advertise in the login form: the
// configured list (validated against the registry), or every registered cloud
// when keystone is enabled with no explicit list.
func (c *Config) consoleKeystoneClouds() []ConsoleKeystoneCloud {
	if !c.keystoneLoginEnabled() {
		return nil
	}
	if len(c.Console.Auth.Keystone) > 0 {
		return c.Console.Auth.Keystone
	}
	out := make([]ConsoleKeystoneCloud, 0, len(c.Clouds))
	for uid := range c.Clouds {
		out = append(out, ConsoleKeystoneCloud{Cloud: uid})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Cloud < out[j].Cloud })
	return out
}

func (c *Config) ConsoleEnabled() bool { return c.Console.Listen != "" }

func (c *Config) ClusterConsoleEnabled() bool { return c.ClusterConsole.Listen != "" }

// consoleSessionTTL is the browser session lifetime (default 8h; a session is
// further capped by the upstream credential's expiry at mint).
func (c *Config) consoleSessionTTL() time.Duration {
	if c.Console.Auth.SessionTTL > 0 {
		return c.Console.Auth.SessionTTL.D()
	}
	return 8 * time.Hour
}

func (c *Config) deviceCodeTTL() time.Duration {
	if c.Console.Auth.DeviceCodeTTL > 0 {
		return c.Console.Auth.DeviceCodeTTL.D()
	}
	return 10 * time.Minute
}

func (c *Config) devicePollInterval() time.Duration {
	if c.Console.Auth.DevicePollInterval > 0 {
		return c.Console.Auth.DevicePollInterval.D()
	}
	return 5 * time.Second
}

// console mechanism gates. A nil flag derives from what is configured, so a lab
// controller.yaml with an oidc block + local_users + clouds enables all three
// without an explicit auth: block; an operator sets the flag to force-disable.
func (c *Config) keystoneLoginEnabled() bool {
	if c.Console.Auth.KeystoneEnabled != nil {
		return *c.Console.Auth.KeystoneEnabled
	}
	return len(c.Clouds) > 0
}

func (c *Config) oidcLoginEnabled() bool {
	if c.Console.Auth.OIDCEnabled != nil {
		return *c.Console.Auth.OIDCEnabled && c.OIDC != nil
	}
	return c.OIDC != nil
}

func (c *Config) localLoginEnabled() bool {
	if c.Console.Auth.LocalEnabled != nil {
		return *c.Console.Auth.LocalEnabled && len(c.LocalUsers) > 0
	}
	return len(c.LocalUsers) > 0
}

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

// LoadConfig reads, defaults and validates the controller configuration.
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
	// A single flat relay_shared_secret is the single-region shorthand: synthesize
	// it into the per-region map under this controller's region so the minting path
	// has one uniform source. An explicit relay_secrets map wins.
	if len(c.RelaySecrets) == 0 && c.RelaySharedSecret != "" {
		c.RelaySecrets = map[string]RegionSecret{canonicalRegion(c.Region): {Current: c.RelaySharedSecret}}
	}
	if c.StoreBackend == "" {
		c.StoreBackend = "bbolt"
	}
	if c.Router == "" {
		c.Router = "inproc"
	}
	if c.ControllerID == "" {
		if h, err := os.Hostname(); err == nil {
			c.ControllerID = h
		}
	}
	// Presence: TTL stays 0 (= enforcement off) unless the operator opts in with
	// presence.ttl; the heartbeat interval is advisory, defaulted for the client.
	if c.Presence.HeartbeatInterval == 0 {
		c.Presence.HeartbeatInterval = Duration(10 * time.Second)
	}
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
	// Vuln feed: default the sync cadence only when a source is configured; an
	// unset feed stays off (no chore, no defaults synthesized).
	if c.VulnFeed.Enabled() && c.VulnFeed.SyncInterval == 0 {
		c.VulnFeed.SyncInterval = Duration(6 * time.Hour)
	}
	// Clouds registry. require_nova_service_token is NON-OVERRIDABLE for
	// kind:openstack: the enrollment plane must only ever accept a Nova
	// service-scoped token, so we force it true here regardless of the file.
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
		if u.Subject == "" {
			c.LocalUsers[i].Subject = u.Username // default: subject == username
		}
	}
	if err := c.CAKeySource.validate("ca_key_source"); err != nil {
		return err
	}
	if err := c.GrantKeySource.validate("grant_key_source"); err != nil {
		return err
	}
	if err := c.ManagedDomain.validate(); err != nil {
		return err
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
	// Clouds registry. Reject configurations that would break the trust
	// model: an unknown kind, a missing Keystone, or — critically — two service
	// uids sharing one Keystone (that collapses the routing≠auth guarantee and
	// lets a token-holder choose which namespace to bind into).
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
			return fmt.Errorf("clouds[%q] and clouds[%q] share keystone_url %q: forbidden — a shared Keystone breaks routing≠auth; give each its own Keystone or merge them", uid, other, cl.KeystoneURL)
		}
		keystoneSeen[ks] = uid
		switch cl.endpointInterface() {
		case "public", "internal", "admin":
		default:
			return fmt.Errorf("clouds[%q]: endpoint_interface must be public|internal|admin", uid)
		}
		//: a keystone role_map / default_role must NEVER emit a reserved
		// cluster role. stripReservedRoles would drop it anyway, but failing
		// loudly at load is the structural guard against a silent over-grant.
		for ksRole, gzRole := range cl.RoleMap {
			if reservedRoles[gzRole] {
				return fmt.Errorf("clouds[%q].role_map[%q] = %q: a reserved cluster role cannot be granted by a keystone mapping (use %q for workspace admin)", uid, ksRole, gzRole, roleWSAdmin)
			}
		}
		if reservedRoles[cl.DefaultRole] {
			return fmt.Errorf("clouds[%q].default_role = %q: a reserved cluster role cannot be a keystone default (use %q)", uid, cl.DefaultRole, roleWSAdmin)
		}
	}
	// Console must never be reachable without a login mechanism (fail closed):
	// an enabled console with no working provider would be an open door.
	if c.ConsoleEnabled() {
		if !c.keystoneLoginEnabled() && !c.oidcLoginEnabled() && !c.localLoginEnabled() {
			return fmt.Errorf("console.listen is set but no login mechanism is enabled (configure oidc, local_users, or a cloud)")
		}
		if c.Console.Auth.KeystoneEnabled != nil && *c.Console.Auth.KeystoneEnabled && len(c.Clouds) == 0 {
			return fmt.Errorf("console.auth.keystone_enabled is true but no clouds are configured")
		}
		for i, kc := range c.Console.Auth.Keystone {
			if kc.Cloud == "" {
				return fmt.Errorf("console.auth.keystone[%d]: cloud is required", i)
			}
			if _, ok := c.Clouds[kc.Cloud]; !ok {
				return fmt.Errorf("console.auth.keystone[%d].cloud = %q is not in the clouds registry", i, kc.Cloud)
			}
		}
	}
	// Cluster-console OIDC: the block is opt-in, but once present it must be usable —
	// a client_id is mandatory (it is the cluster admin gate's distinct audience) and
	// an issuer must resolve (its own override or the inherited top-level oidc issuer).
	if c.ClusterConsole.OIDC != nil {
		if c.ClusterConsole.OIDC.ClientID == "" {
			return fmt.Errorf("cluster_console.oidc.client_id is required when the cluster_console.oidc block is present")
		}
		if c.clusterConsoleOIDCIssuer() == "" {
			return fmt.Errorf("cluster_console.oidc.issuer is required (no top-level oidc.issuer to inherit)")
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
	// Presence timer invariants (only when enforcement is on, presence.ttl > 0):
	// the heartbeat must be more frequent than the staleness threshold, and the
	// sweep must run at least as often, or a stale session would never be reaped.
	if ttl := c.Presence.TTL.D(); ttl > 0 {
		if c.Presence.HeartbeatInterval.D() >= ttl {
			return fmt.Errorf("presence.heartbeat_interval (%s) must be < presence.ttl (%s)", c.Presence.HeartbeatInterval.D(), ttl)
		}
		reauth := c.ReauthInterval.D()
		if reauth == 0 {
			reauth = defaultReauthInterval
		}
		if reauth > ttl {
			return fmt.Errorf("reauth_interval (%s) must be <= presence.ttl (%s)", reauth, ttl)
		}
	}
	for _, a := range c.RelayAddrs {
		if _, _, err := net.SplitHostPort(a); err != nil {
			return fmt.Errorf("relay_addrs: %q is not host:port: %w", a, err)
		}
	}
	// A SQL backend needs a DSN; an absent one is a hard error, never a silent
	// localhost fallback that could point at the wrong database.
	if c.usesSQLStore() && c.StoreDSN == "" {
		return fmt.Errorf("store=%q requires store_dsn", c.StoreBackend)
	}
	// The single-node default is inproc (empty canonicalizes to it); pg is the
	// multi-controller router. Reject any other value rather than silently falling back.
	switch c.Router {
	case "", "inproc", "pg":
	default:
		return fmt.Errorf("unknown router %q (valid: inproc, pg)", c.Router)
	}
	// router=pg shares all strong state through Postgres (LISTEN/NOTIFY as the bus);
	// bbolt is per-node and would split-brain the deny path.
	//
	// The deny-path reads (revocation/suspension), the affinity directory reads, and
	// the LISTEN connection MUST target the Postgres PRIMARY. There is one DSN today
	// so this holds by construction; if a read-replica DSN is ever added, it must be
	// rejected here for these reads — a lagging replica would return "not suspended"
	// and the deny cache only fails closed on a read error, not on stale data.
	if c.Router == "pg" && !c.usesSQLStore() {
		return fmt.Errorf("router=pg requires a shared SQL store (set store=postgres + store_dsn)")
	}
	// Each controller LISTENs a per-owner doorbell channel named for its id; a Postgres
	// channel name is capped at 63 bytes, so an over-long id would fail the LISTEN at
	// startup. Reject it up front. (gwChannel adds a fixed 10-byte prefix.) The cap is
	// a Postgres-wire limit; the MySQL poll bus uses no channels, so it does not apply.
	if c.Router == "pg" && c.StoreBackend == "postgres" && len(gwChannel(c.ControllerID)) > 63 {
		return fmt.Errorf("controller_id %q is too long for router=pg on postgres (the doorbell channel must be ≤ 63 bytes)", c.ControllerID)
	}
	// A separate cluster-control listener must be its own address, or it would
	// collide with the agent/user gRPC or HTTPS listener instead of segmenting.
	if c.ClusterControlListen != "" {
		if c.ClusterControlListen == c.GRPCListen || c.ClusterControlListen == c.HTTPListen {
			return fmt.Errorf("cluster_control_listen (%s) must differ from grpc_listen and http_listen", c.ClusterControlListen)
		}
	}
	// The cluster-operator console rides its own mTLS listener; it must not collide
	// with any other listener, or it would share a socket with a surface that has a
	// weaker (or login-based) auth gate.
	if c.ClusterConsole.Listen != "" {
		others := map[string]string{
			"grpc_listen": c.GRPCListen, "http_listen": c.HTTPListen,
			"console.listen": c.Console.Listen, "cluster_control_listen": c.ClusterControlListen,
		}
		for name, addr := range others {
			if addr != "" && c.ClusterConsole.Listen == addr {
				return fmt.Errorf("cluster_console.listen (%s) must differ from %s", c.ClusterConsole.Listen, name)
			}
		}
	}
	if c.StoreBackend == "bbolt" && c.Region != "" {
		return fmt.Errorf("region=%q requires a shared SQL store; bbolt is single-node only", c.Region)
	}
	// A controller pinned to a region must hold that region's minting secret, or it
	// cannot mint TURN credentials any relay in its region will accept. A ':' in a
	// region id would corrupt the "<expiry>:<region>:<id>" TURN username parse.
	if c.Region != "" {
		if strings.ContainsRune(c.Region, ':') {
			return fmt.Errorf("region=%q must not contain ':'", c.Region)
		}
		if sec, ok := c.RelaySecrets[canonicalRegion(c.Region)]; !ok || sec.Current == "" {
			return fmt.Errorf("region=%q requires relay_secrets[%q].current", c.Region, canonicalRegion(c.Region))
		}
	}
	// Vuln feed: a configured source must name a known kind and carry the field
	// that source needs, so a typo fails loudly at load rather than running with no
	// feed. An empty source is off and validates trivially.
	switch c.VulnFeed.Source {
	case "":
	case "osv_dir":
		if c.VulnFeed.Dir == "" {
			return fmt.Errorf("vuln_feed.source=osv_dir requires vuln_feed.dir")
		}
	case "osv_bulk":
		// bulk_url empty is valid (defaults to the live OSV.dev bucket).
	case "geneza-paid":
		if c.VulnFeed.PaidEndpoint == "" {
			return fmt.Errorf("vuln_feed.source=geneza-paid requires vuln_feed.paid_endpoint")
		}
		if _, err := c.VulnFeed.paidPubKey(); err != nil {
			return fmt.Errorf("vuln_feed.paid_pubkey: %w", err)
		}
	default:
		return fmt.Errorf("unknown vuln_feed.source %q (valid: osv_dir, osv_bulk, geneza-paid)", c.VulnFeed.Source)
	}
	return nil
}

// usesSQLStore reports whether the configured backend is a shared SQL store
// (Postgres or MariaDB/MySQL), as opposed to the single-node bbolt file.
func (c *Config) usesSQLStore() bool {
	switch c.StoreBackend {
	case "postgres", "mariadb", "mysql":
		return true
	}
	return false
}

// sqlEngine returns the SQL backend name (postgres | mariadb | mysql), or "" when
// the store is bbolt.
func (c *Config) sqlEngine() string {
	if c.usesSQLStore() {
		return c.StoreBackend
	}
	return ""
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

func (c *Config) controllerCertPath() string { return filepath.Join(c.TLSDir(), "controller.crt") }
func (c *Config) controllerKeyPath() string  { return filepath.Join(c.TLSDir(), "controller.key") }
func (c *Config) relayCertPath() string      { return filepath.Join(c.TLSDir(), "relay.crt") }

// relayDataAddr returns the relay's UDP data endpoint agents dial out to:
// relay_data_addrs[0] if set, else host(relay_addrs[0]):RelayDataPort.
func (c *Config) relayDataAddr() string {
	if len(c.RelayDataAddrs) > 0 && c.RelayDataAddrs[0] != "" {
		return c.RelayDataAddrs[0]
	}
	if len(c.RelayAddrs) == 0 {
		return ""
	}
	host, _, err := net.SplitHostPort(c.RelayAddrs[0])
	if err != nil || host == "" {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(defaults.RelayDataPort))
}

// relayDataPort is the UDP port the relay's TURN/STUN server listens on: the
// port of relay_data_addrs[0] when set, else the built-in default.
func (c *Config) relayDataPort() int {
	if len(c.RelayDataAddrs) > 0 && c.RelayDataAddrs[0] != "" {
		if _, p, err := net.SplitHostPort(c.RelayDataAddrs[0]); err == nil {
			if n, err := strconv.Atoi(p); err == nil {
				return n
			}
		}
	}
	return defaults.RelayDataPort
}
func (c *Config) relayKeyPath() string { return filepath.Join(c.TLSDir(), "relay.key") }

func (c *Config) advertiseIPs() []net.IP {
	out := make([]net.IP, 0, len(c.Advertise.IPs))
	for _, s := range c.Advertise.IPs {
		if ip := net.ParseIP(s); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}
