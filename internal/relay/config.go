// Package relay implements the Geneza rendezvous relay: a stateless,
// payload-blind forwarder (ARCHITECTURE.md §3/§4). Endpoints dial in over
// TLS, present a one-time token plus role in a wire.RelayHello frame, and the
// relay splices the initiator/responder pair byte-for-byte. After the hello
// frame the relay never parses another byte — endpoints run their own Noise
// handshake through it, so a compromised relay sees only ciphertext and
// traffic metadata.
package relay

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"geneza.io/internal/defaults"
)

// defaultRegion is the canonical region id for a single-region relay.
const defaultRegion = "default"

func canonicalRegion(region string) string {
	if region == "" {
		return defaultRegion
	}
	return region
}

// RegionSecret is one region's TURN-validation secret. The relay verifies a
// credential against Current only: pion/turn hands the AuthHandler a single
// integrity key per username, so a relay cannot accept two secrets at once.
// Rotating a region's secret is therefore a synchronized flag-day — the controller
// and every relay in the region must swap Current together.
type RegionSecret struct {
	Current string `yaml:"current"`
}

// Config is the resolved relay configuration. Zero values are not usable;
// build one via Load or DefaultConfig and override fields as needed (tests
// shrink the timeouts and disable TLS).
type Config struct {
	// Listen is the TCP listen address, e.g. ":7403".
	Listen string
	// DataListen is the UDP listen address for the embedded TURN server (the
	// overlay's blind relay floor), e.g. ":7404". Empty disables it.
	DataListen string
	// FunnelListen is the public TCP listen address for funnel (the one place the
	// relay terminates public TLS), e.g. ":443". Empty disables funnel ingress.
	FunnelListen string
	// Realm is the TURN realm (e.g. "geneza").
	Realm string
	// SharedSecret is the coturn-style REST shared secret used to validate the
	// controller-minted ephemeral TURN credentials. MUST match the controller's
	// relay_shared_secret. Empty disables the TURN server (no floor). It is the
	// single-region shorthand: it is synthesized into Secrets[Region] at load.
	SharedSecret string
	// Region is this relay's region id; it validates only TURN credentials tagged
	// for this region (caps a leaked secret to one region). Empty = "default".
	Region string
	// Secrets is this region's TURN secret, keyed by region id; a relay holds only
	// its OWN region's entry. Rotating a region's secret is a synchronized flag-day
	// (the AuthHandler validates against one key — see RegionSecret).
	Secrets map[string]RegionSecret
	// RelayID is this relay's stable id in the signed fleet map. RegistrarAddr is
	// the controller gRPC address it heartbeats to (empty = no self-registration, the
	// single-node default where the controller synthesizes the map). ControllerCAFile is
	// the CA bundle used to verify the controller, ControllerServerName the expected SAN.
	RelayID           string
	RegistrarAddr     string
	ControllerCAFile     string
	ControllerServerName string
	// ControlMux enables this relay to accept persistent agent control muxes — a
	// payload-blind forward of an agent's end-to-end mTLS control stream to the
	// controller it names. Off by default. It is inert without a registrar: a relay
	// with no signed controller set to route against rejects every control mux, so a
	// single-node relay never serves one.
	ControlMux bool
	// MaxControlMux caps how many agents may home their control stream through this
	// relay at once. Control muxes are LONG-LIVED (an agent's whole uptime), so they
	// are counted SEPARATELY from the ephemeral-splice cap (MaxPending) — otherwise
	// durable muxes would slowly starve the brief token rendezvous and vice-versa.
	// Each mux holds two sockets; size this to the relay's homed-agent count and its
	// file-descriptor limit.
	MaxControlMux int
	// PublicIP is the relay address advertised to TURN clients in allocations
	// (deployment-specific reachable IP; lab uses the internal vmbr5 IP).
	PublicIP string
	// TLS enables TLS on the listener. It must only be false in unit tests:
	// the hello frame carries the rendezvous token, which must never cross a
	// real network in cleartext.
	TLS      bool
	CertFile string
	KeyFile  string

	// HealthFile is the update liveness file the relay touches once it is serving,
	// for a bootstrap-supervised relay's health gate (mirrors the agent worker's
	// health_file). Empty disables it — the single-node bare-service deployment,
	// which is not bootstrap-supervised, writes no health file.
	HealthFile string

	// DrainStatusFile is where a bootstrap-supervised relay reports its drain status
	// (draining flag + live active count) so the bootstrap can drain the relay
	// (SIGUSR1) and wait for it to clear to 0 BEFORE swapping the binary — the
	// drain-before-swap gate. Empty disables it (a non-supervised relay writes none).
	DrainStatusFile string

	// MatchTTL bounds how long an unmatched endpoint may wait for its peer.
	MatchTTL time.Duration
	// IdleTimeout reaps spliced connections with no traffic in either
	// direction (dead peers that never sent a FIN).
	IdleTimeout time.Duration
	// MaxPending caps the waiting table; arrivals beyond it are rejected so
	// unmatched hellos cannot exhaust memory (fail closed).
	MaxPending int

	// HelloTimeout bounds the TLS handshake + hello frame read on a new
	// connection, and the RelayResp write at match time.
	HelloTimeout time.Duration
	// StatsPeriod is the interval of the periodic stats log line.
	StatsPeriod time.Duration
	// DrainTimeout is how long graceful shutdown lets live splices finish
	// before force-closing them.
	DrainTimeout time.Duration
}

// DefaultConfig returns the documented defaults (TLS on).
func DefaultConfig() Config {
	return Config{
		Listen:        fmt.Sprintf(":%d", defaults.RelayPort),
		DataListen:    fmt.Sprintf(":%d", defaults.RelayDataPort),
		Realm:         "geneza",
		TLS:           true,
		MatchTTL:      defaults.RelayMatchTTL,
		IdleTimeout:   defaults.RelayIdleClose,
		MaxPending:    1024,
		MaxControlMux: 8192,
		HelloTimeout:  10 * time.Second,
		StatsPeriod:   60 * time.Second,
		DrainTimeout:  5 * time.Second,
	}
}

// fileConfig is the YAML-facing shape; durations are strings ("60s", "10m")
// and tls is a *bool so "absent" defaults to true rather than false.
type fileConfig struct {
	Listen            string                  `yaml:"listen"`
	DataListen        *string                 `yaml:"data_listen"`
	FunnelListen      string                  `yaml:"funnel_listen"`
	Realm             string                  `yaml:"realm"`
	SharedSecret      string                  `yaml:"shared_secret"`
	Region            string                  `yaml:"region"`
	Secrets           map[string]RegionSecret `yaml:"secrets,omitempty"`
	RelayID           string                  `yaml:"relay_id"`
	RegistrarAddr     string                  `yaml:"registrar_addr"`
	ControllerCAFile     string                  `yaml:"controller_ca_file"`
	ControllerServerName string                  `yaml:"controller_server_name"`
	ControlMux        bool                    `yaml:"control_mux"`
	PublicIP          string                  `yaml:"public_ip"`
	TLS               *bool                   `yaml:"tls"`
	CertFile          string                  `yaml:"cert_file"`
	KeyFile           string                  `yaml:"key_file"`
	HealthFile        string                  `yaml:"health_file"`
	DrainStatusFile   string                  `yaml:"drain_status_file"`
	MatchTTL          string                  `yaml:"match_ttl"`
	IdleTimeout       string                  `yaml:"idle_timeout"`
	MaxPending        int                     `yaml:"max_pending"`
	MaxControlMux     int                     `yaml:"max_control_mux"`
	HelloTimeout      string                  `yaml:"hello_timeout"`
	StatsPeriod       string                  `yaml:"stats_period"`
	DrainTimeout      string                  `yaml:"drain_timeout"`
}

// Load reads a relay.yaml, applies defaults, and validates. Unknown YAML
// keys are rejected so a typo cannot silently weaken the config.
func Load(path string) (Config, error) {
	cfg := DefaultConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("relay config: %w", err)
	}
	var fc fileConfig
	if err := unmarshalStrict(b, &fc); err != nil {
		return Config{}, fmt.Errorf("relay config %s: %w", path, err)
	}

	if fc.Listen != "" {
		cfg.Listen = fc.Listen
	}
	if fc.DataListen != nil {
		cfg.DataListen = *fc.DataListen // explicit, incl. "" to disable
	}
	if fc.FunnelListen != "" {
		cfg.FunnelListen = fc.FunnelListen
	}
	if fc.Realm != "" {
		cfg.Realm = fc.Realm
	}
	cfg.SharedSecret = fc.SharedSecret
	cfg.Region = canonicalRegion(fc.Region)
	cfg.Secrets = fc.Secrets
	cfg.RelayID = fc.RelayID
	cfg.RegistrarAddr = fc.RegistrarAddr
	cfg.ControllerCAFile = fc.ControllerCAFile
	cfg.ControllerServerName = fc.ControllerServerName
	cfg.ControlMux = fc.ControlMux
	// The flat shared_secret is the single-region shorthand: synthesize it into
	// this relay's region so the validation path has one uniform source.
	if len(cfg.Secrets) == 0 && cfg.SharedSecret != "" {
		cfg.Secrets = map[string]RegionSecret{cfg.Region: {Current: cfg.SharedSecret}}
	}
	cfg.PublicIP = fc.PublicIP
	if fc.TLS != nil {
		cfg.TLS = *fc.TLS
	}
	cfg.CertFile = fc.CertFile
	cfg.KeyFile = fc.KeyFile
	cfg.HealthFile = fc.HealthFile
	cfg.DrainStatusFile = fc.DrainStatusFile
	if fc.MaxPending != 0 {
		cfg.MaxPending = fc.MaxPending
	}
	if fc.MaxControlMux != 0 {
		cfg.MaxControlMux = fc.MaxControlMux
	}
	for _, d := range []struct {
		name string
		in   string
		out  *time.Duration
	}{
		{"match_ttl", fc.MatchTTL, &cfg.MatchTTL},
		{"idle_timeout", fc.IdleTimeout, &cfg.IdleTimeout},
		{"hello_timeout", fc.HelloTimeout, &cfg.HelloTimeout},
		{"stats_period", fc.StatsPeriod, &cfg.StatsPeriod},
		{"drain_timeout", fc.DrainTimeout, &cfg.DrainTimeout},
	} {
		if d.in == "" {
			continue
		}
		v, err := time.ParseDuration(d.in)
		if err != nil {
			return Config{}, fmt.Errorf("relay config %s: %s: %w", path, d.name, err)
		}
		*d.out = v
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("relay config %s: %w", path, err)
	}
	return cfg, nil
}

// Validate rejects configurations the relay cannot run safely with.
func (c Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen must be set")
	}
	if c.TLS && (c.CertFile == "" || c.KeyFile == "") {
		return fmt.Errorf("tls enabled but cert_file/key_file not set")
	}
	if c.MatchTTL <= 0 || c.IdleTimeout <= 0 || c.HelloTimeout <= 0 ||
		c.StatsPeriod <= 0 || c.DrainTimeout <= 0 {
		return fmt.Errorf("all timeouts must be positive")
	}
	if c.MaxPending <= 0 {
		return fmt.Errorf("max_pending must be positive")
	}
	// A control-mux relay needs a registrar to receive the signed controller map it
	// routes against; without one it would silently reject every control mux.
	if c.ControlMux && c.RegistrarAddr == "" {
		return fmt.Errorf("control_mux requires registrar_addr (a relay with no registrar holds no signed controller map to route control muxes against)")
	}
	if c.ControlMux && c.MaxControlMux <= 0 {
		return fmt.Errorf("control_mux requires a positive max_control_mux")
	}
	// A ':' in the region id would corrupt the "<expiry>:<region>:<id>" TURN
	// username this relay parses to enforce region containment.
	if strings.ContainsRune(c.Region, ':') {
		return fmt.Errorf("region %q must not contain ':'", c.Region)
	}
	// A relay that validates TURN credentials must hold its own region's secret;
	// otherwise it could only reject every allocation.
	if len(c.Secrets) > 0 {
		if sec, ok := c.Secrets[canonicalRegion(c.Region)]; !ok || sec.Current == "" {
			return fmt.Errorf("region %q has no secrets entry with a current secret", canonicalRegion(c.Region))
		}
	}
	return nil
}

func unmarshalStrict(b []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	return dec.Decode(v)
}
