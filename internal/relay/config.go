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
	"time"

	"gopkg.in/yaml.v3"

	"osie.cloud/geneza/internal/defaults"
)

// Config is the resolved relay configuration. Zero values are not usable;
// build one via Load or DefaultConfig and override fields as needed (tests
// shrink the timeouts and disable TLS).
type Config struct {
	// Listen is the TCP listen address, e.g. ":7403".
	Listen string
	// DataListen is the UDP listen address for the blind DERP-lite WireGuard
	// data forwarder, e.g. ":7404". Empty disables the forwarder.
	DataListen string
	// TLS enables TLS on the listener. It must only be false in unit tests:
	// the hello frame carries the rendezvous token, which must never cross a
	// real network in cleartext.
	TLS      bool
	CertFile string
	KeyFile  string

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
		Listen:       fmt.Sprintf(":%d", defaults.RelayPort),
		DataListen:   fmt.Sprintf(":%d", defaults.RelayDataPort),
		TLS:          true,
		MatchTTL:     defaults.RelayMatchTTL,
		IdleTimeout:  defaults.RelayIdleClose,
		MaxPending:   1024,
		HelloTimeout: 10 * time.Second,
		StatsPeriod:  60 * time.Second,
		DrainTimeout: 5 * time.Second,
	}
}

// fileConfig is the YAML-facing shape; durations are strings ("60s", "10m")
// and tls is a *bool so "absent" defaults to true rather than false.
type fileConfig struct {
	Listen       string  `yaml:"listen"`
	DataListen   *string `yaml:"data_listen"`
	TLS          *bool   `yaml:"tls"`
	CertFile     string  `yaml:"cert_file"`
	KeyFile      string  `yaml:"key_file"`
	MatchTTL     string  `yaml:"match_ttl"`
	IdleTimeout  string  `yaml:"idle_timeout"`
	MaxPending   int     `yaml:"max_pending"`
	HelloTimeout string  `yaml:"hello_timeout"`
	StatsPeriod  string  `yaml:"stats_period"`
	DrainTimeout string  `yaml:"drain_timeout"`
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
	if fc.TLS != nil {
		cfg.TLS = *fc.TLS
	}
	cfg.CertFile = fc.CertFile
	cfg.KeyFile = fc.KeyFile
	if fc.MaxPending != 0 {
		cfg.MaxPending = fc.MaxPending
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
	return nil
}

func unmarshalStrict(b []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	return dec.Decode(v)
}
