package relay

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"osie.cloud/geneza/internal/wire"
)

func TestLoadExampleConfig(t *testing.T) {
	cfg, err := Load(filepath.Join("testdata", "relay.example.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != ":7403" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	if !cfg.TLS {
		t.Error("TLS should be enabled in the example config")
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		t.Error("cert/key paths missing")
	}
	if cfg.MatchTTL != 60*time.Second {
		t.Errorf("MatchTTL = %v", cfg.MatchTTL)
	}
	if cfg.IdleTimeout != 10*time.Minute {
		t.Errorf("IdleTimeout = %v", cfg.IdleTimeout)
	}
	if cfg.MaxPending != 1024 {
		t.Errorf("MaxPending = %d", cfg.MaxPending)
	}
	// Untouched knobs keep their defaults.
	if cfg.HelloTimeout != 10*time.Second || cfg.StatsPeriod != 60*time.Second ||
		cfg.DrainTimeout != 5*time.Second {
		t.Errorf("tuning defaults wrong: %+v", cfg)
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "relay.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaultsWhenSparse(t *testing.T) {
	// TLS off is the only way a sparse config is valid (no cert paths).
	cfg, err := Load(writeTemp(t, "tls: false\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := DefaultConfig()
	if cfg.Listen != want.Listen || cfg.MatchTTL != want.MatchTTL ||
		cfg.IdleTimeout != want.IdleTimeout || cfg.MaxPending != want.MaxPending {
		t.Errorf("defaults not applied: %+v", cfg)
	}
}

func TestLoadFailsClosed(t *testing.T) {
	cases := map[string]string{
		// TLS defaults to true; missing cert/key must be fatal, not a
		// silent fallback to plaintext.
		"tls without certs": "listen: \":7403\"\n",
		"unknown key":       "tls: false\nlisten_addr: \":1\"\n",
		"bad duration":      "tls: false\nmatch_ttl: sixty\n",
		"negative pending":  "tls: false\nmax_pending: -1\n",
		"zero ttl":          "tls: false\nmatch_ttl: 0s\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeTemp(t, content)); err == nil {
				t.Fatalf("Load accepted %q", content)
			}
		})
	}
}

func helloFor(token string) wire.RelayHello {
	return wire.RelayHello{V: 1, Token: token, Role: wire.RoleInitiator}
}

func TestValidateHello(t *testing.T) {
	// validateHello is the only gate before blind splicing; check the
	// canonical token shape from types.NewToken is accepted.
	ok := func(token string) bool {
		return validateHello(helloFor(token)) == nil
	}
	if !ok("gz-0123456789abcdef0123456789abcdef") {
		t.Error("canonical token rejected")
	}
	for _, bad := range []string{
		"", "gz-", "gz-short", "gz-0123456789ABCDEF0123456789abcdef",
		"0123456789abcdef0123456789abcdef",
		"gz-" + string(make([]byte, 65)),
	} {
		if ok(bad) {
			t.Errorf("token %q accepted", bad)
		}
	}
}
