package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bootstrap.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// An agent bootstrap config with no product key behaves exactly as before:
// product defaults to geneza-agent and worker_config falls back to agent_config.
func TestConfigProductDefaultsAgent(t *testing.T) {
	cfg, err := loadConfig(writeConfig(t, `{
		"controller_http_url": "https://gw:7402",
		"agent_config": "/etc/geneza/agent.yaml"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Product != productAgent {
		t.Fatalf("product = %q, want %q", cfg.Product, productAgent)
	}
	if cfg.WorkerConfig != "/etc/geneza/agent.yaml" {
		t.Fatalf("worker_config fallback = %q, want the agent config", cfg.WorkerConfig)
	}
}

// A relay bootstrap config selects the relay product and its own worker_config.
func TestConfigRelayProduct(t *testing.T) {
	cfg, err := loadConfig(writeConfig(t, `{
		"controller_http_url": "https://gw:7402",
		"product": "geneza-relay",
		"worker_config": "/etc/geneza/relay.yaml",
		"artifact_pub_file": "/etc/geneza/artifact.pub"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Product != productRelay {
		t.Fatalf("product = %q, want %q", cfg.Product, productRelay)
	}
	if cfg.WorkerConfig != "/etc/geneza/relay.yaml" {
		t.Fatalf("worker_config = %q", cfg.WorkerConfig)
	}
}

func TestConfigRejectsUnknownProduct(t *testing.T) {
	_, err := loadConfig(writeConfig(t, `{
		"controller_http_url": "https://gw:7402",
		"product": "geneza-bogus"
	}`))
	if err == nil {
		t.Fatal("unknown product must be rejected")
	}
}
