package agentd

import (
	"path/filepath"
	"testing"
)

func TestLoadExampleConfig(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join("testdata", "agent.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ControllerGRPCAddr != "controller.example.internal:7401" {
		t.Errorf("controller_grpc_addr = %q", cfg.ControllerGRPCAddr)
	}
	if cfg.Labels["env"] != "prod" || cfg.Labels["role"] != "web" {
		t.Errorf("labels = %v", cfg.Labels)
	}
	if !cfg.SpawnHost() {
		t.Error("spawn_session_host should be true in the example")
	}
	if cfg.HealthFile != "/run/geneza/worker.health" {
		t.Errorf("health_file = %q", cfg.HealthFile)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StateDir != "/var/lib/geneza/agent" {
		t.Errorf("state_dir default = %q", cfg.StateDir)
	}
	if cfg.SessionHostSocket != "/run/geneza/session-host.sock" {
		t.Errorf("session_host_socket default = %q", cfg.SessionHostSocket)
	}
	if cfg.SpoolDir != "/var/lib/geneza/spool" {
		t.Errorf("spool_dir default = %q", cfg.SpoolDir)
	}
	if cfg.HealthFile != "/run/geneza/worker.health" {
		t.Errorf("health_file default = %q", cfg.HealthFile)
	}
	if !cfg.SpawnHost() {
		t.Error("spawn_session_host must default to true")
	}
}
