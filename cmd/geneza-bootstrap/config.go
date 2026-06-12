package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// config is /etc/geneza/bootstrap.json. Deliberately JSON, not YAML: the
// bootstrap must stay stdlib-only and fully auditable, so it carries no YAML
// dependency. Defaults below mirror the documented filesystem layout; only
// gateway_http_url has no usable default.
type config struct {
	GatewayHTTPURL  string `json:"gateway_http_url"`
	CARootsFile     string `json:"ca_roots_file"`
	ArtifactPubFile string `json:"artifact_pub_file"`
	// RootPubFile pins the PUBLIC half of the offline TUF-lite ROOT key. When set,
	// the bootstrap runs in root-anchored mode: it requires a root-keys doc from
	// the gateway, verifies it against this pinned root, and trusts manifests
	// signed by ANY key the root authorizes (rotation-friendly). The pinned root
	// itself never signs manifests (role separation). Empty = legacy mode, where
	// artifact_pub_file is the single trusted release-signing key.
	RootPubFile       string `json:"root_pub_file"`
	VersionsDir       string `json:"versions_dir"`
	StateFile         string `json:"state_file"`
	NodeIDFile        string `json:"node_id_file"`
	AgentConfig       string `json:"agent_config"`
	RunDir            string `json:"run_dir"`
	SpoolDir          string `json:"spool_dir"`
	SessionHostSocket string `json:"session_host_socket"`
	PollIntervalSec   int    `json:"poll_interval_sec"`
	HealthTimeoutSec  int    `json:"health_timeout_sec"`
}

func loadConfig(path string) (*config, error) {
	cfg := &config{
		ArtifactPubFile:   "/etc/geneza/artifact.pub",
		VersionsDir:       "/var/lib/geneza/versions",
		StateFile:         "/var/lib/geneza/bootstrap-state.json",
		NodeIDFile:        "/var/lib/geneza/agent/node-id",
		AgentConfig:       "/etc/geneza/agent.yaml",
		RunDir:            "/run/geneza",
		SpoolDir:          "/var/lib/geneza/spool",
		SessionHostSocket: "/run/geneza/session-host.sock",
		PollIntervalSec:   15,
		HealthTimeoutSec:  60,
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.GatewayHTTPURL == "" {
		return nil, fmt.Errorf("%s: gateway_http_url is required", path)
	}
	if cfg.ArtifactPubFile == "" {
		// Without the pinned key there is no trustworthy update path at
		// all; refusing to start is the only fail-closed option.
		return nil, fmt.Errorf("%s: artifact_pub_file is required", path)
	}
	if cfg.PollIntervalSec <= 0 {
		cfg.PollIntervalSec = 15
	}
	if cfg.HealthTimeoutSec <= 0 {
		cfg.HealthTimeoutSec = 60
	}
	return cfg, nil
}

func (c *config) pollInterval() time.Duration { return time.Duration(c.PollIntervalSec) * time.Second }
func (c *config) healthTimeout() time.Duration {
	return time.Duration(c.HealthTimeoutSec) * time.Second
}
