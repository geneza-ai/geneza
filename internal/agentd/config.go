// Package agentd implements the Geneza agent worker: enrollment, the
// persistent NodeControl channel to the gateway, session-offer handling and
// the relay/Noise/SSH data path, bridging tunnel channels to the separately
// supervised session-host process over its unix-socket gRPC API.
package agentd

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"osie.cloud/geneza/internal/defaults"
)

// Config is /etc/geneza/agent.yaml. Zero values fall back to defaults so a
// minimal config only needs gateway_grpc_addr.
type Config struct {
	GatewayGRPCAddr   string            `yaml:"gateway_grpc_addr"`
	GatewayHTTPURL    string            `yaml:"gateway_http_url"`
	StateDir          string            `yaml:"state_dir"`
	Name              string            `yaml:"name"`
	Labels            map[string]string `yaml:"labels"`
	SessionHostSocket string            `yaml:"session_host_socket"`
	SpoolDir          string            `yaml:"spool_dir"`
	HealthFile        string            `yaml:"health_file"`
	// SpawnSessionHost defaults to true; bootstrap-supervised deployments run
	// the session host themselves and pass --no-spawn-session-host instead.
	SpawnSessionHost *bool `yaml:"spawn_session_host"`
}

// LoadConfig reads the YAML config at path. A missing file is not an error
// (enroll can run from flags alone); all defaults are applied either way.
func LoadConfig(path string) (*Config, error) {
	var cfg Config
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	case os.IsNotExist(err):
		// fall through to defaults
	default:
		return nil, err
	}
	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.StateDir == "" {
		c.StateDir = defaults.VarDir + "/agent"
	}
	if c.SessionHostSocket == "" {
		c.SessionHostSocket = defaults.SessionHostSock
	}
	if c.SpoolDir == "" {
		c.SpoolDir = defaults.VarDir + "/spool"
	}
	if c.HealthFile == "" {
		c.HealthFile = defaults.RunDir + "/worker.health"
	}
}

// SpawnHost resolves the spawn_session_host default (true).
func (c *Config) SpawnHost() bool {
	return c.SpawnSessionHost == nil || *c.SpawnSessionHost
}
