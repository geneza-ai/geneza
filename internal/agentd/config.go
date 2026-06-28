// Package agentd implements the Geneza agent worker: enrollment, the
// persistent NodeControl channel to the controller, session-offer handling and
// the relay/Noise/SSH data path, bridging tunnel channels to the separately
// supervised session-host process over its unix-socket gRPC API.
package agentd

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"geneza.io/internal/defaults"
	"geneza.io/internal/keysource"
)

// Config is /etc/geneza/agent.yaml. Zero values fall back to defaults so a
// minimal config only needs controller_grpc_addr.
type Config struct {
	ControllerGRPCAddr   string            `yaml:"controller_grpc_addr"`
	ControllerHTTPURL    string            `yaml:"controller_http_url"`
	StateDir          string            `yaml:"state_dir"`
	Name              string            `yaml:"name"`
	Labels            map[string]string `yaml:"labels"`
	SessionHostSocket string            `yaml:"session_host_socket"`
	SpoolDir          string            `yaml:"spool_dir"`
	HealthFile        string            `yaml:"health_file"`
	// SpawnSessionHost defaults to true; bootstrap-supervised deployments run
	// the session host themselves and pass --no-spawn-session-host instead.
	SpawnSessionHost *bool `yaml:"spawn_session_host"`
	// Services this node exposes beyond the implicit shell/exec/sftp host
	// access: tcp/rdp/vnc/http/postgres/mysql (addr=host:port reachable from the
	// node), subnet-route (addr=CIDR), exit-node (addr empty). Each is policy-
	// gated by name/kind/labels.
	Services []ServiceDecl `yaml:"services"`
	// Dataplane selects the per-Network overlay backend: "kernel" (kernel
	// WireGuard via wgctrl; direct-only) or "userspace" (wireguard-go over pion
	// ICE/TURN/STUN: relay floor + auto direct upgrade). Defaults to "kernel".
	Dataplane string `yaml:"dataplane"`
	// DataplaneRelayOnly forces the userspace path to use ONLY the TURN relay
	// candidate (no host/srflx), isolating the floor for the P-libs1 proof.
	// Default false = full ICE (pion auto-selects direct when reachable).
	DataplaneRelayOnly bool `yaml:"dataplane_relay_only"`
	// RelayHomedControl lets the agent home its control stream through a relay
	// when the signed map advertises a control-mux relay (default true; nil = on).
	// It is inert unless the fleet offers one, so a single-node agent keeps dialing
	// the controller directly. Set false to force direct everywhere (staged rollout).
	RelayHomedControl *bool `yaml:"relay_homed_control"`
	// NodeKeySource optionally backs the node identity private key by an
	// HSM/PKCS#11 token (backend: pkcs11) instead of node.key on disk. The node key
	// is ECDSA P-256, which every PKCS#11 token supports. Empty = on-disk node.key
	// under state_dir (the default, byte-for-byte unchanged). With a token backend
	// the private bytes never enter the agent: a host compromise cannot exfiltrate
	// the identity, so impersonation requires the token to stay resident.
	NodeKeySource KeySourceConfig `yaml:"node_key_source,omitempty"`
}

// KeySourceConfig selects where the agent's node identity private key is held.
// An absent or backend-empty block means the on-disk node.key under state_dir
// (the default). With backend: pkcs11 the key lives on a token and signing —
// the mTLS client handshake and recording-manifest signature — runs on the
// token, so the private bytes never enter the agent process.
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
// on-disk node.key used when the backend is file/empty (file-backed keys live
// under state_dir, so the path is fixed, not operator-set).
func (k KeySourceConfig) spec(defaultPath string) keysource.Spec {
	return keysource.Spec{
		Backend:    k.Backend,
		Path:       defaultPath,
		Module:     k.Module,
		TokenLabel: k.TokenLabel,
		Slot:       k.Slot,
		PIN:        k.PIN,
		KeyLabel:   k.KeyLabel,
		KeyID:      k.KeyID,
	}
}

// usesPKCS11 reports whether this block selects the token backend.
func (k KeySourceConfig) usesPKCS11() bool { return k.Backend == keysource.BackendPKCS11 }

// validate checks a key-source block. file/empty needs nothing; pkcs11 needs a
// module, a token selector, and a key selector, so a half-configured token fails
// loudly at config time rather than with an obscure error during enrollment.
func (k KeySourceConfig) validate() error {
	switch k.Backend {
	case "", keysource.BackendFile:
		return nil
	case keysource.BackendPKCS11:
		if k.Module == "" {
			return fmt.Errorf("node_key_source.module is required for backend: pkcs11")
		}
		if k.TokenLabel == "" && k.Slot == nil {
			return fmt.Errorf("node_key_source: token_label or slot is required for backend: pkcs11")
		}
		if k.KeyLabel == "" && k.KeyID == "" {
			return fmt.Errorf("node_key_source: key_label or key_id is required for backend: pkcs11")
		}
		return nil
	default:
		return fmt.Errorf("node_key_source.backend %q is invalid (want \"file\" or \"pkcs11\")", k.Backend)
	}
}

// nodeKeySource resolves the node-key source: the on-disk default reads node.key
// under the state dir.
func (c *Config) nodeKeySource() keysource.Spec {
	return c.NodeKeySource.spec(filepath.Join(c.StateDir, fileNodeKey))
}

// RelayHoming reports whether the agent may home its control stream through a
// relay (default true; an absent config key means on).
func (c *Config) RelayHoming() bool {
	return c.RelayHomedControl == nil || *c.RelayHomedControl
}

// ServiceDecl declares one exposed service in agent.yaml.
type ServiceDecl struct {
	Name   string            `yaml:"name"`
	Kind   string            `yaml:"kind"`
	Addr   string            `yaml:"addr"`
	Labels map[string]string `yaml:"labels"`
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
	if err := cfg.NodeKeySource.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
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
		c.HealthFile = defaults.WorkerHealthFile
	}
}

// SpawnHost resolves the spawn_session_host default (true).
func (c *Config) SpawnHost() bool {
	return c.SpawnSessionHost == nil || *c.SpawnSessionHost
}
