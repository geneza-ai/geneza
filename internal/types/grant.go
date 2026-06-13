package types

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"time"
)

// Session actions.
const (
	ActionShell   = "shell"
	ActionExec    = "exec"
	ActionSFTP    = "sftp"
	ActionForward = "forward"
	ActionAttach  = "attach"
	ActionVPN     = "vpn" // L3 packet routing (subnet-route / exit-node)
)

// Client paths (trust distinction between native E2E and web-proxy).
const (
	PathNative = "native"
	PathWeb    = "web"
)

// SessionGrant is the gateway-signed, single-session credential. The agent
// enforces it independently of the gateway: signature by a trusted grant key,
// expiry, node binding, action scope, and the requirement that the tunnel's
// remote Noise static equals ClientNoisePub.
type SessionGrant struct {
	V              int           `json:"v"`
	ID             string        `json:"id"`
	User           string        `json:"user"`
	Roles          []string      `json:"roles,omitempty"`
	WorkspaceID    string        `json:"workspace_id,omitempty"` // tenant; agent asserts == its own
	NetworkVNI     uint32        `json:"network_vni,omitempty"`  // tenant Network segment id (data-plane demux)
	NodeID         string        `json:"node_id"`
	Action         string        `json:"action"`
	Command        string        `json:"command,omitempty"`
	AttachID       string        `json:"attach_id,omitempty"` // host session id for attach
	AllowPTY       bool          `json:"allow_pty,omitempty"`
	AllowDetach    bool          `json:"allow_detach,omitempty"`
	ForwardTarget  string        `json:"forward_target,omitempty"`
	ClientNoisePub []byte        `json:"client_noise_pub"`
	AgentNoisePub  []byte        `json:"agent_noise_pub"`
	RelayAddr      string        `json:"relay_addr"`
	RelayToken     string        `json:"relay_token"`
	ClientPath     string        `json:"client_path,omitempty"`
	IssuedAt       time.Time     `json:"iat"`
	ExpiresAt      time.Time     `json:"exp"` // grant validity (rendezvous window)
	MaxSessionTTL  time.Duration `json:"max_session_ttl,omitempty"`
	Record         bool          `json:"record,omitempty"`
	// Service access: the named service this grant authorizes (empty for plain
	// node access). The agent enforces ForwardTarget/Routes derived from it.
	Service     string `json:"service,omitempty"`
	ServiceKind string `json:"service_kind,omitempty"`
	// VPN (action=vpn): the CIDRs the agent will route for this client and the
	// overlay IP assigned to the client. Routes/exit-node = ["0.0.0.0/0"].
	Routes    []string `json:"routes,omitempty"`
	OverlayIP string   `json:"overlay_ip,omitempty"`
}

// Validate performs the agent-side checks that do not depend on the tunnel.
// nodeID/agentNoisePub identify the local agent. now is injected for tests.
func (g *SessionGrant) Validate(nodeID string, agentNoisePub []byte, now time.Time) error {
	if g.V != 1 {
		return fmt.Errorf("unsupported grant version %d", g.V)
	}
	if g.NodeID != nodeID {
		return fmt.Errorf("grant is for node %q, this is %q", g.NodeID, nodeID)
	}
	if !bytes.Equal(g.AgentNoisePub, agentNoisePub) {
		return fmt.Errorf("grant agent noise key mismatch")
	}
	if now.Before(g.IssuedAt.Add(-2 * time.Minute)) {
		return fmt.Errorf("grant not yet valid (clock skew?)")
	}
	if now.After(g.ExpiresAt) {
		return fmt.Errorf("grant expired at %s", g.ExpiresAt.Format(time.RFC3339))
	}
	if len(g.ClientNoisePub) != 32 {
		return fmt.Errorf("grant has invalid client noise key")
	}
	switch g.Action {
	case ActionShell, ActionExec, ActionSFTP, ActionForward, ActionAttach, ActionVPN:
	default:
		return fmt.Errorf("unknown action %q", g.Action)
	}
	if g.Action == ActionExec && g.Command == "" {
		return fmt.Errorf("exec grant without command")
	}
	if g.Action == ActionAttach && g.AttachID == "" {
		return fmt.Errorf("attach grant without attach_id")
	}
	if g.Action == ActionForward && g.ForwardTarget == "" {
		return fmt.Errorf("forward grant without target")
	}
	if g.Action == ActionVPN && len(g.Routes) == 0 {
		return fmt.Errorf("vpn grant without routes")
	}
	return nil
}

// VerifyGrant verifies a signed grant envelope against the trusted grant keys
// (from cluster config) and returns the parsed grant.
func VerifyGrant(trusted map[string]ed25519.PublicKey, s *Signed) (*SessionGrant, error) {
	var g SessionGrant
	if _, err := Verify(trusted, "grant", s, &g); err != nil {
		return nil, err
	}
	return &g, nil
}
