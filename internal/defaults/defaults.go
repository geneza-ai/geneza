// Package defaults centralizes well-known ports, paths and protocol constants.
package defaults

import "time"

// Ports (the 74xx block is reserved for Geneza on the lab host).
const (
	GatewayGRPCPort = 7401 // mTLS gRPC: enrollment, node control, user/admin API
	GatewayHTTPPort = 7402 // HTTPS: artifact blobs, desired-version, CA roots
	RelayPort       = 7403 // TLS rendezvous relay
	WebProxyPort    = 7405 // web session proxy (browser path)
)

// Filesystem layout.
const (
	EtcDir          = "/etc/geneza"
	VarDir          = "/var/lib/geneza"
	RunDir          = "/run/geneza"
	SessionHostSock = "/run/geneza/session-host.sock"
)

// Signed-envelope domain-separation contexts (types.Sign / types.Verify).
const (
	ContextGrant         = "grant"
	ContextClusterConfig = "cluster-config"
	ContextManifest      = "artifact-manifest"
)

// Certificate / credential lifetimes (overridable in gateway config).
const (
	NodeCertTTL  = 24 * time.Hour
	UserCertTTL  = 8 * time.Hour
	GrantTTL     = 2 * time.Minute // window to complete the rendezvous+handshake
	JoinTokenTTL = time.Hour
)

// Tunnel constants.
const (
	NoisePrologue   = "geneza/1"
	MaxFrame        = 1 << 20 // relay/wire frame cap
	TunnelChunk     = 32 * 1024
	RelayMatchTTL   = 60 * time.Second // unmatched rendezvous slot lifetime
	RelayIdleClose  = 10 * time.Minute
	HeartbeatPeriod = 15 * time.Second
)

// Capabilities advertised by agents.
var AgentCapabilities = []string{"shell", "exec", "sftp", "forward", "attach"}
