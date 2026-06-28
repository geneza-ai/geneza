// Package defaults centralizes well-known ports, paths and protocol constants.
package defaults

import "time"

// Ports (the 74xx block is reserved for Geneza on the lab host).
const (
	ControllerGRPCPort = 7401 // mTLS gRPC: enrollment, node control, user/admin API
	ControllerHTTPPort = 7402 // HTTPS: artifact blobs, desired-version, CA roots
	RelayPort       = 7403 // TLS rendezvous relay (TCP: Noise/SSH sessions)
	RelayDataPort   = 7404 // blind DERP-lite UDP forwarder (WireGuard data plane)
	WebProxyPort    = 7405 // web session proxy (browser path)
)

// Filesystem layout.
const (
	EtcDir          = "/etc/geneza"
	VarDir          = "/var/lib/geneza"
	RunDir          = "/run/geneza"
	SessionHostSock = "/run/geneza/session-host.sock"
)

// WorkerHealthFileName is the liveness file the worker touches inside run_dir
// and the bootstrap's health gate watches after a binary swap. Both sides MUST
// agree on this name — it lives here so they cannot drift.
const WorkerHealthFileName = "worker.health"

// WorkerHealthFile is the conventional absolute path under the default run dir.
const WorkerHealthFile = RunDir + "/" + WorkerHealthFileName

// Signed-envelope domain-separation contexts (types.Sign / types.Verify).
const (
	ContextGrant         = "grant"
	ContextClusterConfig = "cluster-config"
	ContextManifest      = "artifact-manifest"
	ContextRootKeys      = "artifact-root" // root doc authorizing the signing-key set
	// ContextTrustAnchors domain-separates the offline/threshold-signed fleet trust
	// anchors (who may sign the routine map + grants, which CA roots are trusted).
	ContextTrustAnchors = "trust-anchors"
	// ContextRoutineMap domain-separates the online grant-key-signed routing view
	// (relays, controller endpoints) bound to a specific trust-anchors version.
	ContextRoutineMap = "routine-map"
	// ContextSessionPolicy domain-separates realtime session-enforcement messages
	// (lease / policy-delta / revoke) so a grant signature can never be replayed
	// as a lease and vice-versa, even though both are signed by the grant key.
	ContextSessionPolicy = "session-policy"
)

// SessionLeaseTTL is the fail-closed data-path lease lifetime for a direct (p2p)
// session. It must exceed the worst-case agent control-stream reconnect (so a
// brief outage re-leases before starvation) yet be short enough that a lost
// revoke or a partition tears the conduit in ~2 minutes, not at the 24h session
// TTL. The controller re-pushes a fresh lease every reauth sweep (15s << this).
const SessionLeaseTTL = 120 * time.Second

// Certificate / credential lifetimes (overridable in controller config).
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
	RelayDataIdle   = 60 * time.Second // blind UDP forwarder: idle-expire a mailbox
	HeartbeatPeriod = 15 * time.Second
)

// Capabilities advertised by agents.
var AgentCapabilities = []string{"shell", "exec", "sftp", "forward", "attach"}
