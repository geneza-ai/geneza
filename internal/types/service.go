package types

// Service kinds. A node exposes services; policy authorizes access to a
// specific service, not just "the node." Kinds split into three access shapes:
//
//	host services   shell / exec / sftp    — run on the node itself (the host IS the service)
//	forwarded svcs  tcp/rdp/vnc/http/...    — TCP-forward to an addr reachable from the node
//	network svcs    subnet-route / exit-node — L3 packet routing through the node (VPN)
const (
	KindShell    = "shell"
	KindExec     = "exec"
	KindSFTP     = "sftp"
	KindTCP      = "tcp"
	KindRDP      = "rdp"
	KindVNC      = "vnc"
	KindHTTP     = "http"
	KindPostgres = "postgres"
	KindMySQL    = "mysql"
	KindSubnet   = "subnet-route"
	KindExitNode = "exit-node"
)

// Service describes one access target a node exposes.
type Service struct {
	Name   string            `json:"name"`
	Kind   string            `json:"kind"`
	Addr   string            `json:"addr,omitempty"` // host:port (forwarded), CIDR (subnet-route)
	NodeID string            `json:"node_id,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

// Action returns the session action that carries this service kind:
//
//	host services   -> their own action (shell/exec/sftp)
//	forwarded svcs  -> "forward" (TCP-forward to Addr)
//	network svcs    -> "vpn"     (L3 packet routing)
func (s Service) Action() string {
	switch s.Kind {
	case KindShell:
		return ActionShell
	case KindExec:
		return ActionExec
	case KindSFTP:
		return ActionSFTP
	case KindSubnet, KindExitNode:
		return ActionVPN
	default: // tcp/rdp/vnc/http/postgres/mysql and any other forwarded kind
		return ActionForward
	}
}

// IsNetwork reports whether the service routes L3 packets (VPN) rather than a
// single TCP target.
func (s Service) IsNetwork() bool { return s.Kind == KindSubnet || s.Kind == KindExitNode }

// KnownServiceKind reports whether kind is a recognized service kind.
func KnownServiceKind(kind string) bool {
	switch kind {
	case KindShell, KindExec, KindSFTP, KindTCP, KindRDP, KindVNC, KindHTTP,
		KindPostgres, KindMySQL, KindSubnet, KindExitNode:
		return true
	}
	return false
}
