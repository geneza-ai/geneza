package relay

import (
	"io"
	"net"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// turnserver.go embeds a standard pion/turn server (RFC 8656) as the overlay's
// blind relay floor — replacing the hand-rolled udpforward. It forwards opaque
// ChannelData/Data verbatim (payload stays E2E WireGuard; the relay never
// decrypts), authenticated by gateway-minted coturn-style ephemeral credentials
// validated against a shared secret with NO stored per-user state. We do not own
// a relay protocol anymore — TURN is the standard. See docs/dataplane-libs-plan.md.
type turnRelay struct {
	srv *turn.Server
	pc  net.PacketConn
}

// newTURNRelay binds the data UDP socket (relay still owns it, co-resident with
// the TCP rendezvous splice) and starts the TURN server on it. publicIP is the
// relay address advertised to clients (deployment-specific; the lab uses the
// internal vmbr5 IP via relay_data_addrs).
func newTURNRelay(addr, realm, sharedSecret, publicIP string, logw io.Writer) (*turnRelay, error) {
	pc, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return nil, err
	}
	lf := logging.NewDefaultLoggerFactory()
	lf.Writer = logw
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: realm,
		// Recompute-and-verify: parses the embedded expiry, rejects expired creds,
		// derives the integrity key from the shared secret — zero stored state.
		AuthHandler:   turn.LongTermTURNRESTAuthHandler(sharedSecret, lf.NewLogger("turn")),
		LoggerFactory: lf,
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP(publicIP),
				Address:      "0.0.0.0",
			},
		}},
	})
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return &turnRelay{srv: srv, pc: pc}, nil
}

func (t *turnRelay) close() error     { return t.srv.Close() }
func (t *turnRelay) allocations() int { return t.srv.AllocationCount() }
