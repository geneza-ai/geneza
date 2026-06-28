package relay

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // coturn-REST credentials are HMAC-SHA1 by spec
	"encoding/base64"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// turnserver.go embeds a standard pion/turn server (RFC 8656) as the overlay's
// blind relay floor — replacing the hand-rolled udpforward. It forwards opaque
// ChannelData/Data verbatim (payload stays E2E WireGuard; the relay never
// decrypts), authenticated by controller-minted coturn-style ephemeral credentials
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
func newTURNRelay(addr, realm, region string, secrets map[string]RegionSecret, publicIP string, logw io.Writer) (*turnRelay, error) {
	pc, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return nil, err
	}
	lf := logging.NewDefaultLoggerFactory()
	lf.Writer = logw
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm:         realm,
		AuthHandler:   regionAuthHandler(region, secrets, lf.NewLogger("turn")),
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

// regionAuthHandler validates a region-tagged coturn-REST credential whose
// username is "<expiry>:<region>:<id>". It is recompute-and-verify (no stored
// per-user state): it rejects an expired credential and one tagged for a
// DIFFERENT region — so this relay only honors credentials minted for its own
// region, which confines a leaked region secret to that region. The integrity
// key is derived from the region's current secret exactly as a coturn REST
// server does (HMAC-SHA1 of the username, base64, then the long-term key).
//
// Note: pion verifies message integrity against the single key this returns, so
// only the region's current secret is honored. Rotating a region's secret is
// therefore a synchronized flag-day — controller and relays swap Current together.
// A zero-downtime overlap would need the minted username to name the secret
// version so two keys could be tried; that is a deliberate follow-up.
func regionAuthHandler(region string, secrets map[string]RegionSecret, logger logging.LeveledLogger) turn.AuthHandler {
	return func(ra *turn.RequestAttributes) (string, []byte, bool) {
		fields := strings.SplitN(ra.Username, ":", 3)
		if len(fields) != 3 {
			logger.Warnf("rejecting malformed TURN username %q", ra.Username)
			return "", nil, false
		}
		ts, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil || ts < time.Now().Unix() {
			return "", nil, false
		}
		if fields[1] != region {
			logger.Warnf("rejecting TURN credential for foreign region %q (this relay serves %q)", fields[1], region)
			return "", nil, false
		}
		sec, ok := secrets[region]
		if !ok || sec.Current == "" {
			return "", nil, false
		}
		mac := hmac.New(sha1.New, []byte(sec.Current))
		_, _ = mac.Write([]byte(ra.Username))
		password := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		return ra.Username, turn.GenerateAuthKey(ra.Username, ra.Realm, password), true
	}
}
