package icewire

import (
	"net"
	"time"

	"github.com/pion/stun/v3"
)

// RegionEndpoint pairs a region id with a STUN-probeable address.
type RegionEndpoint struct {
	Region string
	Addr   string // host:port
}

// ClosestRegion probes each region's relay once and returns the region with the
// lowest round-trip time, or "" if none answered. The caller reports the result
// as its home region so the controller hands it that region's relay candidates.
func ClosestRegion(endpoints []RegionEndpoint, timeout time.Duration) string {
	best := ""
	var bestRTT time.Duration
	for _, e := range endpoints {
		rtt, ok := ProbeRTT(e.Addr, timeout)
		if !ok {
			continue
		}
		if best == "" || rtt < bestRTT {
			best, bestRTT = e.Region, rtt
		}
	}
	return best
}

// ProbeRTT measures the round-trip time to a STUN/relay endpoint by sending one
// STUN Binding request and timing the response. It is pure OUTBOUND UDP — the
// caller (a client or agent) uses it to pick its closest relay region; the
// controller never measures closeness, preserving the dial-out-only property. The
// bool is false when the endpoint did not answer within timeout.
func ProbeRTT(stunAddr string, timeout time.Duration) (time.Duration, bool) {
	conn, err := net.DialTimeout("udp", stunAddr, timeout)
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	start := time.Now()
	if _, err := conn.Write(req.Raw); err != nil {
		return 0, false
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, false
	}
	rtt := time.Since(start)
	resp := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
	if err := resp.Decode(); err != nil || resp.Type != stun.BindingSuccess {
		return 0, false
	}
	return rtt, true
}
