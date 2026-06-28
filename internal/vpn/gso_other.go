//go:build !linux

package vpn

// gso_other.go is the non-Linux fallback for gsoConn: same API, but per-datagram
// (no UDP_SEGMENT/UDP_GRO, which are Linux-only). The bind compiles and runs
// identically on macOS/Windows — just without kernel offload — so Geneza stays
// single-data-plane and cross-platform (see geneza-dataplane-decision). macOS
// (UDP via sendmsg) and Windows (UDP_SEND_MSG_SIZE) batch APIs can be added later
// behind this same type without touching icebind.go.

import (
	"net"
	"net/netip"
)

// gsoBatchSize is 1 off Linux (no kernel offload); the bind reads it for BatchSize().
const gsoBatchSize = 1

type gsoConn struct {
	uc *net.UDPConn
}

func newGSOConn(uc *net.UDPConn) *gsoConn { return &gsoConn{uc: uc} }

func (g *gsoConn) batchSize() int      { return gsoBatchSize }
func (g *gsoConn) LocalAddr() net.Addr { return g.uc.LocalAddr() }
func (g *gsoConn) Close() error        { return g.uc.Close() }

func (g *gsoConn) WriteTo(p []byte, addr net.Addr) (int, error) { return g.uc.WriteTo(p, addr) }

func (g *gsoConn) WriteBatchTo(bufs [][]byte, addr netip.AddrPort) error {
	for _, b := range bufs {
		if _, err := g.uc.WriteToUDPAddrPort(b, addr); err != nil {
			return err
		}
	}
	return nil
}

func (g *gsoConn) ReadBatchInto(out [][]byte, sizes []int, srcs []netip.AddrPort) (int, error) {
	n, ap, err := g.uc.ReadFromUDPAddrPort(out[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	srcs[0] = ap
	return 1, nil
}
