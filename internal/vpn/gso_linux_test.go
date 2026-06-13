//go:build linux

package vpn

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestGSORoundTrip exercises the real kernel GSO/GRO path: coalesce a batch into
// sendmmsg/UDP_SEGMENT, receive + split via recvmmsg/UDP_GRO, verify every
// datagram arrives intact and in order. Falls back gracefully if the loopback
// path doesn't offload (the split handles single datagrams too).
func TestGSORoundTrip(t *testing.T) {
	lo := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	rxc, err := net.ListenUDP("udp4", lo)
	if err != nil {
		t.Fatal(err)
	}
	txc, err := net.ListenUDP("udp4", lo)
	if err != nil {
		t.Fatal(err)
	}
	grx := newGSOConn(rxc)
	gtx := newGSOConn(txc)
	defer grx.Close()
	defer gtx.Close()
	t.Logf("tx offload=%v rx offload=%v", gtx.txOffload, grx.rxOffload)

	dst := netip.MustParseAddrPort(rxc.LocalAddr().String())
	const n, sz = 40, 1200
	bufs := make([][]byte, n)
	for i := range bufs {
		b := make([]byte, 0, 1<<16) // large cap so coalesce can append into it
		b = append(b, make([]byte, sz)...)
		for j := range b {
			b[j] = byte(i)
		}
		bufs[i] = b
	}
	if err := gtx.WriteBatchTo(bufs, dst); err != nil {
		t.Fatalf("WriteBatchTo: %v", err)
	}

	out := make([][]byte, gsoBatchSize)
	for i := range out {
		out[i] = make([]byte, iceReadBuf)
	}
	sizes := make([]int, gsoBatchSize)
	srcs := make([]netip.AddrPort, gsoBatchSize)
	_ = rxc.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := 0
	for got < n {
		m, err := grx.ReadBatchInto(out, sizes, srcs)
		if err != nil {
			t.Fatalf("ReadBatchInto after %d/%d: %v", got, n, err)
		}
		for i := 0; i < m; i++ {
			if sizes[i] != sz {
				t.Fatalf("pkt %d: size %d != %d", got, sizes[i], sz)
			}
			want := byte(got)
			for j := 0; j < sizes[i]; j++ {
				if out[i][j] != want {
					t.Fatalf("pkt %d byte %d = %d, want %d (ordering/content mismatch)", got, j, out[i][j], want)
				}
			}
			got++
		}
	}
	if got != n {
		t.Fatalf("received %d, want %d", got, n)
	}
}
