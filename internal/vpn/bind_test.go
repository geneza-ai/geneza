package vpn

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// startTinyRelay is an in-test blind forwarder mirroring internal/relay's
// udpForwarder: REG records rid->addr, DATA{rid} is forwarded verbatim to that
// addr. Self-contained so the bind test needs no relay import.
func startTinyRelay(t *testing.T) (addr string, stop func()) {
	t.Helper()
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	table := map[uint64]netip.AddrPort{}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, src, err := uc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if n < relayHdrLen || buf[0] != relayMagic {
				continue
			}
			rid := getRid(buf[2:8])
			switch buf[1] {
			case frameREG, frameKEEPALIVE:
				mu.Lock()
				table[rid] = src
				mu.Unlock()
			case frameDATA:
				mu.Lock()
				dst, ok := table[rid]
				mu.Unlock()
				if ok {
					out := make([]byte, n)
					copy(out, buf[:n])
					uc.WriteToUDPAddrPort(out, dst)
				}
			}
		}
	}()
	return uc.LocalAddr().String(), func() { uc.Close() }
}

// TestBindRelayRoundtrip proves the P1 spine without a kernel device: two binds
// + a blind forwarder, A.Send -> relay -> B.receive yields the same bytes tagged
// with A's peer identity (so wireguard-go would route it to the right peer).
func TestBindRelayRoundtrip(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	raddr, stop := startTinyRelay(t)
	defer stop()

	bindA := NewMagicBind(1, log)
	if _, _, err := bindA.Open(0); err != nil {
		t.Fatal(err)
	}
	defer bindA.Close()
	bindB := NewMagicBind(1, log)
	if _, _, err := bindB.Open(0); err != nil {
		t.Fatal(err)
	}
	defer bindB.Close()

	var pubA, pubB [32]byte
	pubA[0], pubB[0] = 0xAA, 0xBB
	secret := make([]byte, 16)
	const ridA, ridB = uint64(0x100), uint64(0x200)

	bindA.SyncPeers([]PeerRelay{{WGPub: pubB, RelayAddr: raddr, SelfRid: ridA, PeerRid: ridB, FlowSecret: secret}})
	bindB.SyncPeers([]PeerRelay{{WGPub: pubA, RelayAddr: raddr, SelfRid: ridB, PeerRid: ridA, FlowSecret: secret}})

	time.Sleep(150 * time.Millisecond) // let REG reach the relay

	payload := []byte("wg-ciphertext-bytes")
	if err := bindA.Send([][]byte{payload}, &genezaEndpoint{wgPub: pubB}); err != nil {
		t.Fatalf("A send: %v", err)
	}

	packets := [][]byte{make([]byte, 1500)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	type res struct {
		n   int
		err error
	}
	ch := make(chan res, 1)
	go func() { n, err := bindB.receive(packets, sizes, eps); ch <- res{n, err} }()

	select {
	case r := <-ch:
		if r.err != nil || r.n != 1 {
			t.Fatalf("B receive: n=%d err=%v", r.n, r.err)
		}
		if got := string(packets[0][:sizes[0]]); got != string(payload) {
			t.Fatalf("payload mismatch: got %q want %q", got, payload)
		}
		ge, ok := eps[0].(*genezaEndpoint)
		if !ok || ge.wgPub != pubA {
			t.Fatalf("wrong endpoint tag: %+v", eps[0])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("B did not receive the relayed datagram")
	}
}

// TestParseEndpointRoundtrip: DstToString <-> ParseEndpoint round-trips.
func TestParseEndpointRoundtrip(t *testing.T) {
	b := NewMagicBind(1, nil)
	var pub [32]byte
	pub[0], pub[31] = 0x12, 0x34
	orig := &genezaEndpoint{wgPub: pub}
	ep, err := b.ParseEndpoint(orig.DstToString())
	if err != nil {
		t.Fatal(err)
	}
	if ge := ep.(*genezaEndpoint); ge.wgPub != pub {
		t.Fatalf("round-trip mismatch: %x", ge.wgPub)
	}
	if _, err := b.ParseEndpoint("1.2.3.4:51820"); err == nil {
		t.Fatal("expected non-gz endpoint to be rejected")
	}
}
