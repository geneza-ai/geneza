package vpn

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// fakeTUN is an in-memory TUN: writes land on outbound, reads come from inbound.
type fakeTUN struct {
	inbound  chan []byte
	outbound chan []byte
	closed   chan struct{}
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{
		inbound:  make(chan []byte, 16),
		outbound: make(chan []byte, 16),
		closed:   make(chan struct{}),
	}
}

func (t *fakeTUN) Read(p []byte) (int, error) {
	select {
	case pkt := <-t.inbound:
		return copy(p, pkt), nil
	case <-t.closed:
		return 0, io.EOF
	}
}

func (t *fakeTUN) Write(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	select {
	case t.outbound <- cp:
		return len(p), nil
	case <-t.closed:
		return 0, io.ErrClosedPipe
	}
}

func (t *fakeTUN) Name() string { return "faketun0" }

func (t *fakeTUN) Close() error {
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	return nil
}

// TestPumpRoundTrip checks that an IP packet written into one TUN is framed
// over the conn and delivered to the peer TUN, in both directions.
func TestPumpRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	tunA, tunB := newFakeTUN(), newFakeTUN()
	closeA := func() { a.Close(); tunA.Close() }
	closeB := func() { b.Close(); tunB.Close() }
	go Pump(tunA, a, closeA)
	go Pump(tunB, b, closeB)

	pkt := []byte{0x45, 0x00, 0x00, 0x14, 0xde, 0xad, 0xbe, 0xef} // looks-like IPv4 header bytes
	tunA.inbound <- pkt
	select {
	case got := <-tunB.outbound:
		if !bytes.Equal(got, pkt) {
			t.Fatalf("A->B packet mismatch: got %x want %x", got, pkt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("A->B packet not delivered")
	}

	pkt2 := []byte{0x45, 0x11, 0x22, 0x33}
	tunB.inbound <- pkt2
	select {
	case got := <-tunA.outbound:
		if !bytes.Equal(got, pkt2) {
			t.Fatalf("B->A packet mismatch: got %x want %x", got, pkt2)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("B->A packet not delivered")
	}
}

// TestPumpClosePropagates verifies that closing the conn tears down both ends.
func TestPumpClosePropagates(t *testing.T) {
	a, b := net.Pipe()
	tun := newFakeTUN()
	done := make(chan struct{})
	go func() { Pump(tun, a, func() { a.Close(); tun.Close() }); close(done) }()
	b.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Pump did not return after conn close")
	}
}
