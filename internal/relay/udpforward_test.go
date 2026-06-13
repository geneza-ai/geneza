package relay

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

func relayFrame(typ byte, rid uint64, payload []byte) []byte {
	f := make([]byte, udpHdrLen+len(payload))
	f[0] = udpMagic
	f[1] = typ
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], rid)
	copy(f[2:8], tmp[2:])
	copy(f[udpHdrLen:], payload)
	return f
}

func mustUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func waitEntries(t *testing.T, f *udpForwarder, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if f.entryCount() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("forwarder entries = %d, want %d", f.entryCount(), want)
}

func newTestForwarder(t *testing.T, idle time.Duration) (*udpForwarder, *net.UDPAddr) {
	t.Helper()
	f, err := newUDPForwarder("127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if idle > 0 {
		f.idle = idle
	}
	go f.serve()
	t.Cleanup(func() { f.close() })
	return f, f.conn.LocalAddr().(*net.UDPAddr)
}

// TestUDPForwardRoundtrip: A and B register mailboxes; A's DATA addressed to B's
// rid is forwarded verbatim to B.
func TestUDPForwardRoundtrip(t *testing.T) {
	f, raddr := newTestForwarder(t, 0)
	ca, cb := mustUDP(t), mustUDP(t)
	defer ca.Close()
	defer cb.Close()
	const ridA, ridB = uint64(0x0a0a0a), uint64(0x0b0b0b)
	tail := make([]byte, 16) // shape gate

	ca.WriteToUDP(relayFrame(udpREG, ridA, tail), raddr)
	cb.WriteToUDP(relayFrame(udpREG, ridB, tail), raddr)
	waitEntries(t, f, 2)

	ca.WriteToUDP(relayFrame(udpDATA, ridB, []byte("ping")), raddr)
	cb.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := cb.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("B read: %v", err)
	}
	got := buf[:n]
	if got[1] != udpDATA || getRid6(got[2:8]) != ridB || !bytes.Equal(got[udpHdrLen:], []byte("ping")) {
		t.Fatalf("B got wrong frame: %x", got)
	}
}

// TestUDPForwardShapeGateAndUnknownRid: a too-short REG creates no mailbox, and
// DATA to an unregistered rid is dropped (no reflection).
func TestUDPForwardShapeGateAndUnknownRid(t *testing.T) {
	f, raddr := newTestForwarder(t, 0)
	ca, cb := mustUDP(t), mustUDP(t)
	defer ca.Close()
	defer cb.Close()

	// Short REG (no 16-byte tail) -> rejected, no mailbox.
	ca.WriteToUDP(relayFrame(udpREG, 0x010203, []byte{1, 2}), raddr)
	time.Sleep(100 * time.Millisecond)
	if f.entryCount() != 0 {
		t.Fatalf("short REG created a mailbox: entries=%d", f.entryCount())
	}

	// DATA to an unregistered rid -> dropped; B (listening) receives nothing.
	ca.WriteToUDP(relayFrame(udpDATA, 0x999999, []byte("x")), raddr)
	cb.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := cb.ReadFromUDP(make([]byte, 64)); err == nil {
		t.Fatal("unexpected delivery for unknown rid")
	}
}

// TestUDPForwardIdleExpiry: a mailbox with no refresh idle-expires.
func TestUDPForwardIdleExpiry(t *testing.T) {
	f, raddr := newTestForwarder(t, 80*time.Millisecond)
	ca := mustUDP(t)
	defer ca.Close()
	ca.WriteToUDP(relayFrame(udpREG, 0x424242, make([]byte, 16)), raddr)
	waitEntries(t, f, 1)
	// Wait past idle + a sweep tick (idle/2) without refreshing.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if f.entryCount() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("idle mailbox not expired: entries=%d", f.entryCount())
}
