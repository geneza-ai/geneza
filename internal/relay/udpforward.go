package relay

import (
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"osie.cloud/geneza/internal/defaults"
)

// udpforward.go is the blind DERP-lite WireGuard data forwarder: a connectionless
// UDP relay that shuttles opaque, end-to-end-encrypted WG datagrams between two
// endpoints by an opaque routing id (rid). It NEVER parses a WG payload, holds NO
// key, and learns nothing but ephemeral per-flow rids (gateway-minted; meaningless
// without the gateway's private rid→flow map). See docs/magicsock-design.md §3.
//
// It is a separate UDP listener co-resident in the Relay process; the TCP
// rendezvous splice (Noise/SSH) is untouched.

// Frame: byte0 magic 0x91, byte1 type, bytes2..7 rid (48-bit BE), bytes8.. payload.
const (
	udpMagic   = 0x91
	udpHdrLen  = 8
	udpReadBuf = 1 << 16

	udpREG       = 1
	udpDATA      = 2
	udpKEEPALIVE = 3
	udpSTUNREQ   = 4
	udpSTUNRESP  = 5
	udpCLOSE     = 6

	// minRegTail is the shape gate on REG payloads: a real endpoint sends an
	// HMAC tail (≥16 bytes); blind scanners that just spray short packets are
	// rejected without ever creating a mailbox (anti-amplification).
	minRegTail = 16
	// maxMailboxes caps the table so a flood of distinct rids cannot exhaust
	// memory (fail closed past the cap).
	maxMailboxes = 65536
)

type udpMailbox struct {
	addr     netip.AddrPort
	lastSeen time.Time
}

// udpForwarder owns the data-plane UDP socket and the rid→mailbox table.
type udpForwarder struct {
	conn *net.UDPConn
	log  *slog.Logger
	idle time.Duration

	mu    sync.Mutex
	table map[uint64]*udpMailbox
}

func newUDPForwarder(addr string, log *slog.Logger) (*udpForwarder, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	return &udpForwarder{
		conn:  c,
		log:   log.With("component", "udpforward"),
		idle:  defaults.RelayDataIdle,
		table: map[uint64]*udpMailbox{},
	}, nil
}

// serve runs the read loop + a sweeper until the conn is closed (Shutdown).
func (f *udpForwarder) serve() {
	f.log.Info("relay: udp data forwarder listening", "addr", f.conn.LocalAddr().String())
	stopSweep := make(chan struct{})
	go f.sweepLoop(stopSweep)
	defer close(stopSweep)

	buf := make([]byte, udpReadBuf)
	for {
		n, src, err := f.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return // conn closed by Shutdown -> exit
		}
		f.handle(buf[:n], src)
	}
}

func (f *udpForwarder) handle(pkt []byte, src netip.AddrPort) {
	if len(pkt) < udpHdrLen || pkt[0] != udpMagic {
		return // not our frame -> drop (no reflection)
	}
	rid := getRid6(pkt[2:8])
	switch pkt[1] {
	case udpREG:
		if len(pkt) < udpHdrLen+minRegTail {
			return // shape gate
		}
		f.register(rid, src)
	case udpKEEPALIVE:
		f.register(rid, src) // refresh mailbox + NAT mapping
	case udpDATA:
		f.forward(rid, pkt)
	// udpSTUNREQ -> STUN-lite echo lands in P2 (dropped for now: no amplification)
	default:
		// unknown / CLOSE -> ignore
	}
}

// register claims (or refreshes) a mailbox: the first sender of an rid owns it.
// The relay cannot authenticate the claim (it holds no secret) — possession of
// the gateway-minted rid IS the capability; WG AEAD authenticates end to end.
func (f *udpForwarder) register(rid uint64, src netip.AddrPort) {
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	if mb := f.table[rid]; mb != nil {
		mb.addr = src
		mb.lastSeen = now
		return
	}
	if len(f.table) >= maxMailboxes {
		return // fail closed
	}
	f.table[rid] = &udpMailbox{addr: src, lastSeen: now}
}

// forward shuttles a DATA frame to the destination rid's mailbox, verbatim and
// opaque. Unknown rid -> dropped (no reflection to unregistered addresses).
func (f *udpForwarder) forward(dstRid uint64, pkt []byte) {
	f.mu.Lock()
	mb := f.table[dstRid]
	f.mu.Unlock()
	if mb == nil {
		return
	}
	if _, err := f.conn.WriteToUDPAddrPort(pkt, mb.addr); err != nil {
		f.log.Debug("udp forward failed", "err", err)
	}
}

func (f *udpForwarder) sweepLoop(stop <-chan struct{}) {
	t := time.NewTicker(f.idle / 2)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			cutoff := time.Now().Add(-f.idle)
			f.mu.Lock()
			for rid, mb := range f.table {
				if mb.lastSeen.Before(cutoff) {
					delete(f.table, rid)
				}
			}
			f.mu.Unlock()
		}
	}
}

func (f *udpForwarder) close() error { return f.conn.Close() }

func (f *udpForwarder) entryCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.table)
}

func getRid6(b []byte) uint64 {
	var tmp [8]byte
	copy(tmp[2:], b[:6])
	return binary.BigEndian.Uint64(tmp[:])
}
