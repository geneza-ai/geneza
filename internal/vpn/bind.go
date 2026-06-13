package vpn

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// bind.go implements magicsock-lite: a custom wireguard-go conn.Bind that
// multiplexes one UDP socket between a blind DERP-lite relay floor and (P2+) a
// direct path, choosing per packet. The peer endpoint wireguard-go holds is a
// stable *genezaEndpoint keyed by WG pubkey — the live path floats inside the
// bind, so wireguard-go never re-handshakes on a path switch (the Tailscale
// property). See docs/magicsock-design.md.
//
// P1 scope: relay floor only. Every Send frames DATA to the peer's relay
// mailbox; the path state is pinned to stRelay. STUN/disco/direct land in P2+.

// Relay frame wire format (docs/magicsock-design.md §3.2):
//
//	byte 0     magic/version = 0x91   (also the demux discriminator vs raw WG)
//	byte 1     type
//	bytes 2..7 routing id (rid), 48-bit big-endian
//	bytes 8..N opaque payload
const (
	relayMagic  = 0x91
	relayHdrLen = 8

	frameREG       = 1
	frameDATA      = 2
	frameKEEPALIVE = 3
	frameSTUNREQ   = 4
	frameSTUNRESP  = 5
	frameCLOSE     = 6

	ridMax            = (1 << 48) - 1
	relayKeepaliveInt = 15 * time.Second
)

// pathState is the per-peer path the bind currently uses.
type pathState int32

const (
	stRelay pathState = iota // floor (always available)
	stProbing
	stDirect
	stFallback
)

// genezaEndpoint identifies a PEER by WG pubkey, not an address — the key lever
// that lets the underlying path float without a wireguard-go re-handshake.
type genezaEndpoint struct {
	wgPub [32]byte
}

func (e *genezaEndpoint) ClearSrc()           {}
func (e *genezaEndpoint) SrcToString() string { return "" }
func (e *genezaEndpoint) DstToString() string { return "gz:" + hex.EncodeToString(e.wgPub[:]) }
func (e *genezaEndpoint) DstToBytes() []byte  { b := make([]byte, 32); copy(b, e.wgPub[:]); return b }
func (e *genezaEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e *genezaEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

var _ conn.Endpoint = (*genezaEndpoint)(nil)

// peerState is the bind's per-peer routing record.
type peerState struct {
	wgPub      [32]byte
	relaySelf  uint64 // 48-bit rid we REG and receive DATA on
	relayPeer  uint64 // 48-bit rid we address this peer's DATA to
	relayAddr  netip.AddrPort
	flowSecret [16]byte
	state      atomic.Int32 // pathState

	// direct path (P2+):
	bestDirect netip.AddrPort
	directOK   atomic.Bool
	lastDirect atomic.Int64
}

// PeerRelay is the relay coordinates the gateway minted for one peer, threaded
// from WGPeer.relay into the bind.
type PeerRelay struct {
	WGPub      [32]byte
	RelayAddr  string // host:port
	SelfRid    uint64
	PeerRid    uint64
	FlowSecret []byte
}

// MagicBind is the conn.Bind for one Network (VNI).
type MagicBind struct {
	vni uint32
	log *slog.Logger

	mu     sync.Mutex
	uc     *net.UDPConn
	port   uint16
	closed bool
	stopKA chan struct{}

	peersMu   sync.RWMutex
	peers     map[[32]byte]*peerState
	byRid     map[uint64]*peerState
	relayAddr netip.AddrPort // the relay UDP addr (one per VNI in P1)
}

var _ conn.Bind = (*MagicBind)(nil)

func NewMagicBind(vni uint32, log *slog.Logger) *MagicBind {
	if log == nil {
		log = slog.Default()
	}
	return &MagicBind{
		vni:   vni,
		log:   log.With("component", "magicsock", "vni", vni),
		peers: map[[32]byte]*peerState{},
		byRid: map[uint64]*peerState{},
	}
}

// Open binds the single magicsock UDP socket and returns one ReceiveFunc.
func (b *MagicBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.uc != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.uc = uc
	b.closed = false
	b.port = uint16(uc.LocalAddr().(*net.UDPAddr).Port)
	b.stopKA = make(chan struct{})
	go b.keepaliveLoop(b.stopKA)
	b.log.Info("magicsock bound", "port", b.port)
	return []conn.ReceiveFunc{b.receive}, b.port, nil
}

func (b *MagicBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.uc == nil || b.closed {
		return nil
	}
	b.closed = true
	if b.stopKA != nil {
		close(b.stopKA)
		b.stopKA = nil
	}
	err := b.uc.Close() // makes the in-flight ReadFromUDPAddrPort return net.ErrClosed
	b.uc = nil
	return err
}

func (b *MagicBind) SetMark(uint32) error { return nil }

// BatchSize returns 1: we read one datagram per ReceiveFunc call. (The device's
// own batch is max(bind,tun)=128, so it still hands us 128-wide slices — we fill
// index 0 and return 1. Never assume len==1.)
func (b *MagicBind) BatchSize() int { return 1 }

func (b *MagicBind) socket() *net.UDPConn {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.uc
}

// ListenPort reports the bound UDP port (the userspace backend reports this up
// for endpoint discovery, replacing the kernel's listen port).
func (b *MagicBind) ListenPort() uint16 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.port
}

// ParseEndpoint accepts our "gz:<64hex>" peer-identity token (round-trips with
// genezaEndpoint.DstToString) from the UAPI endpoint= line.
func (b *MagicBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	rest, ok := strings.CutPrefix(s, "gz:")
	if !ok {
		return nil, conn.ErrWrongEndpointType
	}
	raw, err := hex.DecodeString(rest)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("magicsock: bad gz endpoint")
	}
	var e genezaEndpoint
	copy(e.wgPub[:], raw)
	return &e, nil
}

// Send chooses the path per packet. P1: always the relay floor.
func (b *MagicBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	ge, ok := ep.(*genezaEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.peersMu.RLock()
	ps := b.peers[ge.wgPub]
	b.peersMu.RUnlock()
	if ps == nil {
		return nil // peer gone mid-flight; next reconcile fixes it
	}
	uc := b.socket()
	if uc == nil {
		return net.ErrClosed
	}

	if pathState(ps.state.Load()) == stDirect && ps.directOK.Load() {
		for _, buf := range bufs {
			if _, err := uc.WriteToUDPAddrPort(buf, ps.bestDirect); err != nil {
				return err
			}
		}
		return nil
	}
	// Relay floor: frame DATA{relayPeer} + ciphertext to the relay.
	dst := ps.relayAddr
	for _, buf := range bufs {
		frame := make([]byte, relayHdrLen+len(buf))
		frame[0] = relayMagic
		frame[1] = frameDATA
		putRid(frame[2:8], ps.relayPeer)
		copy(frame[relayHdrLen:], buf)
		if _, err := uc.WriteToUDPAddrPort(frame, dst); err != nil {
			return err
		}
	}
	return nil
}

// receive is the single ReceiveFunc: demux relay frames vs (P2+) direct WG.
func (b *MagicBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	uc := b.socket()
	if uc == nil {
		return 0, net.ErrClosed
	}
	n, src, err := uc.ReadFromUDPAddrPort(packets[0])
	if err != nil {
		return 0, err // net.ErrClosed after Close() -> receive goroutine exits
	}
	pkt := packets[0][:n]

	// Relay/disco frame iff it carries the magic AND comes from the relay addr.
	if n >= relayHdrLen && pkt[0] == relayMagic && b.isRelayAddr(src) {
		switch pkt[1] {
		case frameDATA:
			rid := getRid(pkt[2:8])
			b.peersMu.RLock()
			ps := b.byRid[rid]
			b.peersMu.RUnlock()
			if ps == nil {
				return 0, nil // unknown mailbox -> ignore, recv again
			}
			copy(packets[0], pkt[relayHdrLen:]) // memmove-safe (dst < src overlap)
			sizes[0] = n - relayHdrLen
			eps[0] = &genezaEndpoint{wgPub: ps.wgPub}
			return 1, nil
		default:
			// STUNRESP/CLOSE/etc. handled in P2+; ignore for now.
			return 0, nil
		}
	}
	// P1: no direct path. Anything not a relay DATA frame is dropped.
	return 0, nil
}

func (b *MagicBind) isRelayAddr(src netip.AddrPort) bool {
	b.peersMu.RLock()
	ra := b.relayAddr
	b.peersMu.RUnlock()
	return ra.IsValid() && src == ra
}

// SyncPeers replaces the bind's peer set from the reconciled relay coordinates
// and (re-)REGisters each peer's mailbox immediately, so the relay has the
// mailbox before the peer's WG handshake DATA arrives (REG-before-DATA).
func (b *MagicBind) SyncPeers(peers []PeerRelay) {
	next := make(map[[32]byte]*peerState, len(peers))
	nextRid := make(map[uint64]*peerState, len(peers))
	var relayAddr netip.AddrPort

	b.peersMu.Lock()
	for _, p := range peers {
		ra, err := resolveUDP(p.RelayAddr)
		if err != nil {
			b.log.Warn("bad relay addr", "addr", p.RelayAddr, "err", err)
			continue
		}
		relayAddr = ra
		ps := b.peers[p.WGPub]
		if ps == nil {
			ps = &peerState{wgPub: p.WGPub}
		}
		ps.relaySelf = p.SelfRid & ridMax
		ps.relayPeer = p.PeerRid & ridMax
		ps.relayAddr = ra
		copy(ps.flowSecret[:], p.FlowSecret)
		ps.state.Store(int32(stRelay))
		next[p.WGPub] = ps
		nextRid[ps.relaySelf] = ps
	}
	b.peers = next
	b.byRid = nextRid
	if relayAddr.IsValid() {
		b.relayAddr = relayAddr
	}
	b.peersMu.Unlock()

	// REG each mailbox now (before WG sends DATA to the peer).
	for _, ps := range next {
		b.sendReg(ps)
	}
}

// keepaliveLoop re-REGisters every mailbox on an interval to keep the relay
// table entry (and the NAT mapping toward the relay) warm.
func (b *MagicBind) keepaliveLoop(stop chan struct{}) {
	t := time.NewTicker(relayKeepaliveInt)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			b.peersMu.RLock()
			pss := make([]*peerState, 0, len(b.peers))
			for _, ps := range b.peers {
				pss = append(pss, ps)
			}
			b.peersMu.RUnlock()
			for _, ps := range pss {
				b.sendReg(ps)
			}
		}
	}
}

// sendReg sends a REG frame claiming ps.relaySelf, with an HMAC(flowSecret) tail
// that the receiving endpoint can validate end to end (the relay cannot — it
// holds no key; the tail is only a cheap shape gate relay-side).
func (b *MagicBind) sendReg(ps *peerState) {
	uc := b.socket()
	if uc == nil || !ps.relayAddr.IsValid() {
		return
	}
	frame := make([]byte, relayHdrLen+sha256.Size)
	frame[0] = relayMagic
	frame[1] = frameREG
	putRid(frame[2:8], ps.relaySelf)
	mac := hmac.New(sha256.New, ps.flowSecret[:])
	mac.Write(frame[2:8])
	copy(frame[relayHdrLen:], mac.Sum(nil))
	if _, err := uc.WriteToUDPAddrPort(frame, ps.relayAddr); err != nil {
		b.log.Debug("REG send failed", "err", err)
	}
}

func putRid(b []byte, rid uint64) {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], rid&ridMax)
	copy(b, tmp[2:]) // low 6 bytes
}

func getRid(b []byte) uint64 {
	var tmp [8]byte
	copy(tmp[2:], b[:6])
	return binary.BigEndian.Uint64(tmp[:])
}

func resolveUDP(hostport string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(hostport); err == nil {
		return ap, nil
	}
	ua, err := net.ResolveUDPAddr("udp", hostport)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return ua.AddrPort(), nil
}
