//go:build linux

package vpn

// gso_linux.go is a focused IPv4 UDP socket with kernel segmentation offload
// (GSO on TX via UDP_SEGMENT, GRO on RX via UDP_GRO). It lets the userspace
// WireGuard data path move ~128 packets per syscall instead of one, which is the
// single biggest lever for multi-gigabit on the direct (incl. NAT-traversed)
// overlay path. The GSO/GRO cmsg codecs + coalesce/split logic are ported from
// wireguard-go's conn package (MIT, golang.zx2c4.com/wireguard) — those helpers
// are unexported there and StdNetBind owns its own socket, which conflicts with
// pion gathering ICE candidates on the same socket, so we own the socket here and
// reuse the proven batching algorithm. IPv4-only (the overlay is 100.64.0.0/24)
// and no sticky-source control (single data socket per Network), so this is a
// trimmed version of StdNetBind.Send/receiveIP. See geneza-dataplane-decision.

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const (
	// gsoBatchSize mirrors wireguard-go conn.IdealBatchSize: the device hands us
	// up to this many packets per peer per Send, and we fill this many on RX.
	gsoBatchSize = 128
	// udpSegMaxDatagrams is the kernel's hard cap on segments per UDP_SEGMENT send.
	udpSegMaxDatagrams = 64
	// maxIPv4PayloadLen bounds a single coalesced super-datagram (layer3+4 hdrs).
	maxIPv4PayloadLen = 1<<16 - 1 - 20 - 8
	// socketBufferSize matches wireguard-go's default (7 MiB) to absorb bursts.
	socketBufferSize = 7 << 20
	// gsoRXReadBuf is sized for one GRO super-datagram (kernel coalesces ≤64 KiB).
	gsoRXReadBuf = 1 << 16
	// gsoRXMsgs is how many GRO super-datagrams to pull per recvmmsg; each splits
	// into ≤~45 WG-sized segments, so 2 stays within gsoBatchSize output slots.
	gsoRXMsgs = 2
	sizeOfGSOData = 2
)

// gsoConn is a GSO/GRO-capable IPv4 UDP socket shared by one Network's pion ICE
// agents (host+srflx candidates) AND its WireGuard data path.
type gsoConn struct {
	uc *net.UDPConn
	pc *ipv4.PacketConn

	mu sync.Mutex // guards txOffload (may be disabled at runtime on EIO)
	txOffload bool
	rxOffload bool

	txPool sync.Pool // *[]ipv4.Message for coalesced sends (reentrant: one per peer)

	// RX state is owned by the single reader goroutine (no locking).
	rxMsgs []ipv4.Message
}

// newGSOConn wraps a bound *net.UDPConn: bumps socket buffers, enables UDP_GRO,
// probes TX/RX offload, and preps the batch pools.
func newGSOConn(uc *net.UDPConn) *gsoConn {
	g := &gsoConn{uc: uc}
	if rc, err := uc.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) {
			ifd := int(fd)
			_ = unix.SetsockoptInt(ifd, unix.SOL_SOCKET, unix.SO_RCVBUF, socketBufferSize)
			_ = unix.SetsockoptInt(ifd, unix.SOL_SOCKET, unix.SO_SNDBUF, socketBufferSize)
			_ = unix.SetsockoptInt(ifd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, socketBufferSize)
			_ = unix.SetsockoptInt(ifd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, socketBufferSize)
			if _, e := unix.GetsockoptInt(ifd, unix.IPPROTO_UDP, unix.UDP_SEGMENT); e == nil {
				g.txOffload = true
			}
			_ = unix.SetsockoptInt(ifd, unix.IPPROTO_UDP, unix.UDP_GRO, 1)
			if opt, e := unix.GetsockoptInt(ifd, unix.IPPROTO_UDP, unix.UDP_GRO); e == nil && opt == 1 {
				g.rxOffload = true
			}
		})
	}
	g.pc = ipv4.NewPacketConn(uc)
	g.txPool = sync.Pool{New: func() any {
		msgs := make([]ipv4.Message, gsoBatchSize)
		for i := range msgs {
			msgs[i].Buffers = make(net.Buffers, 1)
			msgs[i].OOB = make([]byte, 0, unix.CmsgSpace(sizeOfGSOData))
		}
		return &msgs
	}}
	g.rxMsgs = make([]ipv4.Message, gsoRXMsgs)
	for i := range g.rxMsgs {
		g.rxMsgs[i].Buffers = make(net.Buffers, 1)
		g.rxMsgs[i].Buffers[0] = make([]byte, gsoRXReadBuf)
		g.rxMsgs[i].OOB = make([]byte, unix.CmsgSpace(sizeOfGSOData))
	}
	return g
}

func (g *gsoConn) batchSize() int   { return gsoBatchSize }
func (g *gsoConn) LocalAddr() net.Addr { return g.uc.LocalAddr() }
func (g *gsoConn) Close() error      { return g.uc.Close() }

// WriteTo sends one datagram (used by the pion demux for STUN/connectivity checks).
func (g *gsoConn) WriteTo(p []byte, addr net.Addr) (int, error) { return g.uc.WriteTo(p, addr) }

// WriteBatchTo sends every buf (all destined to addr) coalesced into as few
// sendmmsg/UDP_SEGMENT syscalls as possible. Falls back to per-datagram if GSO
// is unsupported, the batch is trivial, or the kernel rejects offload (EIO).
func (g *gsoConn) WriteBatchTo(bufs [][]byte, addr netip.AddrPort) error {
	if len(bufs) == 0 {
		return nil
	}
	g.mu.Lock()
	offload := g.txOffload
	g.mu.Unlock()
	if !offload || len(bufs) == 1 {
		return g.writePerDatagram(bufs, addr)
	}
	ua := net.UDPAddrFromAddrPort(addr)
	msgs := g.txPool.Get().(*[]ipv4.Message)
	defer func() {
		for i := range *msgs {
			(*msgs)[i].OOB = (*msgs)[i].OOB[:0]
			(*msgs)[i].Buffers[0] = nil
			(*msgs)[i].Addr = nil
		}
		g.txPool.Put(msgs)
	}()
	n := coalesceGSO(ua, bufs, *msgs)
	if err := g.sendBatch((*msgs)[:n]); err != nil {
		if errors.Is(err, unix.EIO) { // NIC/path can't checksum-offload: disable + retry plain
			g.mu.Lock()
			g.txOffload = false
			g.mu.Unlock()
			return g.writePerDatagram(bufs, addr)
		}
		return err
	}
	return nil
}

func (g *gsoConn) writePerDatagram(bufs [][]byte, addr netip.AddrPort) error {
	for _, b := range bufs {
		if _, err := g.uc.WriteToUDPAddrPort(b, addr); err != nil {
			return err
		}
	}
	return nil
}

func (g *gsoConn) sendBatch(msgs []ipv4.Message) error {
	var start int
	for start < len(msgs) {
		n, err := g.pc.WriteBatch(msgs[start:], 0)
		if err != nil {
			return err
		}
		if n == 0 {
			break
		}
		start += n
	}
	return nil
}

// ReadBatchInto reads up to len(out) datagrams (GRO-splitting coalesced reads)
// into the caller-provided buffers, returning the count. out[i] is filled with
// the datagram payload, sizes[i] its length, srcs[i] its source. Single reader.
func (g *gsoConn) ReadBatchInto(out [][]byte, sizes []int, srcs []netip.AddrPort) (int, error) {
	for i := range g.rxMsgs {
		g.rxMsgs[i].Buffers[0] = g.rxMsgs[i].Buffers[0][:gsoRXReadBuf]
		g.rxMsgs[i].OOB = g.rxMsgs[i].OOB[:cap(g.rxMsgs[i].OOB)]
	}
	nread, err := g.pc.ReadBatch(g.rxMsgs, 0)
	if err != nil {
		return 0, err
	}
	count := 0
	for i := 0; i < nread && count < len(out); i++ {
		m := &g.rxMsgs[i]
		if m.N == 0 {
			continue
		}
		ua, ok := m.Addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		src := ua.AddrPort()
		data := m.Buffers[0][:m.N]
		seg := 0
		if g.rxOffload {
			seg, _ = getGSOSize(m.OOB[:m.NN])
		}
		if seg <= 0 || seg >= m.N { // single datagram
			sizes[count] = copy(out[count], data)
			srcs[count] = src
			count++
			continue
		}
		for off := 0; off < m.N && count < len(out); off += seg { // GRO split
			end := off + seg
			if end > m.N {
				end = m.N
			}
			sizes[count] = copy(out[count], data[off:end])
			srcs[count] = src
			count++
		}
	}
	return count, nil
}

// coalesceGSO groups bufs (all to addr) into ipv4.Messages with a UDP_SEGMENT
// cmsg, ported from wireguard-go conn.coalesceMessages (sticky-src removed).
func coalesceGSO(addr *net.UDPAddr, bufs [][]byte, msgs []ipv4.Message) int {
	base := -1
	gsoSize := 0
	dgramCnt := 0
	endBatch := false
	for i, buf := range bufs {
		if i > 0 {
			msgLen := len(buf)
			baseLen := len(msgs[base].Buffers[0])
			freeCap := cap(msgs[base].Buffers[0]) - baseLen
			if msgLen+baseLen <= maxIPv4PayloadLen &&
				msgLen <= gsoSize &&
				msgLen <= freeCap &&
				dgramCnt < udpSegMaxDatagrams &&
				!endBatch {
				msgs[base].Buffers[0] = append(msgs[base].Buffers[0], buf...)
				if i == len(bufs)-1 {
					setGSOSize(&msgs[base].OOB, uint16(gsoSize))
				}
				dgramCnt++
				if msgLen < gsoSize { // a smaller tail segment is legal but ends the batch
					endBatch = true
				}
				continue
			}
		}
		if dgramCnt > 1 {
			setGSOSize(&msgs[base].OOB, uint16(gsoSize))
		}
		endBatch = false
		base++
		gsoSize = len(buf)
		msgs[base].Buffers[0] = buf
		msgs[base].Addr = addr
		msgs[base].OOB = msgs[base].OOB[:0]
		dgramCnt = 1
	}
	return base + 1
}

// getGSOSize / setGSOSize are the UDP_GRO / UDP_SEGMENT cmsg codecs, ported
// verbatim from wireguard-go conn/gso_linux.go (MIT).
func getGSOSize(control []byte) (int, error) {
	for len(control) > unix.SizeofCmsghdr {
		hdr, data, rem, err := unix.ParseOneSocketControlMessage(control)
		if err != nil {
			return 0, err
		}
		if hdr.Level == unix.SOL_UDP && hdr.Type == unix.UDP_GRO && len(data) >= sizeOfGSOData {
			var gso uint16
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&gso)), sizeOfGSOData), data[:sizeOfGSOData])
			return int(gso), nil
		}
		control = rem
	}
	return 0, nil
}

func setGSOSize(control *[]byte, gsoSize uint16) {
	existingLen := len(*control)
	space := unix.CmsgSpace(sizeOfGSOData)
	if cap(*control)-existingLen < space {
		return
	}
	*control = (*control)[:cap(*control)]
	gsoControl := (*control)[existingLen:]
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&gsoControl[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_SEGMENT
	hdr.SetLen(unix.CmsgLen(sizeOfGSOData))
	copy(gsoControl[unix.CmsgLen(0):], unsafe.Slice((*byte)(unsafe.Pointer(&gsoSize)), sizeOfGSOData))
	*control = (*control)[:existingLen+space]
}
