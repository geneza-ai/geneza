package vpn

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
	"golang.zx2c4.com/wireguard/conn"
)

// icebind.go is the data-plane transport: a wireguard-go conn.Bind backed by
// per-peer pion/ice agents (RFC 8445 ICE) with a pion/turn relay floor and STUN
// reflexive discovery. Geneza writes ZERO NAT-traversal protocol — pion does
// candidate gathering, connectivity checks, hole-punch and relay→direct pair
// selection. We only adapt ICE's per-peer connection to WireGuard's single
// multi-peer Bind, and carry ICE signaling over the gateway control stream.
// See docs/dataplane-libs-plan.md.

// iceReadBuf is >= pion/turn's InboundMTU (1600); a smaller buffer makes
// packetio.Buffer.Read return io.ErrShortBuffer and DISCARD the datagram tail,
// so we size generously and, on ErrShortBuffer, drop-and-continue (never die).
const iceReadBuf = 1600

// genezaEndpoint identifies a PEER by its WG pubkey, not an address — so the live
// ICE path floats under wireguard-go and a relay→direct upgrade never triggers a
// WG re-handshake (the *ice.Conn is stable across pion's internal pair switch).
type genezaEndpoint struct{ wgPub [32]byte }

func (e *genezaEndpoint) ClearSrc()           {}
func (e *genezaEndpoint) SrcToString() string { return "" }
func (e *genezaEndpoint) DstToString() string { return "gz:" + hex.EncodeToString(e.wgPub[:]) }
func (e *genezaEndpoint) DstToBytes() []byte  { b := make([]byte, 32); copy(b, e.wgPub[:]); return b }
func (e *genezaEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e *genezaEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

var _ conn.Endpoint = (*genezaEndpoint)(nil)

// SignalSink pushes ICE signaling (local candidates + our ufrag/pwd) up the
// gateway control stream. The worker implements it via AgentMsg.disco.
type SignalSink interface {
	SendLocalCandidate(vni uint32, peerWGPub [32]byte, candidate string)
	SendICECreds(vni uint32, peerWGPub [32]byte, ufrag, pwd string)
}

// PeerSetup is the per-peer ICE/TURN setup the gateway minted (from WGPeer.turn).
type PeerSetup struct {
	WGPub       [32]byte
	Controlling bool
	TurnURL     string
	TurnUser    string
	TurnPass    string
	TurnRealm   string
}

type peerICE struct {
	wgPub       [32]byte
	controlling bool
	agent       *ice.Agent
	setup       PeerSetup // retained so a failed agent can be rebuilt

	mu           sync.Mutex
	conn         *ice.Conn
	cancel       context.CancelFunc
	remoteUfrag  string
	remotePwd    string
	connecting   bool
	iceConnected bool // ICE state == Connected (distinct from conn!=nil, which survives a restart)
	restarting   bool
	localCands   []string // our gathered candidates, cached for periodic re-announce
}

type recvMsg struct {
	ep  *genezaEndpoint
	buf []byte // pooled; returned to bufPool after the device copies it out
	n   int
}

// bufPool recycles per-datagram read buffers so the hot inbound path does no
// per-packet allocation (throughput).
var bufPool = sync.Pool{New: func() any { return make([]byte, iceReadBuf) }}

// numDrainers is how many ReceiveFunc goroutines the device runs draining recvCh
// concurrently (removes the single-goroutine inbound funnel).
const numDrainers = 4

// iceBind is the conn.Bind for one Network (VNI): one ice.Agent + *ice.Conn per
// peer, multiplexed under N concurrent ReceiveFuncs.
type ICEBind struct {
	vni       uint32
	relayOnly bool // P-libs1: relay candidates only (force the TURN floor)
	log       *slog.Logger

	mu      sync.Mutex
	sink    SignalSink
	selfPub [32]byte
	peers   map[[32]byte]*peerICE
	recvCh  chan recvMsg
	done    chan struct{} // closed on Close; readers/drainers exit on it (recvCh is never closed -> no send-on-closed panic)
	closed  bool
}

var _ conn.Bind = (*ICEBind)(nil)

// NewICEBind builds a bind for one VNI. relayOnly forces the TURN floor (P-libs1);
// false adds host + server-reflexive candidates so ICE auto-upgrades to direct.
func NewICEBind(vni uint32, relayOnly bool, log *slog.Logger) *ICEBind {
	if log == nil {
		log = slog.Default()
	}
	return &ICEBind{
		vni:       vni,
		relayOnly: relayOnly,
		log:       log.With("component", "icebind", "vni", vni),
		peers:     map[[32]byte]*peerICE{},
		recvCh:    make(chan recvMsg, 1024),
		done:      make(chan struct{}),
	}
}

func (b *ICEBind) SetSink(s SignalSink) {
	b.mu.Lock()
	b.sink = s
	b.mu.Unlock()
}

func (b *ICEBind) SetSelfPub(pub [32]byte) {
	b.mu.Lock()
	b.selfPub = pub
	b.mu.Unlock()
}

// Open returns numDrainers ReceiveFuncs so the device drains recvCh on several
// goroutines concurrently (no single inbound funnel). No single shared socket
// (each ice.Agent owns its sockets); port 0 is reported.
func (b *ICEBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		b.closed = false
		b.recvCh = make(chan recvMsg, 1024)
		b.done = make(chan struct{})
	}
	fns := make([]conn.ReceiveFunc, numDrainers)
	for i := range fns {
		fns[i] = b.receive
	}
	return fns, 0, nil
}

// receive blocks for one datagram then opportunistically batches more (up to the
// device's slice width) so wireguard-go processes several per call. Pooled read
// buffers are returned after the copy-out. Closure is signalled via b.done so a
// per-peer reader never sends on a closed channel.
func (b *ICEBind) receive(pkts [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	var msg recvMsg
	select {
	case msg = <-b.recvCh:
	case <-b.done:
		return 0, net.ErrClosed
	}
	count := 0
	put := func(m recvMsg) {
		sizes[count] = copy(pkts[count], m.buf[:m.n])
		eps[count] = m.ep
		bufPool.Put(m.buf) //nolint:staticcheck // pooled []byte
		count++
	}
	put(msg)
	for count < len(pkts) {
		select {
		case m := <-b.recvCh:
			put(m)
		default:
			return count, nil
		}
	}
	return count, nil
}

func (b *ICEBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	ge, ok := ep.(*genezaEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	p := b.peers[ge.wgPub]
	b.mu.Unlock()
	if p == nil {
		return nil // peer gone mid-flight; next reconcile fixes it
	}
	p.mu.Lock()
	c := p.conn
	p.mu.Unlock()
	if c == nil {
		return nil // ICE not yet connected; WG retransmits the handshake
	}
	for _, buf := range bufs {
		if _, err := c.Write(buf); err != nil { // one Write == one datagram
			return err
		}
	}
	return nil
}

func (b *ICEBind) BatchSize() int       { return 1 } // ice.Conn is one-datagram
func (b *ICEBind) SetMark(uint32) error { return nil }

// ParseEndpoint accepts our "gz:<64hex>" peer-identity token.
func (b *ICEBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	rest, ok := strings.CutPrefix(s, "gz:")
	if !ok {
		return nil, conn.ErrWrongEndpointType
	}
	raw, err := hex.DecodeString(rest)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("icebind: bad gz endpoint")
	}
	var e genezaEndpoint
	copy(e.wgPub[:], raw)
	return &e, nil
}

func (b *ICEBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	close(b.done) // wakes drainers (ErrClosed) + stops reader sends; recvCh is never closed
	for _, p := range b.peers {
		p.mu.Lock()
		if p.cancel != nil {
			p.cancel()
		}
		p.mu.Unlock()
		if p.agent != nil {
			_ = p.agent.Close()
		}
	}
	b.peers = map[[32]byte]*peerICE{}
	return nil
}

// SyncPeers reconciles the ICE agent set against the gateway's desired peers.
func (b *ICEBind) SyncPeers(setups []PeerSetup) {
	want := make(map[[32]byte]bool, len(setups))
	for _, s := range setups {
		want[s.WGPub] = true
		b.ensurePeer(s)
	}
	// Tear down agents for peers no longer present.
	b.mu.Lock()
	var gone []*peerICE
	for k, p := range b.peers {
		if !want[k] {
			gone = append(gone, p)
			delete(b.peers, k)
		}
	}
	b.mu.Unlock()
	for _, p := range gone {
		p.mu.Lock()
		if p.cancel != nil {
			p.cancel()
		}
		p.mu.Unlock()
		if p.agent != nil {
			_ = p.agent.Close()
		}
	}
}

func (b *ICEBind) ensurePeer(s PeerSetup) {
	b.mu.Lock()
	if _, ok := b.peers[s.WGPub]; ok {
		b.mu.Unlock()
		return // already up
	}
	sink := b.sink
	b.mu.Unlock()

	turnURI, err := stun.ParseURI(s.TurnURL)
	if err != nil {
		b.log.Warn("bad turn url", "url", s.TurnURL, "err", err)
		return
	}
	turnURI.Username, turnURI.Password = s.TurnUser, s.TurnPass

	urls := []*stun.URI{turnURI}
	candTypes := []ice.CandidateType{ice.CandidateTypeRelay}
	if !b.relayOnly {
		stunURI := &stun.URI{Scheme: stun.SchemeTypeSTUN, Host: turnURI.Host, Port: turnURI.Port, Proto: stun.ProtoTypeUDP}
		urls = append(urls, stunURI)
		candTypes = []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive, ice.CandidateTypeRelay}
	}

	a, err := ice.NewAgent(&ice.AgentConfig{
		Urls:           urls,
		NetworkTypes:   []ice.NetworkType{ice.NetworkTypeUDP4},
		CandidateTypes: candTypes,
	})
	if err != nil {
		b.log.Warn("ice agent create failed", "peer", shortHex(s.WGPub), "err", err)
		return
	}

	p := &peerICE{wgPub: s.WGPub, controlling: s.Controlling, agent: a, setup: s}
	b.mu.Lock()
	b.peers[s.WGPub] = p
	b.mu.Unlock()

	// Trickle LOCAL candidates up the control stream (gateway forwards to the
	// peer) and cache them for periodic re-announce.
	_ = a.OnCandidate(func(c ice.Candidate) {
		if c == nil { // nil == gathering complete
			return
		}
		m := c.Marshal()
		p.mu.Lock()
		p.localCands = append(p.localCands, m)
		p.mu.Unlock()
		if sink != nil {
			sink.SendLocalCandidate(b.vni, s.WGPub, m)
		}
	})
	_ = a.OnConnectionStateChange(func(st ice.ConnectionState) {
		b.log.Info("ice state", "peer", shortHex(s.WGPub), "state", st.String())
		switch st {
		case ice.ConnectionStateConnected:
			p.mu.Lock()
			p.iceConnected = true
			p.restarting = false
			p.mu.Unlock()
		case ice.ConnectionStateFailed:
			// Recovery from a path failure (e.g. the relay restarted, killing the
			// selected pair). pion's in-place agent.Restart does NOT reliably resume
			// the check loop for an established agent, so we fully RECREATE the peer's
			// ICE agent (fresh Dial), reusing the proven initial-connect path. The WG
			// endpoint is gz:<wgpub> (unchanged), so the bind just swaps to the new
			// *ice.Conn — WG keeps its session (no re-handshake within the rekey window).
			p.mu.Lock()
			established := p.conn != nil && !p.restarting
			if established {
				p.restarting = true
			}
			p.iceConnected = false
			p.mu.Unlock()
			if established {
				go b.recreatePeer(p)
			}
		case ice.ConnectionStateDisconnected:
			p.mu.Lock()
			p.iceConnected = false
			p.mu.Unlock()
		}
	})
	_ = a.OnSelectedCandidatePairChange(func(local, remote ice.Candidate) {
		b.log.Info("ice pair selected", "peer", shortHex(s.WGPub),
			"local", local.Type().String(), "remote", remote.Type().String())
	})

	// Ship OUR ufrag/pwd up so the peer can Dial/Accept us, and re-announce
	// creds+candidates periodically until connected. Re-announce (not a gateway
	// cache) is what makes convergence robust to ordering / restart: whenever the
	// peer's agent comes up, our next re-announce reaches it, and vice versa — no
	// stale signaling state anywhere.
	ufrag, pwd, _ := a.GetLocalUserCredentials()
	if sink != nil {
		sink.SendICECreds(b.vni, s.WGPub, ufrag, pwd)
	}
	if err := a.GatherCandidates(); err != nil {
		b.log.Warn("ice gather failed", "peer", shortHex(s.WGPub), "err", err)
	}
	go b.reannounce(p, sink, ufrag, pwd)
}

// reannounce re-sends our ICE creds + gathered candidates every 2s until the
// peer connects (capped ~40s), so a peer whose agent appeared after our first
// announce still receives them. Idempotent at the receiver (AddRemoteCandidate
// dedups; the one-shot connect ignores repeat creds).
func (b *ICEBind) reannounce(p *peerICE, sink SignalSink, ufrag, pwd string) {
	if sink == nil {
		return
	}
	for i := 0; i < 20; i++ {
		time.Sleep(2 * time.Second)
		b.mu.Lock()
		replaced := b.peers[p.wgPub] != p
		b.mu.Unlock()
		if replaced {
			return // this peerICE was recreated; its re-announce goroutine is stale
		}
		p.mu.Lock()
		connected := p.iceConnected
		cands := append([]string(nil), p.localCands...)
		p.mu.Unlock()
		if connected {
			return
		}
		sink.SendICECreds(b.vni, p.wgPub, ufrag, pwd)
		for _, c := range cands {
			sink.SendLocalCandidate(b.vni, p.wgPub, c)
		}
	}
}

// recreatePeer tears down a failed peer's ICE agent and rebuilds it from scratch
// (fresh agent + fresh Dial), reusing the initial-connect path. Both peers' pairs
// fail together on a relay restart, so both recreate and reconverge via the same
// re-announce mechanism that brought them up initially. Bounded by pion's
// FailedTimeout (~25s) per attempt; a brief asymmetric-timing window may need one
// extra cycle. The WG endpoint (gz:<wgpub>) is unchanged, so the bind swaps to
// the new *ice.Conn transparently — no WG re-handshake within the rekey window.
func (b *ICEBind) recreatePeer(p *peerICE) {
	b.mu.Lock()
	if b.closed || b.peers[p.wgPub] != p {
		b.mu.Unlock()
		return // already replaced or shutting down
	}
	delete(b.peers, p.wgPub)
	setup := p.setup
	b.mu.Unlock()

	p.mu.Lock()
	if p.cancel != nil {
		p.cancel()
	}
	p.mu.Unlock()
	if p.agent != nil {
		_ = p.agent.Close()
	}
	b.log.Info("ice path failed; recreating peer agent", "peer", shortHex(p.wgPub))
	time.Sleep(2 * time.Second) // brief backoff (also lets a restarted relay settle)
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if !closed {
		b.ensurePeer(setup)
	}
}

// AddRemoteCandidate feeds a peer's gateway-forwarded ICE candidate to its agent.
func (b *ICEBind) AddRemoteCandidate(peerWGPub [32]byte, candidate string) {
	b.mu.Lock()
	p := b.peers[peerWGPub]
	b.mu.Unlock()
	if p == nil {
		return
	}
	c, err := ice.UnmarshalCandidate(candidate)
	if err != nil {
		b.log.Warn("bad remote candidate", "peer", shortHex(peerWGPub), "err", err)
		return
	}
	if err := p.agent.AddRemoteCandidate(c); err != nil {
		b.log.Warn("add remote candidate", "peer", shortHex(peerWGPub), "err", err)
	}
}

// OnICECreds records the peer's ufrag/pwd and starts the ICE connection once
// (pion's Dial/Accept is once-per-agent). Exactly one side Dials, the other
// Accepts. The gateway guarantees the FIRST creds we see are the peer's CURRENT
// creds (it clears stale cache on the peer's reconnect), so the one-shot connect
// never locks onto a superseded pair.
func (b *ICEBind) OnICECreds(peerWGPub [32]byte, ufrag, pwd string) {
	b.mu.Lock()
	p := b.peers[peerWGPub]
	b.mu.Unlock()
	if p == nil {
		return
	}
	p.mu.Lock()
	p.remoteUfrag, p.remotePwd = ufrag, pwd
	start := !p.connecting && p.conn == nil
	if start {
		p.connecting = true
	}
	p.mu.Unlock()
	if start {
		go b.connect(p) // one-shot Dial/Accept (recovery is via recreatePeer)
	}
}

// OnPunchAt is the gateway's "re-run ICE now" trigger (late-upgrade / roam). In
// P-libs1 (relay-only) it is a no-op; ICE restart lands with the direct phase.
func (b *ICEBind) OnPunchAt(peerWGPub [32]byte, t0UnixMs int64, attempt int) {}

func (b *ICEBind) connect(p *peerICE) {
	ctx, cancel := context.WithCancel(context.Background())
	p.mu.Lock()
	p.cancel = cancel
	rufrag, rpwd, ctrl := p.remoteUfrag, p.remotePwd, p.controlling
	p.mu.Unlock()

	var c *ice.Conn
	var err error
	if ctrl {
		c, err = p.agent.Dial(ctx, rufrag, rpwd)
	} else {
		c, err = p.agent.Accept(ctx, rufrag, rpwd)
	}
	if err != nil {
		b.log.Warn("ice connect failed", "peer", shortHex(p.wgPub), "err", err)
		p.mu.Lock()
		p.connecting = false
		p.mu.Unlock()
		return
	}
	p.mu.Lock()
	p.conn = c
	p.mu.Unlock()
	b.log.Info("ice connected", "peer", shortHex(p.wgPub), "controlling", ctrl)

	// Per-peer reader: one Read == one inbound WG datagram -> recvCh -> ReceiveFunc.
	// Pooled buffers (no per-packet alloc); the drainer returns each to the pool.
	go func() {
		for {
			buf := bufPool.Get().([]byte)
			n, rerr := c.Read(buf)
			if n > 0 {
				select {
				case b.recvCh <- recvMsg{ep: &genezaEndpoint{wgPub: p.wgPub}, buf: buf, n: n}:
				case <-b.done:
					bufPool.Put(buf)
					return
				default: // backpressure: drop, like a UDP socket
					bufPool.Put(buf)
				}
			} else {
				bufPool.Put(buf)
			}
			if rerr != nil {
				if errors.Is(rerr, io.ErrShortBuffer) {
					continue // datagram too big for buf; dropped, keep reading
				}
				return // closed / fatal
			}
		}
	}()
}

func shortHex(k [32]byte) string { return hex.EncodeToString(k[:4]) }
