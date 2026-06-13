package vpn

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
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

	// directAddr is the peer's selected DIRECT remote (host/srflx) UDP endpoint,
	// set by OnSelectedCandidatePairChange. Non-nil ⇒ Send GSO-batches straight to
	// it on the shared socket (the multi-gig path, incl. NAT-traversed); nil ⇒ the
	// pair is relayed (or not yet up) ⇒ Send falls back to per-datagram ice.Conn.
	directAddr atomic.Pointer[netip.AddrPort]

	// lastRX is the unix-nano time of the last inbound datagram from this peer.
	// Since every peer runs a 25s persistent keepalive, a connected-but-silent peer
	// for >livenessStale means the path died WITHOUT pion noticing (e.g. a TURN
	// relay restart, which pion's consent freshness misses) → the liveness watchdog
	// recreates it. This is the data-plane-level liveness the kernel-handoff audit
	// recommended, applied to the userspace path.
	lastRX atomic.Int64

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
	wanted  map[[32]byte]PeerSetup // desired peer set (last SyncPeers); recreatePeer never resurrects a peer not here
	backoff map[[32]byte]int       // consecutive recreate attempts per peer (reset on Connected); drives recreate backoff
	recvCh  chan recvMsg
	done    chan struct{} // closed on Close; readers/drainers exit on it (recvCh is never closed -> no send-on-closed panic)
	closed  bool

	// Shared GSO data socket + pion mux (non-relayOnly only). One UDP socket per
	// VNI carries ALL peers' host+srflx ICE (via the UniversalUDPMux) AND the
	// batched WireGuard data (sendmmsg/UDP_SEGMENT TX, recvmmsg/GRO RX) — the
	// multi-gigabit path. Relayed peers stay on their pion/TURN sockets (no GSO).
	gso       *gsoConn
	mux       *ice.UniversalUDPMuxDefault
	demux     *demuxPacketConn
	srcToPeer map[netip.AddrPort]*peerICE // direct remote addr -> peer, for WG RX routing
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
		wanted:    map[[32]byte]PeerSetup{},
		backoff:   map[[32]byte]int{},
		srcToPeer: map[netip.AddrPort]*peerICE{},
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
// goroutines concurrently. For non-relayOnly binds it also opens ONE shared
// GSO/GRO UDP socket per VNI and runs pion's UniversalUDPMux on it (host+srflx),
// plus a single RX loop that demuxes STUN→pion and WG→recvCh — so the direct
// (incl. NAT-traversed) data path batches packets per syscall (multi-gig). If the
// socket/mux can't be set up it degrades to per-peer pion sockets (the prior
// behavior, no GSO). Port 0 is reported (the device's own listen port is unused).
func (b *ICEBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		b.closed = false
		b.recvCh = make(chan recvMsg, 1024)
		b.done = make(chan struct{})
	}
	if !b.relayOnly && b.gso == nil {
		if uc, err := net.ListenUDP("udp4", &net.UDPAddr{}); err != nil {
			b.log.Warn("shared GSO socket unavailable; falling back to per-peer sockets (no GSO)", "err", err)
		} else {
			gso := newGSOConn(uc)
			demux := newDemuxPacketConn(gso, b.done)
			mux := ice.NewUniversalUDPMuxDefault(ice.UniversalUDPMuxParams{UDPConn: demux})
			b.gso, b.demux, b.mux = gso, demux, mux
			go b.readLoop()
			b.log.Info("shared GSO data socket up", "addr", gso.LocalAddr().String(), "batch", gso.batchSize())
		}
	}
	go b.livenessWatchdog() // recreates connected-but-silent peers (pion-independent path-death recovery)
	fns := make([]conn.ReceiveFunc, numDrainers)
	for i := range fns {
		fns[i] = b.receive
	}
	return fns, 0, nil
}

// livenessWatchdog recreates any peer that ICE still considers connected but that
// has gone silent past livenessStale despite its 25s keepalive — i.e. the path
// died and pion's consent freshness didn't catch it (notably a TURN relay
// restart). Runs for every bind (relayOnly included — that's exactly the relay
// floor that needs it). Bounded: one recreate per stale peer, gated by restarting.
func (b *ICEBind) livenessWatchdog() {
	const (
		interval      = 10 * time.Second
		livenessStale = 45 * time.Second // > 1.8x the 25s keepalive (no false positives on idle-but-live peers)
	)
	for {
		select {
		case <-b.done:
			return
		case <-time.After(interval):
		}
		now := time.Now().UnixNano()
		b.mu.Lock()
		var stale []*peerICE
		for _, p := range b.peers {
			p.mu.Lock()
			connected := p.iceConnected && !p.restarting
			p.mu.Unlock()
			if !connected {
				continue
			}
			if last := p.lastRX.Load(); last != 0 && time.Duration(now-last) > livenessStale {
				stale = append(stale, p)
			}
		}
		b.mu.Unlock()
		for _, p := range stale {
			p.mu.Lock()
			restart := !p.restarting
			if restart {
				p.restarting = true
			}
			p.mu.Unlock()
			if restart {
				b.log.Info("peer RX stale; recreating (liveness watchdog)", "peer", shortHex(p.wgPub),
					"idle", time.Duration(now-p.lastRX.Load()).Round(time.Second).String())
				go b.recreatePeer(p)
			}
		}
	}
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
	gso := b.gso
	b.mu.Unlock()
	if p == nil {
		return nil // peer gone mid-flight; next reconcile fixes it
	}
	// DIRECT (host/srflx): GSO-batch the whole per-peer batch in one sendmmsg on
	// the shared socket — the multi-gig path, traversing the same NAT hole pion
	// punched (the srflx candidate's source IS this socket).
	if gso != nil {
		if ap := p.directAddr.Load(); ap != nil {
			return gso.WriteBatchTo(bufs, *ap)
		}
	}
	// RELAY / pre-direct: per-datagram via the pion *ice.Conn (TURN client socket).
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

// BatchSize is the GSO/GRO batch width: 128 on Linux (sendmmsg/recvmmsg), 1
// elsewhere. The device stages up to this many packets per peer per Send.
func (b *ICEBind) BatchSize() int       { return gsoBatchSize }
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
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	close(b.done) // wakes drainers + readLoop + demux readers; recvCh is never closed
	peers := b.peers
	mux, gso := b.mux, b.gso
	b.peers = map[[32]byte]*peerICE{}
	b.srcToPeer = map[netip.AddrPort]*peerICE{}
	b.mux, b.gso, b.demux = nil, nil, nil
	b.mu.Unlock()

	for _, p := range peers {
		p.mu.Lock()
		if p.cancel != nil {
			p.cancel()
		}
		p.mu.Unlock()
		if p.agent != nil {
			_ = p.agent.Close()
		}
	}
	if mux != nil {
		_ = mux.Close()
	}
	if gso != nil {
		_ = gso.Close() // unblocks readLoop's ReadBatch
	}
	return nil
}

// SyncPeers reconciles the ICE agent set against the gateway's desired peers.
func (b *ICEBind) SyncPeers(setups []PeerSetup) {
	want := make(map[[32]byte]bool, len(setups))
	// Record the desired set FIRST so an in-flight recreatePeer (which re-adds via
	// ensurePeer) never resurrects a peer this sync is about to remove.
	b.mu.Lock()
	b.wanted = make(map[[32]byte]PeerSetup, len(setups))
	for _, s := range setups {
		b.wanted[s.WGPub] = s
	}
	b.mu.Unlock()
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
			delete(b.backoff, k)
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

	// Tighten ICE timeouts so a misaligned attempt (e.g. the two ends recreating
	// out of phase after a relay restart) gives up fast and the next recreate
	// cycle aligns quickly — pion's 25s default makes recovery take minutes. Floor
	// is the 2s keepalive; 5s disconnected + 8s failed keeps ample grace for a
	// healthy path (and a false-fail just recreates, which WG floats over).
	disconnectedTimeout := 5 * time.Second
	failedTimeout := 8 * time.Second
	keepaliveInterval := 2 * time.Second
	agentCfg := &ice.AgentConfig{
		Urls:                urls,
		NetworkTypes:        []ice.NetworkType{ice.NetworkTypeUDP4},
		CandidateTypes:      candTypes,
		DisconnectedTimeout: &disconnectedTimeout,
		FailedTimeout:       &failedTimeout,
		KeepaliveInterval:   &keepaliveInterval,
	}
	// Gather host+srflx on the SHARED GSO socket (so all peers multiplex one
	// socket and the direct/NAT-traversed data path can GSO-batch from it). Relay
	// candidates still use pion's own TURN client socket (unaffected).
	b.mu.Lock()
	mux := b.mux
	b.mu.Unlock()
	if mux != nil && !b.relayOnly {
		agentCfg.UDPMux = mux
		agentCfg.UDPMuxSrflx = mux
	}
	a, err := ice.NewAgent(agentCfg)
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
			p.lastRX.Store(time.Now().UnixNano()) // seed liveness so the watchdog waits a full window
			p.mu.Lock()
			p.iceConnected = true
			p.restarting = false
			p.mu.Unlock()
			b.mu.Lock()
			delete(b.backoff, s.WGPub) // converged: clear the recreate backoff
			b.mu.Unlock()
		case ice.ConnectionStateFailed:
			// Recovery from ANY ICE failure — both an initial connect that never
			// reached Connected (e.g. a NAT'd relay-floor peer whose first attempt
			// raced the other side coming up) AND an established path that dropped
			// (e.g. the relay restarted, killing the selected pair). pion's in-place
			// agent.Restart does NOT reliably resume the check loop, so we fully
			// RECREATE the peer's ICE agent (fresh Dial), reusing the proven
			// initial-connect path with bounded backoff. The WG endpoint is
			// gz:<wgpub> (unchanged), so the bind just swaps to the new *ice.Conn —
			// WG keeps its session (no re-handshake within the rekey window). The
			// restarting flag + recreatePeer's idempotency dedup concurrent triggers.
			p.mu.Lock()
			restart := !p.restarting
			if restart {
				p.restarting = true
			}
			p.iceConnected = false
			p.mu.Unlock()
			if restart {
				go b.recreatePeer(p)
			}
		case ice.ConnectionStateDisconnected:
			p.mu.Lock()
			p.iceConnected = false
			p.mu.Unlock()
		}
	})
	_ = a.OnSelectedCandidatePairChange(func(local, remote ice.Candidate) {
		// A DIRECT pair (host/srflx, not relay) ⇒ record the peer's remote UDP
		// endpoint so Send GSO-batches straight to it on the shared socket, and map
		// that src→peer for WG RX demux. A relay pair ⇒ clear it (Send falls back to
		// the per-datagram ice.Conn over TURN).
		var ap *netip.AddrPort
		if remote.Type() != ice.CandidateTypeRelay && local.Type() != ice.CandidateTypeRelay {
			if addr, err := netip.ParseAddr(remote.Address()); err == nil {
				v := normAP(netip.AddrPortFrom(addr, uint16(remote.Port())))
				ap = &v
			}
		}
		old := p.directAddr.Swap(ap)
		b.mu.Lock()
		if old != nil {
			delete(b.srcToPeer, *old)
		}
		if ap != nil {
			b.srcToPeer[*ap] = p
		}
		b.mu.Unlock()
		b.log.Info("ice pair selected", "peer", shortHex(s.WGPub),
			"local", local.Type().String(), "remote", remote.Type().String(), "direct", ap != nil)
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

// reannounce re-sends our ICE creds + gathered candidates until the peer connects
// — PERPETUALLY, never capped — so convergence is robust no matter when the other
// side's agent appears (late enroll, worker restart after a TUF self-update, a
// recreatePeer rebuild on either end). The gateway holds no signaling state and
// drops a disco msg to an offline peer, so the ONLY thing that guarantees both
// sides eventually hold each other's creds is that both keep announcing until
// connected. Cadence is tiered to stay cheap: fast while converging, slow as a
// steady-state heartbeat for a peer that is simply unreachable right now.
// Idempotent at the receiver (AddRemoteCandidate dedups; the one-shot connect
// ignores repeat creds). Stops only when this peerICE connects, is replaced
// (recreate/teardown), or the bind closes.
func (b *ICEBind) reannounce(p *peerICE, sink SignalSink, ufrag, pwd string) {
	if sink == nil {
		return
	}
	for i := 0; ; i++ {
		d := 2 * time.Second // first ~30s: fast convergence
		switch {
		case i >= 39:
			d = 10 * time.Second // after ~2min: slow heartbeat
		case i >= 15:
			d = 5 * time.Second // ~30s..2min
		}
		select {
		case <-time.After(d):
		case <-b.done:
			return
		}
		b.mu.Lock()
		replaced := b.peers[p.wgPub] != p
		b.mu.Unlock()
		if replaced {
			return // this peerICE was recreated/torn down; its re-announce is stale
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

// recreateBackoff is the per-attempt delay before rebuilding a failed peer's ICE
// agent, capped so a persistently-unreachable peer retries at a steady low rate
// (and doesn't hammer the TURN relay) while a transient failure recovers fast.
var recreateBackoff = []time.Duration{2 * time.Second, 3 * time.Second, 5 * time.Second, 8 * time.Second, 12 * time.Second, 20 * time.Second}

// recreatePeer tears down a failed peer's ICE agent and rebuilds it from scratch
// (fresh agent + fresh Dial), reusing the initial-connect path. This is the SINGLE
// recovery path for every ICE failure — initial connect that never succeeded as
// well as an established path that dropped. Both peers keep retrying (perpetual
// re-announce + recreate) until their attempts overlap and the connectivity check
// completes, so a NAT'd relay-floor peer converges even if the first try raced.
// Bounded by pion's FailedTimeout (~25s) per attempt plus an escalating backoff.
// Idempotent: if this peerICE was already replaced (concurrent trigger) or torn
// down (no longer wanted), it does nothing — it never resurrects a removed peer.
// The WG endpoint (gz:<wgpub>) is unchanged, so the bind swaps to the new
// *ice.Conn transparently — no WG re-handshake within the rekey window.
func (b *ICEBind) recreatePeer(p *peerICE) {
	b.mu.Lock()
	if b.closed || b.peers[p.wgPub] != p {
		b.mu.Unlock()
		return // already replaced or shutting down
	}
	delete(b.peers, p.wgPub)
	attempt := b.backoff[p.wgPub]
	b.backoff[p.wgPub] = attempt + 1
	b.mu.Unlock()

	p.mu.Lock()
	if p.cancel != nil {
		p.cancel()
	}
	p.mu.Unlock()
	if p.agent != nil {
		_ = p.agent.Close()
	}
	// Jittered backoff: +0..100% so the two ends DON'T recreate in lockstep — with
	// identical ladders both peers' Dial/Accept windows kept missing, needing many
	// cycles to align. Random offset desyncs them so a fresh pair overlaps in 1-2
	// cycles (this is the dominant factor in relay-restart recovery time).
	base := recreateBackoff[min(attempt, len(recreateBackoff)-1)]
	d := base + time.Duration(rand.Int64N(int64(base)))
	b.log.Info("ice path failed; recreating peer agent", "peer", shortHex(p.wgPub), "attempt", attempt+1, "backoff", d.Round(100*time.Millisecond))
	select {
	case <-time.After(d): // backoff (also lets a restarted relay settle)
	case <-b.done:
		return
	}
	// Only rebuild if the peer is STILL wanted (a SyncPeers during the backoff may
	// have removed it) and we're not shutting down.
	b.mu.Lock()
	setup, wanted := b.wanted[p.wgPub]
	rebuild := !b.closed && wanted
	b.mu.Unlock()
	if rebuild {
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

// OnICECreds records the peer's ufrag/pwd and starts the ICE connection once per
// agent instance (pion's Dial/Accept is once-per-agent). Exactly one side Dials,
// the other Accepts (role fixed by PeerSetup.Controlling). If the creds we lock
// onto turn out to be superseded (the peer recreated its agent after we Dialed),
// the connectivity check simply fails and recreatePeer rebuilds THIS side too;
// both ends keep recreating + re-announcing (perpetually) until a matched pair of
// fresh agents completes the check. So a one-shot-per-instance connect is safe
// without any gateway-side signaling state.
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
		// Deterministic recovery: this agent's Dial/Accept is spent (pion is
		// once-per-agent), so rebuild a fresh one rather than leaving the peer
		// stuck. Leave connecting=true so a stray repeat-cred can't re-Dial this
		// dead agent before the recreate swaps in a new peerICE. The Failed
		// state-change may also fire recreate; restarting + recreatePeer idempotency
		// collapse them to a single rebuild.
		p.mu.Lock()
		restart := !p.restarting
		if restart {
			p.restarting = true
		}
		p.mu.Unlock()
		if restart {
			go b.recreatePeer(p)
		}
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
				p.lastRX.Store(time.Now().UnixNano()) // liveness (relay path)
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

// normAP normalizes an AddrPort to unmapped IPv4 so map keys are consistent
// whether the addr came from the kernel (4-byte) or netip.ParseAddr of a pion
// candidate string.
func normAP(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// readLoop is the single RX goroutine for the shared GSO socket. It reads a
// GRO-coalesced batch per syscall and demultiplexes: STUN packets go to pion (via
// the demux PacketConn the UniversalUDPMux reads), WireGuard packets are routed to
// the owning peer (by source addr) and pushed to recvCh for the device drainers.
// One reader ⇒ no contention on the gso RX scratch. Exits on Close.
func (b *ICEBind) readLoop() {
	out := make([][]byte, gsoBatchSize)
	for i := range out {
		out[i] = make([]byte, iceReadBuf)
	}
	sizes := make([]int, gsoBatchSize)
	srcs := make([]netip.AddrPort, gsoBatchSize)
	for {
		select {
		case <-b.done:
			return
		default:
		}
		b.mu.Lock()
		gso := b.gso
		b.mu.Unlock()
		if gso == nil {
			return
		}
		n, err := gso.ReadBatchInto(out, sizes, srcs)
		if err != nil {
			select {
			case <-b.done:
				return
			case <-time.After(time.Millisecond): // transient; closed socket also surfaces via b.done
			}
			continue
		}
		for i := 0; i < n; i++ {
			pkt := out[i][:sizes[i]]
			if stun.IsMessage(pkt) {
				b.demux.push(pkt, srcs[i]) // → pion UniversalUDPMux
				continue
			}
			key := normAP(srcs[i])
			b.mu.Lock()
			p := b.srcToPeer[key]
			if p != nil && b.peers[p.wgPub] != p { // stale entry (peer recreated/removed)
				delete(b.srcToPeer, key)
				p = nil
			}
			b.mu.Unlock()
			if p == nil {
				continue // unknown WG src; drop (WG retransmits once the pair is selected)
			}
			p.lastRX.Store(time.Now().UnixNano()) // liveness
			buf := bufPool.Get().([]byte)
			nn := copy(buf, pkt)
			select {
			case b.recvCh <- recvMsg{ep: &genezaEndpoint{wgPub: p.wgPub}, buf: buf, n: nn}:
			case <-b.done:
				bufPool.Put(buf) //nolint:staticcheck
				return
			default: // backpressure: drop, like a UDP socket
				bufPool.Put(buf) //nolint:staticcheck
			}
		}
	}
}

// demuxPacketConn is the net.PacketConn handed to pion's UniversalUDPMux. The
// shared socket is read by ICEBind.readLoop, which feeds ONLY STUN packets here;
// pion's mux connWorker drains them via ReadFrom. WriteTo (pion's STUN /
// connectivity-check sends) goes straight out the shared socket. Close is a no-op
// — the socket is owned by ICEBind (the mux must not close it out from under us).
type demuxPacketConn struct {
	gso  *gsoConn
	in   chan demuxPkt
	done <-chan struct{}
}

type demuxPkt struct {
	buf []byte
	src *net.UDPAddr
}

func newDemuxPacketConn(gso *gsoConn, done <-chan struct{}) *demuxPacketConn {
	return &demuxPacketConn{gso: gso, in: make(chan demuxPkt, 256), done: done}
}

func (d *demuxPacketConn) push(p []byte, src netip.AddrPort) {
	cp := make([]byte, len(p))
	copy(cp, p)
	pkt := demuxPkt{buf: cp, src: net.UDPAddrFromAddrPort(src)}
	select {
	case d.in <- pkt:
	case <-d.done:
	default: // STUN retransmits; never block the RX loop
	}
}

func (d *demuxPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt := <-d.in:
		return copy(p, pkt.buf), pkt.src, nil
	case <-d.done:
		return 0, nil, net.ErrClosed
	}
}

func (d *demuxPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return d.gso.WriteTo(p, addr)
}
func (d *demuxPacketConn) Close() error                     { return nil }
func (d *demuxPacketConn) LocalAddr() net.Addr              { return d.gso.LocalAddr() }
func (d *demuxPacketConn) SetDeadline(time.Time) error      { return nil }
func (d *demuxPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (d *demuxPacketConn) SetWriteDeadline(time.Time) error { return nil }
