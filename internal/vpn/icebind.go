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

	mu          sync.Mutex
	conn        *ice.Conn
	cancel      context.CancelFunc
	remoteUfrag string
	remotePwd   string
	connecting  bool
}

type recvMsg struct {
	ep   *genezaEndpoint
	data []byte
}

// iceBind is the conn.Bind for one Network (VNI): one ice.Agent + *ice.Conn per
// peer, multiplexed under a single ReceiveFunc.
type ICEBind struct {
	vni       uint32
	relayOnly bool // P-libs1: relay candidates only (force the TURN floor)
	log       *slog.Logger

	mu      sync.Mutex
	sink    SignalSink
	selfPub [32]byte
	peers   map[[32]byte]*peerICE
	recvCh  chan recvMsg
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
		recvCh:    make(chan recvMsg, 256),
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

// Open returns one ReceiveFunc draining recvCh. There is no single shared socket
// (each ice.Agent owns its sockets); port 0 is reported — the ICE model doesn't
// expose a fixed WG listen port.
func (b *ICEBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		b.closed = false
		b.recvCh = make(chan recvMsg, 256)
	}
	return []conn.ReceiveFunc{b.receive}, 0, nil
}

func (b *ICEBind) receive(pkts [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	msg, ok := <-b.recvCh
	if !ok {
		return 0, net.ErrClosed
	}
	n := copy(pkts[0], msg.data)
	sizes[0] = n
	eps[0] = msg.ep
	return 1, nil
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
	close(b.recvCh)
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

	// Trickle LOCAL candidates up the control stream (gateway forwards to the peer).
	_ = a.OnCandidate(func(c ice.Candidate) {
		if c == nil { // nil == gathering complete
			return
		}
		if sink != nil {
			sink.SendLocalCandidate(b.vni, s.WGPub, c.Marshal())
		}
	})
	_ = a.OnConnectionStateChange(func(st ice.ConnectionState) {
		b.log.Debug("ice state", "peer", shortHex(s.WGPub), "state", st.String())
		// On failure (e.g. the relay died, killing the selected pair), rebuild the
		// agent so it re-gathers a fresh relay allocation + re-announces. pion does
		// not re-allocate on its own; this is the recovery trigger.
		if st == ice.ConnectionStateFailed {
			go b.restartPeer(s.WGPub)
		}
	})
	_ = a.OnSelectedCandidatePairChange(func(local, remote ice.Candidate) {
		b.log.Info("ice pair selected", "peer", shortHex(s.WGPub),
			"local", local.Type().String(), "remote", remote.Type().String())
	})

	// Ship OUR ufrag/pwd up so the peer can Dial/Accept us.
	if ufrag, pwd, cerr := a.GetLocalUserCredentials(); cerr == nil && sink != nil {
		sink.SendICECreds(b.vni, s.WGPub, ufrag, pwd)
	}
	if err := a.GatherCandidates(); err != nil {
		b.log.Warn("ice gather failed", "peer", shortHex(s.WGPub), "err", err)
	}
}

// restartPeer tears down a failed peer's ICE agent and rebuilds it (re-gather +
// re-announce), with a short backoff so a persistently-unreachable relay doesn't
// spin. The agent's setup (TURN creds, role) is reused; the gateway's disco
// cache replays the peer's signaling so both ends re-converge.
func (b *ICEBind) restartPeer(wgPub [32]byte) {
	b.mu.Lock()
	p := b.peers[wgPub]
	if p == nil || b.closed {
		b.mu.Unlock()
		return
	}
	delete(b.peers, wgPub)
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
	b.log.Info("ice failed; rebuilding peer agent", "peer", shortHex(wgPub))
	time.Sleep(3 * time.Second) // backoff before re-gather
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return
	}
	b.ensurePeer(setup)
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

// OnICECreds records the peer's ufrag/pwd and starts the ICE connection once both
// sides' creds are known (exactly one side Dials, the other Accepts).
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
		go b.connect(p)
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
	go func() {
		buf := make([]byte, iceReadBuf)
		for {
			n, rerr := c.Read(buf)
			if n > 0 {
				d := make([]byte, n)
				copy(d, buf[:n])
				select {
				case b.recvCh <- recvMsg{ep: &genezaEndpoint{wgPub: p.wgPub}, data: d}:
				default: // drop on backpressure, like a UDP socket
				}
			}
			if rerr != nil {
				if errors.Is(rerr, io.ErrShortBuffer) {
					continue // datagram too big for buf; drop it, keep reading
				}
				return // closed / fatal
			}
		}
	}()
}

func shortHex(k [32]byte) string { return hex.EncodeToString(k[:4]) }
