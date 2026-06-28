# Data plane on industry-standard libraries: pion/ice + pion/turn + pion/stun over wireguard-go

Status: **PLAN (supersedes the hand-rolled magicsock-lite in `docs/magicsock-design.md` and
`docs/wg-dataplane-plan.md` Phase D–G).** Decision owner: lead architect. Target task: #37
(re-scoped from "hand-rolled magicsock-lite" to "WireGuard-over-ICE on pion").

This document is the definitive migration plan to replace Geneza's hand-rolled NAT-traversal
(`internal/vpn/bind.go`'s STUN+disco+hole-punch and `internal/relay/udpforward.go`'s blind
rid-keyed UDP relay) with RFC-standard, widely-deployed Go libraries — while keeping
**wireguard-go as the WG device** (it is the standard) and keeping Geneza's controller/policy/
control plane authoritative and unchanged.

It is grounded in source verified against the real modules in this host's Go cache:
`github.com/pion/ice/v4@v4.2.7`, `github.com/pion/turn/v5@v5.0.7`, `github.com/pion/stun/v3@v3.1.4`,
`github.com/pion/transport/v4@v4.0.2` — all confirmed **CGO-free** (no `import "C"` anywhere in
the trees).

---

## 0. The seam we are cutting at (what already exists)

Geneza already has the correct architectural seam. We are swapping the *implementation under the
seam*, not the seam:

- `internal/agentd/network.go` — `wgBackend` interface (`Create/SetAddr/Configure/ListenPort/Delete`)
  and the version-monotonic `reconcile`. **KEPT verbatim.**
- `internal/agentd/wg_userspace.go` — `userspaceWGBackend` implementing `wgBackend` + a
  `discoBackend` (`SetSignalSink`, `DeliverCallMeMaybe`, `DeliverPunchAt`). One
  `device.NewDevice(tun, bind, log)` per VNI. **KEPT as the orchestration shell; its body is
  rewired to drive pion instead of `MagicBind`.**
- `internal/vpn/bind.go` — `MagicBind` (`conn.Bind`) = the 824-line hand-rolled magicsock-lite.
  **DELETED and replaced by `iceBind`.**
- `internal/relay/udpforward.go` — the rid-keyed blind UDP forwarder. **DELETED and replaced by
  an embedded `pion/turn` server in the relay binary.**
- proto `DiscoMsg`/`EndpointUpdate`/`CallMeMaybe`/`PunchAt` (`api/proto/geneza/v1/control.proto`)
  + `WGPeer.relay` (`RelayPath`) — **KEPT and REUSED as the ICE signaling channel** (candidates +
  ufrag/pwd ride these existing fields; one additive field pair for ICE creds).
- `internal/controller/relaypath.go` — mints per-pair relay coordinates (rid pair + flow secret).
  **REPLACED by minting coturn-style ephemeral TURN credentials** (HMAC over a shared secret;
  same "controller mints, relay holds no per-pair state" property, now standards-based).

> Note for honesty: today's worker (`internal/agentd/worker.go`) wires `NetworkEndpoints` up the
> control stream but does **not yet** send/receive `DiscoMsg`. So the P2 disco signaling path is
> effectively a stub. That is good news: we have not yet shipped a hand-rolled disco wire format to
> production, so adopting pion's candidate strings now costs us nothing in compatibility.

---

## 1. Decision and rationale

**Decision: adopt WireGuard-over-ICE using pion (`ice` + `turn` + `stun`) under wireguard-go.**
Reject the tsnet/Headscale alternative. Reject keeping the hand-rolled magicsock-lite.

### 1.1 Why pion over the hand-rolled path

The user's stated philosophy is *reuse industry-standard libraries*. The hand-rolled
`bind.go`/`udpforward.go` violate that in exactly the place it hurts most: NAT classification,
STUN parsing, hole-punch timing, and connectivity checking are the highest-bug-density,
lowest-standard parts of any overlay. pion/ice is **RFC 8445 ICE** with **RFC 5389/8489 STUN** and
**RFC 5766/8656 TURN**, used by every browser via the broader pion stack and hardened over years.

What pion lets us delete from `bind.go` (824 lines), all of it security-sensitive and bespoke:
- STUN-lite client + NAT classification: `sendStunReq`/`onStunResp`/`localAddrs`/`natClass`
  (~150 lines) → pion gathers host + server-reflexive candidates via real STUN.
- disco ping/pong + candidate confirmation: `sendDiscoPing`/`onDiscoPing`/`onDiscoPong`/
  `peerForCandidate`/`discoTxid` (~140 lines) → pion's connectivity checks ARE the hole-punch.
- relay framing (REG/DATA/KEEPALIVE/STUNREQ + HMAC tail + rid pack/unpack) (~120 lines) → pion's
  TURN client speaks standard Allocate / CreatePermission / ChannelData.
- the maint/keepalive/probe loop choreography + `stRelay/stProbing/stDirect/stFallback` state
  machine (~120 lines) → **pion's agent runs all of this internally** (more below).

### 1.2 Why pion over tsnet/Headscale

`tailscale.com/wgengine/magicsock` is **not usable standalone**: every routing method is typed in
`tailcfg` (`SetNetworkMap(tailcfg.NodeView)`, `SetDERPMap(*tailcfg.DERPMap)`), and DeepWiki's own
component analysis states it "cannot function standalone with non-Tailscale control planes." The
only real embedding surface, `tsnet`, *requires a coordination server* (Tailscale SaaS or
Headscale) — there is no "no control plane" mode.

Embedding Headscale would force Geneza into **two control planes** and trade away the exact things
that are the product:
- **Single-session, controller-signed, agent-re-verified grants** → Tailscale's netmap is persistent
  membership, not per-session brokering.
- **Payload-blind, identity-blind relay** → DERP mailboxes are keyed by **node public key**; the
  relay learns every node's stable identity and the who-talks-to-whom graph. Strict regression.
- **Customer-IdP OIDC federation + OPA/Rego policy + workspace multi-tenancy** → Headscale is one
  tailnet per instance (multi-tenant = N Headscale processes), OIDC groups can't be used in ACLs,
  and ACLs are tags, not policy-as-data.

So tsnet/Headscale is *more* integration work AND it dismantles the differentiators. pion is the
opposite: it is a pure NAT-traversal library that **keeps Geneza's controller authoritative** — the
controller becomes the ICE signaling channel over the control stream it already owns, and the relay
becomes a TURN server the controller feeds credentials to. Effort is medium; standards-reuse is
maximal; the control plane is reused verbatim.

### 1.3 Effort summary (honest)

| Path | Reuse of standards | Fit with Geneza control plane | Relay blindness | Net new effort |
|---|---|---|---|---|
| Hand-rolled magicsock-lite | low (bespoke STUN/disco) | perfect | strongest (rid, payload+identity blind) | already partly built; **but we own every traversal bug** |
| **pion ice/turn/stun (chosen)** | **highest (RFC 8445/5389/5766)** | **good — controller is the ICE signaller + TURN credentialer** | payload-blind; TURN sees an opaque ephemeral principal + peer 5-tuples (acceptable, §1.4) | medium: per-peer agent lifecycle + signaling adapter + embedded TURN |
| tsnet + Headscale | Tailscale-proprietary (not a standard) | **poor — two control planes** | regression (DERP keyed by node pubkey) | high integration + high re-add of controller semantics + ongoing Headscale ops |

### 1.4 Zero-trust / blindness analysis for a standard TURN relay (the load-bearing question)

The headline property of `udpforward.go` is a **payload-blind AND identity-blind** relay: it sees
only an anonymous 48-bit rid and `copy()`s opaque bytes. Standard TURN changes one of those two
properties. Verified against `pion/turn`'s `internal/allocation/allocation.go`:

**Payload: still fully blind / still E2E.** The inbound-from-peer path does only
`proto.ChannelData{Data: buffer[:n]}` (or `proto.Data(buffer[:n])`) and forwards verbatim. The TURN
server never inspects, decrypts, or terminates the relayed bytes — they are an opaque attribute.
**WireGuard inside a TURN allocation stays end-to-end encrypted; the relay holds no WG key and never
sees plaintext.** This is byte-for-byte the same guarantee `udpforward.go` gives today.

**Metadata: TURN sees more than the rid model. This is the one real trade-off:**

| | today `udpforward.go` (rid) | pion/turn |
|---|---|---|
| Client identity | none — anonymous 48-bit rid; relay can't link flows to a principal | an authenticated `username` (`"<expiry-unix>:<id>"`), visible in the AuthHandler and tied to each allocation's 5-tuple |
| Peer addresses | sees both endpoints' ip:port (mailbox addr) | sees peer ip:port via CreatePermission/ChannelBind + the allocation 5-tuple |
| Per-flow state | rid→mailbox table, **no auth** | full allocations (5-tuple, lifetime, permissions) keyed to the authenticated principal |
| Payload | opaque | **opaque** |

**Is the trade-off acceptable? Yes — and it is on net a *security upgrade*, with one mitigation.**
- Today's rid model is *unauthenticated*: possession of an unguessable rid is the entire capability;
  `udpforward.go.register()`'s own comment admits "the relay cannot authenticate the claim." A
  leaked rid is a standing capability with no expiry. TURN credentials are **HMAC-authenticated and
  time-boxed** — a leaked credential auto-expires and an unauthorized party cannot allocate at all.
  That directly fixes the weakest part of the current design.
- The only regression is **anonymity**: TURN authenticates a principal. We **buy almost all of it
  back** by minting the REST username with an **opaque, rotating, per-session id** (the rid's spirit)
  rather than a stable user identity. The relay then sees "some authorized ephemeral principal + its
  peers for the lifetime of one allocation" — more than a pure rid but no payload and no durable
  identity. We mint `id = base64(random 96 bits)` per (workspace, vni, node-pair, session), rotated
  on the allocation TTL.
- **Acceptance criterion (write it into the threat model):** the relay remains payload-blind and
  WG-key-blind (unconditional); it learns an opaque, expiring, per-session principal and the peer
  5-tuples of active allocations (accepted, in exchange for authenticated + time-boxed access and
  standards-correctness). If absolute relay-side anonymity is later deemed a hard requirement, the
  fallback is documented in §9 (keep a rid-shaped *custom pion candidate* over the blind relay).

---

## 2. Exactly what to DELETE and what to KEEP

### 2.1 DELETE

- **`internal/vpn/bind.go`** — the entire `MagicBind` / magicsock-lite implementation:
  the relay frame format (`relayMagic 0x91`, `frameREG/DATA/KEEPALIVE/STUNREQ/STUNRESP/CLOSE/
  DiscoPing/DiscoPong`), `peerState` with `relaySelf/relayPeer/flowSecret/state/directOK`, the
  `stRelay/stProbing/stDirect/stFallback` state machine, `keepaliveLoop`, `maintLoop`,
  `sendReg`, `sendStunReq`, `onStunResp`, `localAddrs` (NAT classification), `sendDiscoPing`,
  `onDiscoPing`, `onDiscoPong`, `peerForCandidate`, `putRid`/`getRid`. **Gone in full.** Replaced by
  `internal/vpn/icebind.go` (`iceBind`). The `genezaEndpoint{wgPub}` type and `ParseEndpoint`
  `gz:<hex>` token are the one part of bind.go **kept** (carried into icebind.go — it is the lever
  that lets the live path float without a WG re-handshake; see §3.1).
- **`internal/relay/udpforward.go`** — the rid-keyed blind forwarder: frame format, `udpMailbox`
  table, `register`/`forward`/`stunReply`/`sweepLoop`, rid pack/unpack. Replaced by
  `internal/relay/turnserver.go` (embedded `pion/turn`). `udpforward_test.go` deleted with it.
- **`internal/controller/relaypath.go`** — `relayPathFor`, `relayCoords`, `mintRid`, `mintSecret`,
  the `RelayPathRecord` get-or-create. Replaced by `internal/controller/turncreds.go`
  (coturn-style ephemeral credential minting; **no persistence — credentials are derived, not
  stored**, which also lets us delete the `RelayPathRecord` bucket from the store).
- **rid / flow_secret / RelayPath wire surface (semantic deletion, see §3.4 for the proto detail):**
  the *meaning* of `RelayPath{relay_addr, self_rid, peer_rid, flow_secret}` is retired. We reuse the
  message slot but repurpose its fields to `{turn_url, turn_username, turn_password, turn_realm}`
  (or add a sibling `TurnCreds` and reserve the old fields — §3.4 picks the cleaner option).
- **From `bind.go`/`udpforward.go` constants:** `ridMax`, `ridMask48`, `minRegTail`,
  `minStunReq`, `stunPadTo`, `maxMailboxes`, `relayKeepaliveInt`, `directDeadTimeout`,
  `maintInterval` — all become pion `AgentConfig` timing knobs (§3.1) or vanish.

### 2.2 KEEP (verbatim or near-verbatim)

- **wireguard-go userspace backend shell** — `device.NewDevice(tun, bind, log)` per VNI in
  `wg_userspace.go`; `renderUAPI` (synthesizing `endpoint=gz:<hex(pubkey)>` for every peer so
  wireguard-go will send a handshake — still required); `vniFromIfName`; the `usDevice` struct.
  The wireguard-go dependency (`golang.zx2c4.com/wireguard`) stays — **it IS the standard WG.**
- **The whole control plane**, unchanged: membership/tag-gating (`policy.LabelsMatch` on Network
  `Selector`), `NetworkConfig`/`NetworkSpec`/`WGPeer`, IPAM (`BindingRecord`/`allocIPInCIDR`/
  VNI-qualified FIB), `networkpush.go` (`desiredNetworks`/`networkPeers`/`networkOverlayIP`),
  `registry.SendNetworkConfig` + monotonic `nextNetVersion`, push-on-connect,
  `repushAllNetworks` on approve/remove.
- **The `wgBackend` seam** (`network.go`) — `Create/SetAddr/Configure/ListenPort/Delete` + the
  version-monotonic `reconcile`. Reconcile logic is untouched; only the backend body changes.
- **The `discoBackend` seam + DiscoMsg/EndpointUpdate proto** — `SetSignalSink`,
  `DeliverCallMeMaybe`, `DeliverPunchAt`, `SignalSink.SendEndpointUpdate`, and
  `DiscoMsg{vni, peer_wgpub, CallMeMaybe|PunchAt|EndpointUpdate}`. **Reused as ICE signaling**
  (§3.3): `EndpointUpdate.local_addrs`/`reflexive` carry pion candidate strings; `CallMeMaybe`
  carries the remote's candidate strings into `AddRemoteCandidate`; `PunchAt` demotes to "begin /
  restart ICE now"; one additive field pair carries ufrag/pwd.
- **The controller as authoritative coordinator** — it already orders the peer pair (lo/hi) to mint
  rids; that same ordering now (a) assigns ICE controller vs controlled, and (b) names the TURN
  REST username's session id. The dial-out / no-inbound model is preserved: agents only ever send
  *outbound* to the TURN server.
- **Per-VNI device + TUN + overlay IP assignment** (`WGSetAddr`, `gnzw<vni>` naming) and the
  kernel-WG backend (`realWGBackend`) as the alternate `dataplane: kernel` path. The
  `dataplane: userspace` switch in config selects pion.

---

## 3. The new design (grounded in the real pion APIs)

Three components: (A) `iceBind` — a `conn.Bind` over per-peer pion ICE agents; (B) an embedded
`pion/turn` server in the relay binary; (C) controller-minted ephemeral TURN credentials + ICE
signaling over the existing control stream. wireguard-go sits on top of (A), unchanged.

```
  wireguard-go device (per VNI)            relay binary (geneza-core)
        │  conn.Bind                          ┌───────────────────────────┐
        ▼                                     │  pion/turn.Server          │
  ┌───────────────┐   STUN/TURN/ICE           │  (you pass the UDPConn)    │
  │   iceBind     │◀───── over UDP ──────────▶│  LongTermTURNRESTAuthHandler│
  │ map[wgPub]:   │   (relay candidate)       │  payload-blind: copy()      │
  │  *ice.Agent   │                           └───────────────────────────┘
  │  *ice.Conn    │   candidates + ufrag/pwd            ▲ shared secret
  └───────┬───────┘   over control stream               │
          │            (DiscoMsg / EndpointUpdate)       │
          ▼                                              │
   controller control stream  ────────────────────  controller mints REST creds
   (existing mTLS gRPC NodeControl)              GenerateLongTermTURNRESTCredentials
```

### 3.1 `iceBind` — the `conn.Bind` over per-peer ICE (`internal/vpn/icebind.go`)

Per the WireGuard-over-ICE research, an `*ice.Conn` **implements `net.Conn` only (not
`net.PacketConn`) but is datagram-framed** (its `Read` is backed by `pion/transport/packetio.Buffer`,
which preserves message boundaries: one `Read` == one inbound datagram, one `Write` == one outbound
datagram). `Conn.Write` rejects STUN messages (`stun.IsMessage`), but WG packets are never STUN
messages, so they pass cleanly. That is exactly the datagram pipe wireguard-go's `conn.Bind` needs.

Because an `*ice.Conn` is **single-peer**, the bind is the multiplexer: **one `*ice.Agent` +
one `*ice.Conn` per peer**, keyed by WG pubkey (the cunicu/NetBird pattern; Geneza's
`genezaEndpoint{wgPub}` is the clean key — keep it). `Send(bufs, ep)` type-asserts the endpoint,
looks up that peer's `*ice.Conn`, and writes; a per-peer reader goroutine does `iceConn.Read` and
pushes up to the single `ReceiveFunc` via a channel.

```go
package vpn

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
	"golang.zx2c4.com/wireguard/conn"
)

// genezaEndpoint and ParseEndpoint("gz:<hex>") are carried over from bind.go
// unchanged — the peer is identified by WG pubkey so the live ICE path can
// float under wireguard-go without a re-handshake.

// peerICE is one peer's ICE session.
type peerICE struct {
	wgPub       [32]byte
	controlling bool
	agent       *ice.Agent
	conn        *ice.Conn      // non-nil after Dial/Accept completes
	cancel      context.CancelFunc
	remoteUfrag string
	remotePwd   string
	mu          sync.Mutex
}

// iceCreds is what the controller minted for THIS peer (per §3.2/§3.3).
type peerSetup struct {
	wgPub       [32]byte
	controlling bool          // controller-assigned (lo=controlling)
	turnURL     string        // "turn:geneza-core:7404?transport=udp"
	turnUser    string        // "<expiry-unix>:<sessionID>"
	turnPass    string        // base64(HMAC-SHA1(secret, turnUser))
	turnRealm   string        // "geneza"
}

type iceBind struct {
	vni  uint32
	log  *slog.Logger
	sink SignalSink

	mu      sync.Mutex
	peers   map[[32]byte]*peerICE
	selfPub [32]byte
	recvCh  chan recvMsg
	closed  bool
}

type recvMsg struct {
	ep   *genezaEndpoint
	data []byte
	n    int
}

var _ conn.Bind = (*iceBind)(nil)

func NewICEBind(vni uint32, log *slog.Logger) *iceBind {
	return &iceBind{
		vni:    vni,
		log:    log.With("component", "icebind", "vni", vni),
		peers:  map[[32]byte]*peerICE{},
		recvCh: make(chan recvMsg, 256),
	}
}

// Open: there is no single shared socket to bind (each ice.Agent owns its
// sockets; for port sharing we add WithUDPMux later — §8). We return one
// ReceiveFunc draining recvCh; port 0 is reported (the controller uses the control
// stream's observed source IP, not a fixed WG listen port, in the ICE model).
func (b *iceBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		b.closed = false
		b.recvCh = make(chan recvMsg, 256)
	}
	return []conn.ReceiveFunc{b.receive}, 0, nil
}

func (b *iceBind) receive(pkts [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	msg, ok := <-b.recvCh
	if !ok {
		return 0, net.ErrClosed
	}
	n := copy(pkts[0], msg.data[:msg.n])
	sizes[0] = n
	eps[0] = msg.ep
	return 1, nil
}

func (b *iceBind) Send(bufs [][]byte, ep conn.Endpoint) error {
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

func (b *iceBind) BatchSize() int { return 1 } // ice.Conn is one-datagram
func (b *iceBind) SetMark(uint32) error { return nil }
// ParseEndpoint: identical to bind.go's gz:<hex> parser (kept).

func (b *iceBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	for _, p := range b.peers {
		if p.cancel != nil {
			p.cancel()
		}
		if p.agent != nil {
			_ = p.agent.Close()
		}
	}
	b.peers = map[[32]byte]*peerICE{}
	close(b.recvCh)
	return nil
}
```

**Per-peer agent lifecycle** (driven from `Configure`, mirroring today's `SyncPeers`):

```go
// SyncPeers reconciles the ICE agent set against the controller's desired peers,
// using the TURN creds + controller role the controller minted for each.
func (b *iceBind) SyncPeers(setups []peerSetup) {
	for _, s := range setups {
		b.ensurePeer(s)
	}
	// (tear down agents for peers no longer present, like reconcile does)
}

func (b *iceBind) ensurePeer(s peerSetup) {
	b.mu.Lock()
	if _, ok := b.peers[s.wgPub]; ok {
		b.mu.Unlock()
		return // already up; cred refresh handled by ICE restart on expiry
	}
	b.mu.Unlock()

	turn, _ := stun.ParseURI(s.turnURL)
	turn.Username, turn.Password = s.turnUser, s.turnPass
	stunURI, _ := stun.ParseURI("stun:" + hostOf(s.turnURL)) // same host, STUN for srflx

	a, err := ice.NewAgent(&ice.AgentConfig{
		Urls:           []*stun.URI{stunURI, turn},
		NetworkTypes:   []ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6},
		CandidateTypes: []ice.CandidateType{
			ice.CandidateTypeHost,
			ice.CandidateTypeServerReflexive,
			ice.CandidateTypeRelay, // the always-available floor (TURN)
		},
		// Per-type nomination waits: relay default 2s so DIRECT pairs (host/srflx)
		// win the selection if reachable, relay is the fallback (RFC 8445 priority).
	})
	if err != nil {
		b.log.Warn("ice agent create failed", "peer", hex.EncodeToString(s.wgPub[:4]), "err", err)
		return
	}

	p := &peerICE{wgPub: s.wgPub, controlling: s.controlling, agent: a}
	b.mu.Lock()
	b.peers[s.wgPub] = p
	self := b.selfPub
	b.mu.Unlock()

	// Trickle LOCAL candidates up the control stream (reuses EndpointUpdate).
	_ = a.OnCandidate(func(c ice.Candidate) {
		if c == nil { // nil == gathering complete
			return
		}
		b.sink.SendEndpointUpdateForPeer(b.vni, s.wgPub, c.Marshal())
	})
	_ = a.OnConnectionStateChange(func(st ice.ConnectionState) {
		b.log.Debug("ice state", "peer", hex.EncodeToString(s.wgPub[:4]), "state", st.String())
	})
	_ = a.OnSelectedCandidatePairChange(func(local, remote ice.Candidate) {
		b.log.Info("ice pair selected", "peer", hex.EncodeToString(s.wgPub[:4]),
			"local", local.Type().String(), "remote", remote.Type().String()) // host/srflx/relay
	})

	// Ship OUR ufrag/pwd up the control stream so the peer can Dial/Accept us.
	ufrag, pwd, _ := a.GetLocalUserCredentials()
	b.sink.SendICECreds(b.vni, s.wgPub, ufrag, pwd)

	if err := a.GatherCandidates(); err != nil {
		b.log.Warn("ice gather failed", "err", err)
		return
	}
	_ = self
	// Dial/Accept happens once we have the remote's ufrag/pwd (§3.3 OnICECreds).
}

// connectLocked is invoked when the remote ufrag/pwd arrive: exactly one side
// Dials (controlling), the other Accepts. Blocks until a pair succeeds (or ctx).
func (b *iceBind) connect(p *peerICE) {
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
		b.log.Warn("ice connect failed", "peer", hex.EncodeToString(p.wgPub[:4]), "err", err)
		return
	}
	p.mu.Lock()
	p.conn = c
	p.mu.Unlock()
	b.log.Info("ice connected", "peer", hex.EncodeToString(p.wgPub[:4]))

	// Per-peer reader: one Read == one inbound WG datagram -> recvCh -> ReceiveFunc.
	go func() {
		buf := make([]byte, 1500)
		for {
			n, rerr := c.Read(buf)
			if rerr != nil {
				return
			}
			d := make([]byte, n)
			copy(d, buf[:n])
			select {
			case b.recvCh <- recvMsg{ep: &genezaEndpoint{wgPub: p.wgPub}, data: d, n: n}:
			default: // drop on backpressure, like a UDP socket
			}
		}
	}()
}
```

**The relay→direct upgrade is handled by ICE — we do NOT hand-write the state machine.** This is
the decisive simplification versus `bind.go`. We put **all three candidate types in ONE agent**
(host + server-reflexive + relay). pion runs connectivity checks across every local×remote pair and
**nominates the highest-priority pair that works**; relay candidates have the lowest RFC-8445
priority, so if a direct (host or srflx) pair is reachable, ICE selects direct from the start — and
if it isn't, ICE selects the relay floor. The `*ice.Conn` we hand wireguard-go is **stable across
the pair selection** — pion swaps the underlying pair internally, the `Conn` (and therefore the WG
`genezaEndpoint`) does not change, so wireguard-go never re-handshakes on an upgrade. The old
`stRelay/stProbing/stDirect/stFallback` machine, `maintLoop`, `directDeadTimeout` fallback, and
disco keepalive **all disappear** — pion's `KeepaliveInterval` (2s default), `DisconnectedTimeout`
(5s), and `FailedTimeout` (25s) replace them.

> Honest caveat (from the WireGuard-over-ICE research): pion's selected pair is **fixed once
> nominated within a single connectivity-check run** — there is no automatic *later* relay→direct
> *re-*upgrade if a direct path only becomes reachable minutes after the relay pair was nominated.
> For Geneza this is acceptable: the common case (both candidate sets known up front) selects direct
> immediately; for the rare late-upgrade case we trigger `agent.Restart(...)` on the `PunchAt`
> signal (now repurposed to "re-run ICE"), which re-gathers and re-selects with the same `*ice.Conn`
> preserved. That is one explicit, controller-driven trigger — not a hand-written per-packet SM.

### 3.2 Embedded `pion/turn` server in the relay binary (`internal/relay/turnserver.go`)

`pion/turn` **allocates no UDP sockets itself — you pass it the `net.PacketConn`**, so the relay
keeps owning its data socket exactly like `udpforward.go` does today (co-resident with the TCP
rendezvous splice, untouched). Verified against `pion/turn/v5@v5.0.7`.

```go
package relay

import (
	"net"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// turnRelay is the standards-based replacement for udpForwarder: an embedded TURN
// server that forwards opaque ChannelData/Data verbatim (payload-blind, E2E WG),
// authenticated by controller-minted coturn-style ephemeral credentials (§3.3). The
// relay holds ONLY the shared secret — zero per-allocation state to provision.
type turnRelay struct {
	srv *turn.Server
	pc  net.PacketConn
}

func newTURNRelay(addr, realm, sharedSecret, publicIP string, log logging.LeveledLogger) (*turnRelay, error) {
	pc, err := net.ListenPacket("udp4", addr) // relay still owns its socket
	if err != nil {
		return nil, err
	}
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: realm,
		// Recompute-and-verify; no stored per-user table. Validates the embedded
		// expiry, rejects expired creds, derives the MD5 integrity key from the
		// shared secret. THIS is the "controller mints, relay holds no state" model.
		AuthHandler: turn.LongTermTURNRESTAuthHandler(sharedSecret, log),
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP(publicIP), // advertised public IP (e.g. 10.70.70.10 in lab)
				Address:      "0.0.0.0",
			},
		}},
	})
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return &turnRelay{srv: srv, pc: pc}, nil
}

func (t *turnRelay) close() error { return t.srv.Close() }
func (t *turnRelay) allocations() int { return t.srv.AllocationCount() }
```

Wired into `relay.go` exactly where `newUDPForwarder`/`fwd.serve()`/`fwd.close()` are today
(the `fwd *udpForwarder` field becomes `turn *turnRelay`; `turn.NewServer` already runs its own
read loop on the socket, so the `go fwd.serve()` goroutine is removed — `turn.Server` manages it).

### 3.3 Controller-minted ephemeral TURN credentials + ICE signaling

**Credential minting (`internal/controller/turncreds.go`, replaces `relaypath.go`):** the controller
already holds session identity and orders the peer pair. It mints coturn-compatible REST
credentials and ships them inside the existing `WGPeer`/`DiscoMsg` push. **No persistence** — the
credentials are derived from `(shared secret, username)`, so the `RelayPathRecord` bucket and its
get-or-create are deleted.

```go
package controller

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/pion/turn/v5"
)

// turnCredsFor mints ephemeral coturn-style TURN credentials for selfID's view of
// a peer flow in a Network. The username is "<expiry-unix>:<opaque session id>";
// the opaque id preserves most of the rid model's anonymity (the relay never sees
// a durable principal — see dataplane-libs-plan.md §1.4). The relay validates with
// LongTermTURNRESTAuthHandler against the same shared secret — no stored state.
func (s *Server) turnCredsFor(ws string, vni uint32, selfID, peerID string) (url, user, pass, realm string, controlling bool, err error) {
	sid := opaqueSessionID() // rotating, per (ws,vni,pair,session); NOT a stable user id
	user, pass, err = turn.GenerateLongTermTURNRESTCredentials(s.cfg.RelaySharedSecret, sid, s.turnCredTTL())
	if err != nil {
		return
	}
	// Deterministic controller assignment reuses the existing lo/hi pair ordering.
	lo := selfID
	if peerID < lo {
		lo = peerID
	}
	return s.turnURL(), user, pass, s.cfg.RelayRealm, selfID == lo, nil
}

func opaqueSessionID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
```

`networkpush.go`'s `networkPeers` swaps its call from `relayPathFor` to `turnCredsFor` and fills the
peer's credential fields (§3.4) plus a `controlling` bool.

**ICE signaling over the control stream (reuses DiscoMsg/EndpointUpdate, NetBird's exact pattern):**
NetBird marshals `ice.Candidate` to a string via `candidate.Marshal()` and signals it; the receiver
`ice.UnmarshalCandidate()`s and `AddRemoteCandidate()`s. That maps **directly** onto Geneza's
existing `repeated string candidates` fields:

- **Local candidate → up:** `agent.OnCandidate` → `c.Marshal()` → `EndpointUpdate` over the
  control stream, tagged with `vni` + `peer_wgpub`. (One small change: today's
  `SignalSink.SendEndpointUpdate(vni, localAddrs, reflexive, natClass)` is **per-VNI**; ICE
  candidates are **per-peer-agent**, so the sink gains a `SendEndpointUpdateForPeer(vni, peerWGPub,
  candidate string)` method. `reflexive`/`natClass` go away — pion does srflx/NAT internally.)
- **Remote candidate → down:** controller forwards as `CallMeMaybe{candidates}`; the bind does
  `ice.UnmarshalCandidate(s)` then `agent.AddRemoteCandidate(c)`. This is literally what
  `OnCallMeMaybe(peerWGPub, candidates, natClass)` already receives — only the body changes from
  "stuff into ps.candidates for hand-rolled disco" to "AddRemoteCandidate."
- **ICE creds (the one genuinely new element):** ufrag/pwd must be exchanged. Add a `IceCreds`
  sub-message to `DiscoMsg` (or a field pair on `EndpointUpdate`/`CallMeMaybe`). `connect(p)` fires
  once the remote ufrag/pwd land.
- **Dial/Accept role:** `controlling` from `turnCredsFor` (lo=controlling). Exactly one side Dials,
  the other Accepts.
- **`PunchAt` → "begin/restart ICE":** it no longer sprays pings (ICE's connectivity checks ARE the
  punch). It becomes the controller's optional "re-run ICE now" trigger → `agent.Restart()` for the
  late-upgrade / roaming case.

### 3.4 Candidate (un)marshaling onto the proto

We REUSE the message shapes; the only schema change is one additive ICE-creds element and a
repurpose of the retired `RelayPath` fields. Cleanest concrete edit:

```proto
// WGPeer: keep field 5's slot, replace its TYPE/meaning. (Old RelayPath rid/secret
// fields are retired per §2.1; reserve them to avoid silent reuse.)
message WGPeer {
  reserved 4;  reserved "rendezvous_token";   // (existing)
  bytes  wg_pubkey   = 1;
  string endpoint    = 2;            // direct host:port HINT (LAN-only); may be empty
  repeated string allowed_ips = 3;
  TurnCreds turn     = 5;            // was RelayPath relay; coturn-style ephemeral TURN creds
}

message TurnCreds {                  // controller-minted, ephemeral, relay holds only the secret
  string turn_url     = 1;          // "turn:geneza-core:7404?transport=udp"
  string username     = 2;          // "<expiry-unix>:<opaque session id>"
  string password     = 3;          // base64(HMAC-SHA1(shared secret, username))
  string realm        = 4;          // "geneza"
  bool   controlling  = 5;          // controller-assigned ICE role (lo of the pair)
}

// DiscoMsg: add ICE creds alongside CallMeMaybe/EndpointUpdate (candidates already fit).
message IceCreds { string ufrag = 1; string pwd = 2; }   // new
// CallMeMaybe.candidates / EndpointUpdate.local_addrs now carry pion candidate
// strings (c.Marshal()), e.g. "2398... 1 udp 2130706431 10.70.70.21 51820 typ host".
```

`peerRelays()` in `wg_userspace.go` becomes `peerSetups()` returning `[]peerSetup` from
`WGPeer.turn`. `renderUAPI` is unchanged (still synthesizes `endpoint=gz:<hex>` per peer).

---

## 4. go.mod additions and wireguard-go coexistence

Add (versions verified resolvable on this host; `pion/transport/v4` and `pion/stun/v3` are pulled
transitively by `ice/v4` and shared with `turn`):

```
require (
    github.com/pion/ice/v4   v4.2.7
    github.com/pion/turn/v5  v5.0.10   // server + REST creds; cache has v5.0.7, latest v5.0.10
    github.com/pion/stun/v3  v3.1.5    // stun.ParseURI / stun.URI{Username,Password}
)
// transitively (let `go mod tidy` pin): github.com/pion/transport/v4, github.com/pion/logging,
// github.com/pion/randutil, github.com/pion/mdns, github.com/pion/dtls (only if turns:/DTLS).
```

Notes / decisions:
- **CGO-free: confirmed.** Grepped the ice/v4, turn/v5, stun/v3 trees for `import "C"` — **none.**
  They are pure Go (`net`, `crypto/*`, `golang.org/x/...`). This preserves Geneza's existing
  CGO-free build (same property as `wgctrl` and `wireguard-go`). The static cross-platform build is
  unaffected. **Do not** pull `pion/dtls` unless we offer `turns:` (TLS-wrapped TURN) — DTLS is
  still pure Go but is extra surface we don't need for the UDP TURN floor.
- **turn v4 vs v5:** the research validated APIs against `v4.1.4`; this host's cache has `v5.0.7`
  and latest is `v5.0.10`. The relevant API is **stable across the major bump** — verified in
  `v5.0.7` source: `turn.NewServer`, `turn.ServerConfig{Realm, AuthHandler, PacketConnConfigs}`,
  `turn.PacketConnConfig{PacketConn, RelayAddressGenerator}`, `turn.RelayAddressGeneratorStatic`,
  `turn.GenerateLongTermTURNRESTCredentials`, `turn.LongTermTURNRESTAuthHandler`,
  `turn.GenerateAuthKey` all present with the researched signatures. **Use v5** (it shares
  `pion/transport/v4` and `pion/stun/v3` with `ice/v4`, avoiding a second copy of those deps).
- **wireguard-go is untouched** — `golang.zx2c4.com/wireguard` (device/conn/tun) stays exactly as
  is; `conn.Bind` is the only integration point and `iceBind` satisfies it. `wgctrl` stays for the
  `dataplane: kernel` backend. No version conflict: pion has no dependency on wireguard-go and vice
  versa; they meet only at our `iceBind`.
- Run `go mod tidy` after adding; expect the three direct requires + ~5 transitive pion modules.

---

## 5. Multi-tenancy: how ICE creds + agents are VNI- (and workspace-) scoped

Geneza's invariant is "workspaces scope everything; Network(VNI) is the data-plane unit." The pion
design preserves this with **no cross-VNI leakage by construction**:

- **One `device.NewDevice` + one `iceBind` per VNI** (already true in `wg_userspace.go`'s
  `ifs map[name]*usDevice`). An `iceBind`'s `peers` map only ever contains the co-members of *that*
  Network, because `Configure` is fed only that `NetworkSpec`'s peers (membership is tag-gated
  server-side before the push). ICE agents therefore never see candidates from another VNI.
- **`DiscoMsg.vni` scopes every signaling message.** `SendEndpointUpdateForPeer(vni, peerWGPub, ...)`
  and `DeliverCallMeMaybe(vni, ...)` route to `bindForVNI(vni)`. A candidate gathered on VNI A can
  never be `AddRemoteCandidate`'d onto an agent on VNI B.
- **TURN credentials are minted per `(workspace, vni, peer-pair, session)`** in `turnCredsFor(ws,
  vni, selfID, peerID)` — the workspace and VNI are part of the scope that selects the peer set, and
  the opaque session id is unique per flow. Because creds are *derived from the shared secret*
  (not stored), there is no cross-tenant table to leak: the relay validates any well-formed,
  unexpired cred against the one secret, but a cred only grants a TURN *allocation* (a relay
  mailbox) — it does not grant Network membership, which remains enforced entirely by the controller's
  tag-gating before any `NetworkConfig` push. A tenant that somehow obtained another tenant's TURN
  cred could relay opaque bytes to a peer it already knows the address of, but **cannot join a
  Network, cannot decrypt (no WG key), and cannot enumerate peers** — the WG/E2E + control-plane
  membership boundary is the tenancy boundary, exactly as today.
- **Optional hardening:** scope the TURN `realm` per workspace (`realm = "geneza/" + ws`) and embed
  the workspace+vni in the opaque session id's derivation, so the relay's `AuthHandler` can reject a
  cred presented under the wrong realm. This is cheap and makes the allocation boundary match the
  tenancy boundary even at the relay. (The relay still learns nothing decryptable.)
- **Roaming/restart is VNI-local:** `agent.Restart()` re-gathers only that VNI's agent; creds
  refresh on the per-flow TTL via a fresh `turnCredsFor` push on the next reconcile.

---

## 6. Phased plan (reuses the geneza1 lab proof harness, `dataplane: userspace`)

Each phase ends with a **lab proof on geneza1** (VMs 105 geneza-core/relay, 106/107 nodes on vmbr5
`10.70.70.0/24`), driven by the existing harness pattern in `/root/labs/geneza1/scripts/` and
`deploy/reset-fleet.sh` / `reset-tenancy.sh`. Config selects pion via `dataplane: userspace`
(the field already exists in `internal/agentd/config.go`). Keep `dataplane: kernel` working
throughout (the alternate backend), so we can A/B.

### P-libs1 — TURN floor (pion/turn relay + ICE with **only** relay candidates) → overlay ping

**Goal:** prove the standards-based blind floor end to end before touching direct-path discovery.

File-level changes:
- `internal/relay/turnserver.go` (new) — embedded `pion/turn` server (§3.2); wire into `relay.go`
  in place of `newUDPForwarder`/`serve`/`close`. Add `RelaySharedSecret`, `RelayRealm` to relay
  config; keep the data listen addr/port.
- `internal/controller/turncreds.go` (new) — `turnCredsFor` (§3.3); delete `relaypath.go` and the
  `RelayPathRecord` store bucket. `networkpush.go` calls `turnCredsFor`.
- proto: add `TurnCreds` + `IceCreds`, repurpose `WGPeer` field 5 (§3.4); regenerate.
- `internal/vpn/icebind.go` (new) — `iceBind` (§3.1) but configured with
  `CandidateTypes: []ice.CandidateType{ice.CandidateTypeRelay}` only (force the floor).
- `internal/agentd/wg_userspace.go` — swap `NewMagicBind`→`NewICEBind`, `peerRelays`→`peerSetups`,
  wire `SendEndpointUpdateForPeer`/`SendICECreds`/`OnICECreds`.
- `internal/agentd/worker.go` — actually plumb `DiscoMsg` send AND receive (today only
  `NetworkEndpoints` is plumbed): forward `EndpointUpdate`/`IceCreds` up; route `CallMeMaybe`/
  `IceCreds`/`PunchAt` down via `discoBackend`. The controller relays per-peer candidates+creds
  between the two members (it already brokers the pair).
- **DELETE** `internal/vpn/bind.go` + `bind_test.go`, `internal/relay/udpforward.go` +
  `udpforward_test.go`.

**Lab proof (`scripts/dataplane-libs-proof.sh`, modeled on `dns-proof.sh`):**
1. `reset-fleet.sh` with `dataplane: userspace`; node1/node2 enroll into the default Network.
2. Assert `gnzw1` up on both with `100.64.0.2/24` and `100.64.0.3/24`.
3. From node1: `ping -c3 100.64.0.3` succeeds (overlay through the TURN relay).
4. On the relay: `turnRelay.allocations() > 0` (exported via the existing relay metrics/health
   endpoint) — proves it's a TURN allocation, not the old rid path.
5. Negative: stop the relay → ping fails (floor is the only path in P-libs1) → restart → recovers.
6. Blindness assertion: the relay logs/metrics show an allocation under an **opaque** username
   (`<expiry>:<random>`), never a WG pubkey; payload bytes are never logged.

### P-libs2 — STUN + host candidates → ICE **auto-upgrades** to direct (no hand-written SM)

**Goal:** prove the relay→direct upgrade is done by ICE's pair selection, not by us.

File-level changes:
- `internal/vpn/icebind.go` — set `CandidateTypes` to `{Host, ServerReflexive, Relay}` (all three
  in one agent). No new state machine. Add the `OnSelectedCandidatePairChange` log (already in the
  sketch) so the proof can read which pair won.
- (No relay change — the same embedded TURN server also answers STUN Binding requests for srflx;
  pion's agent uses the STUN URI we pass.)

**Lab proof:**
1. node1↔node2 on the **same bridge** (vmbr5, directly reachable). `reset-fleet.sh` userspace.
2. Overlay `ping -c3 100.64.0.3` succeeds.
3. Assert the selected pair is **`host`/`host`** (or `srflx`) on both ends — read from the
   `ice pair selected` log line / a new bind-exported gauge. This proves ICE chose **direct**
   without any Geneza state machine.
4. iptables-DROP direct UDP between the two node IPs on the hypervisor → within
   `DisconnectedTimeout`+restart the path falls back to **relay** (selected pair becomes `relay`),
   ping still works. Remove the DROP, trigger `PunchAt` (re-run ICE) → upgrades back to `host`.
   Proves both directions of the transition are pion-driven.
5. `wg show gnzw1` (install `wireguard-tools`) shows a single stable peer entry across the
   upgrade — **no WG re-handshake** on the path switch (the `genezaEndpoint`/`*ice.Conn` stayed
   constant).

### P-libs3 — NAT'd laptop (new bridge vmbr6) → ICE traverses real NAT

**Goal:** prove real NAT traversal (srflx hole-punch with relay fallback) for an off-subnet client,
the scenario the hand-rolled path could never fully prove.

Lab topology addition (one-time, mirrors the host bridge conventions in `/root/CLAUDE.md`):
- Add bridge **vmbr6 `10.70.71.0/24`** on the hypervisor with **MASQUERADE NAT to eno1** and (to
  exercise srflx) a separate NAT hop so the client's reflexive ip:port differs from its host ip:port
  — i.e. the client is genuinely behind NAT relative to vmbr5. Persist in
  `/etc/network/interfaces.d/vmbr`. A VPN-client VM (108 `geneza-laptop`, `10.70.71.30`) enrolls as
  a VPN client (not a node) into the default Network. Inter-bridge routing already ACCEPTs FORWARD,
  so 108 reaches the relay on vmbr5; the NAT makes its srflx candidate non-trivial.

File-level changes: none beyond P-libs2 — this is a topology/proof phase that exercises the same
`iceBind`. (If symmetric-NAT is simulated and srflx fails, ICE selects the relay floor — that's the
correct, automatic behavior.)

**Lab proof:**
1. From laptop (108): overlay `ping -c3 100.64.0.2` (node1) succeeds.
2. Assert selected pair is `srflx`/`host` or `srflx`/`srflx` (direct hole-punch through the cone
   NAT) — read the pair gauge. Proves real NAT traversal via pion STUN, not LAN-only.
3. Flip the lab NAT to symmetric (or DROP direct UDP) → selected pair degrades to `relay`, ping
   still works → proves the TURN floor catches the hard-NAT case automatically.
4. Re-run `e2e.sh` (the 35-check battery) with `dataplane: userspace` to confirm SSH-inside-tunnel,
   session persistence, self-update, etc. all still pass over the pion data plane.

---

## 7. Honest accounting of remaining glue (what pion does NOT do for us)

- **Per-peer agent lifecycle** is ours: create/configure/gather/dial-accept/close wired into
  reconcile (~120–180 lines in `icebind.go`). pion gives the agent; the map, the role assignment,
  and the teardown are glue. (Note NetBird wraps `agent.Close()` with a ~3s timeout to dodge a pion
  nil-deref on sleep/wake — adopt that guard.)
- **Signaling adapters** onto `DiscoMsg`/`EndpointUpdate` (~40 lines) + the new `IceCreds` proto
  element + actually plumbing DiscoMsg send/recv in `worker.go` (which is currently a stub for
  everything but `NetworkEndpoints`). This is real work, but it is the work we'd owe anyway.
- **The bind itself** shrinks dramatically: `map[wgPub]*peerICE`, `Send`→`conn.Write`, per-peer
  reader→`recvCh`→`ReceiveFunc`, `Open/Close/ParseEndpoint` (~150–200 lines vs today's 824).
- **Net LOC across bind+relay+controller is a wash to a modest reduction** (≈824+~210 in
  bind.go+udpforward.go+relaypath.go → ≈550–700 across icebind.go + turnserver.go + turncreds.go +
  the worker plumbing). **The win is correctness and standardness, not line count:** we delete the
  hand-rolled STUN parser, NAT classifier, hole-punch timer, disco protocol, and rid table — the
  exact code where traversal bugs hide — and replace them with RFC-8445 ICE + RFC-5766 TURN.
- **We own NAT-traversal *operational* correctness** still (which STUN/TURN servers, timing knobs,
  symmetric-NAT behavior) — but the *protocol* correctness is pion's, hardened across browsers.
- **No single shared socket in v1** (each agent owns its sockets) — fine for the lab and small
  fleets. Port-sharing (one UDP port for all peers in a VNI) is a later optimization via
  `AgentConfig.UDPMux`/`UDPMuxSrflx` (NetBird's pattern); §8.

---

## 8. Deferred / follow-ups (explicitly out of scope for P-libs1–3)

- **`WithUDPMux` single-port sharing** per VNI (so N peers share one UDP port, closer to a true
  magicsock). Add once the per-peer-socket model is proven; it's a configuration change to the
  agents plus a shared mux owned by the `iceBind`.
- **`turns:` (TLS) TURN** for DPI/UDP-blocked networks — pulls `pion/dtls`/TLS listeners
  (`turn.ListenerConfig`). Geneza's "agents dial out, no inbound" already fits TURN-over-TCP/TLS;
  add when a UDP-blocked customer network appears.
- **macOS-utun / Windows-wintun** userspace devices for VPN clients — orthogonal to pion (the
  `conn.Bind` is platform-independent); tracked as the existing macOS follow-up.
- **OpenStack-metadata boot-time enrollment** seam is unaffected (it provisions identity, not the
  data path).

---

## 9. Fallback if absolute relay anonymity is later made a hard requirement

If the §1.4 trade (relay learns an opaque, expiring per-session principal) is ever ruled
unacceptable, the documented escape is **not** to revive `udpforward.go`, but to keep pion ICE for
the direct path and supply the relay floor as a **custom pion candidate over a thin rid `net.Conn`**
(the cunicu "custom `net.{Dial,Listen}` to attach a filter" pattern). That re-adds ~100 lines of rid
framing but keeps RFC-8445 ICE for everything else — i.e. we still delete the STUN/disco/hole-punch
~290 lines and keep only the anonymity-critical mailbox. This is the NetBird architecture (ICE-P2P
path + a custom relay path) with Geneza's blind rid relay swapped in for NetBird's Relay service.
We default to standard TURN (§1.4 is acceptable) and hold this in reserve.

---

## Source grounding (verified on this host)

- `internal/vpn/bind.go` (824 lines, the magicsock-lite to delete), `internal/relay/udpforward.go`,
  `internal/controller/relaypath.go`, `internal/agentd/wg_userspace.go` (the shell to keep),
  `internal/agentd/network.go` (`wgBackend` seam), `api/proto/geneza/v1/control.proto`
  (`DiscoMsg`/`EndpointUpdate`/`WGPeer`/`RelayPath`).
- pion modules in the Go cache, APIs confirmed: `github.com/pion/ice/v4@v4.2.7`
  (`NewAgent`, `AgentConfig{Urls,NetworkTypes,CandidateTypes}`, `OnCandidate`,
  `GetLocalUserCredentials`, `GatherCandidates`, `Dial`/`Accept`→`*ice.Conn` (net.Conn,
  datagram-framed via `packetio.Buffer`), `Candidate.Marshal`/`UnmarshalCandidate`,
  `AddRemoteCandidate`, `OnSelectedCandidatePairChange`, `Restart`);
  `github.com/pion/turn/v5@v5.0.7` (`NewServer`, `ServerConfig`, `PacketConnConfig`,
  `RelayAddressGeneratorStatic`, `GenerateLongTermTURNRESTCredentials`,
  `LongTermTURNRESTAuthHandler`, `GenerateAuthKey`; `allocation.go` forwards
  `proto.ChannelData{Data: buffer[:n]}` verbatim → payload-blind);
  `github.com/pion/stun/v3@v3.1.4` (`ParseURI`, `URI{Username,Password}`). All three trees grepped
  CGO-free.
- Latest resolvable versions: ice v4.2.7, turn v5.0.10, stun v3.1.5, transport v4.0.2.
