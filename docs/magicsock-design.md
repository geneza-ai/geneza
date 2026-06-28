# Geneza magicsock-lite: userspace-WireGuard data plane + blind DERP-lite relay + controller-coordinated NAT traversal

Status: design (task #37), critique-reviewed; **P0+P1 implemented and VM-proven**. Supersedes
the kernel-WG-only spine shipped in task #36 (`docs/wg-dataplane-plan.md`). This document is the
authoritative reference for the Tailscale-style userspace data plane and drives the
implementation.

> **P1 PROVEN (lab geneza1, 2026-06-13):** both nodes on `dataplane: userspace` bring up a
> wireguard-go device (`gnzw1`, a TUN, `link/none`) behind a magicsock-lite `conn.Bind`, and the
> overlay ping `100.64.0.2 ↔ 100.64.0.3` flows **through the blind relay floor** — 0% loss,
> ~1.09 ms (vs 0.45 ms direct: the relay hop). `tcpdump` on the relay `:7404` shows the
> forward pattern (node→relay→peer) with opaque `0x91`-framed datagrams (no plaintext). Kill the
> relay → ping stops (the path *is* the relay, no direct path in P1); restart → nodes re-REG
> within the 15 s keepalive and ping recovers (0.92 ms). Next: P2 (STUN-via-relay + direct
> upgrade), P3 (hole-punch), P4 (NAT'd-laptop on `vmbr6`), P5 (VPN client `WatchNetworks`).

> **Critique fixes (apply during implementation — verdict: core sound + buildable):**
> 1. **(P1 blocker) Synthesize the peer endpoint unconditionally.** `toPeerConfigs` only sets
>    `pc.Endpoint` when `WGPeer.endpoint != ""`; wireguard-go `SendBuffers` returns "no known
>    endpoint for peer" (and never sends the handshake) when the endpoint is nil. So the UAPI
>    renderer MUST emit `endpoint=gz:<hex(peerPub)>` + `persistent_keepalive_interval=25` for
>    **every** peer, derived from the pubkey, independent of `toPeerConfigs`. §7.1's "reused
>    verbatim" is wrong for the userspace path — reuse only the allowed-ips conversion.
> 2. **(P5 blocker) `WatchNetworks` must be bidi** (`rpc WatchNetworks(stream UserMsg) returns
>    (stream ControllerUserMsg)`), not server-streaming — a server-stream has no client→server leg
>    to carry `EndpointUpdate`/disco. §5.3/§8-P5/§9 corrected accordingly.
> 3. **REG-before-DATA race (P1).** The bind must `REG{relaySelf}` the instant a peer is
>    configured (before WG sends `DATA{peerRid}`) and re-REG on the keepalive tick; a peer's
>    DATA is dropped until the *other* side has REG'd. WG's ~5s rekey retransmit self-heals, so
>    "connectivity is instant" → "instant once both sides have REG'd (≤ one rekey interval)".
> 4. **`Send`/`recv` slices are 128-wide, not 1.** `device.BatchSize()=max(bind=1, tun=128)`;
>    `Send` is handed up to 128 bufs (loop over all — never `bufs[0]`), `recv` is handed
>    128-wide `packets/sizes/eps` (fill index 0, return 1). `BatchSize()==1` does NOT bound them.
> 5. **No UDP-blocked fallback (scope honesty).** Floor + direct are both UDP. UDP-blocked/DPI
>    networks need a future TCP/443 DERP-lite floor (natural home: the existing TCP splice).
>    Until then, scope the "any NAT" claim to "UDP-permitting NATs".
> 6. **Control-stream reflexive candidate is LAN-only** — mark it low-priority; under NAT rely on
>    STUN-lite (the TCP source IP/port ≠ the magicsock UDP reflexive mapping).
> 7. **MTU:** keep overlay 1420 on the lab (v4/1500 underlay: 1420+60+8-rid=1488 fits); the
>    8-byte relay header breaks a v6 underlay — drop to ~1340 there. Reconcile vs the repo's
>    legacy `vpn.MTU=1280`.
> Hardening (later phases): rid leak ⇒ targeted floor-DoS (validate the HMAC tail at the
> receiving endpoint + rotate rids); pad STUNREQ ≥ STUNRESP; symmetric-NAT classification needs
> two relay vantage IPs (or drop the pre-punch skip); add IPv6/dual-stack candidates. e2e harness
> is `/root/labs/geneza1/scripts/e2e.sh` (not `/root/geneza/scripts/`).

This document is grounded against the real tree:

- wireguard-go vendored at `golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173`
  (`go.mod:132`, currently `// indirect` — promote to direct). Module on `go 1.26.4`.
- The agent backend seam `wgBackend` (`internal/agentd/network.go:43`) and its sole
  implementation `realWGBackend` (`network.go:51-60`), wired at `newNetworkManager`
  (`network.go:80`).
- The kernel-WG reconciler `reconcile`/`upOrSyncLocked`/`downLocked`/`toPeerConfigs`
  (`network.go:88-228`) and the endpoint report path `reportEndpointsLocked`
  (`network.go:120-135`).
- The blind TCP rendezvous relay `internal/relay/relay.go` (`New:51`, `tls.Listen:76`,
  `handleConn:219`, `pending:250/300`, `splice:328`, `copyHalf:381`, the blindness
  invariant comment at `relay.go:327`, `Shutdown:168`, `r.wg` WaitGroup).
- The proto `api/proto/geneza/v1/control.proto`: `AgentMsg.oneof` (free tag **7**;
  used 1-6 at `:64-71`), `ControllerMsg.oneof` (free tag **7**; used 1-6 at `:88-95`),
  `NetworkConfig`/`NetworkSpec`/`WGPeer` (`:104-121`), `WGPeer.rendezvous_token=4`
  (`:120`), `NetworkEndpoints`/`NetworkEndpoint` (`:79-85`), `EnrollRequest.wg_static_pub=9`
  (`:34`), `UserAPI` service (`:234`).

---

## 1. Architecture overview

Today's data plane is **kernel-WireGuard**: `network.go` drives `wgctrl`/`ip link …
type wireguard` to create one `gnzw<vni>` link per Network, and the kernel owns one UDP
socket per link and sends straight to `peer.Endpoint`. The kernel cannot do per-packet
path selection: you cannot interpose a "send this packet via a relay routing-id, that one
direct" decision, and you cannot observe which path a datagram arrived on. That makes
runtime relay→direct upgrade and relay fallback impossible.

magicsock-lite moves the data plane to **userspace wireguard-go** with a custom
`conn.Bind`. WireGuard still does all crypto + cryptokey routing; a Tailscale-style
"magicsock" owns endpoint selection, NAT traversal, and relay fallback under the `conn.Bind`
seam. The control plane (membership, IPAM, push, endpoint discovery) is **reused verbatim**
because it was already built to treat the data plane as opaque (`NetworkConfig` is transport-
neutral; `wgBackend` is the only seam that touches transport).

Five components:

1. **Userspace WG device** (`golang.zx2c4.com/wireguard/device.Device`), one per VNI,
   over a Linux TUN (`tun.CreateTUN`). Replaces the kernel `gnzw<vni>` link.
2. **magicsock-lite `conn.Bind`** (`genezaBind`), one per VNI, owning exactly **one** real
   UDP socket multiplexing all peers. This is the seam where relay-vs-direct path selection,
   disco, STUN-lite, and keepalives live.
3. **Blind DERP-lite relay**: a new UDP forwarder co-resident in the existing
   `internal/relay` process, on a separate UDP port (`7404`), keyed by **controller-minted
   opaque routing ids** (not WG pubkeys). Forwards opaque WG ciphertext byte-for-byte. The
   existing TCP rendezvous splice (Noise/SSH sessions) is untouched.
4. **Controller control/signaling**: the existing mTLS dial-out streams (`NodeControl.Stream`,
   and the planned `UserAPI.WatchNetworks`) carry the new disco/candidate exchange and
   hole-punch timing. The controller mints/rotates routing ids and is the rendezvous clock.
5. **Reused control plane**: membership/tag-gating, IPAM/`BindingRecord`, `NetworkConfig`
   push, monotonic reconcile, and the endpoint-report loop — all unchanged.

```
                       CONTROLLER (trusted; mTLS; DIAL-OUT only)
                       - membership / IPAM / NetworkConfig push  (KEEP, unchanged)
                       - mints+rotates opaque relay routing ids per (VNI,pair)  (ADD)
                       - disco router: aggregates candidates, picks punch t0   (ADD)
        control plane (TLS, dial-out, always reachable, INDEPENDENT of overlay)
        ┌──────────────────────┴───────────────────────────────────┐
        │ NodeControl.Stream (nodes)      UserAPI.WatchNetworks (clients) │
        │   ControllerMsg.disco = 7  : CallMeMaybe / PunchAt                 │
        │   AgentMsg.disco    = 7  : EndpointUpdate (candidates + NAT cls) │
        ▼                                                                ▼
 ┌───────────────────────────┐                        ┌───────────────────────────┐
 │ NODE / LAPTOP  (per VNI)  │                        │ NODE  (per VNI)           │
 │ device.Device (wgr-go)    │  WG crypto + ckrouting │ device.Device (wgr-go)    │
 │   │ conn.Bind.Send/Recv   │                        │   │ conn.Bind.Send/Recv   │
 │ genezaBind  ── 1 UDP sock │                        │ genezaBind  ── 1 UDP sock │
 │  path SM: relay→probe→    │                        │  path SM: relay→probe→    │
 │           direct→fallback │                        │           direct→fallback │
 └───────┬───────────────────┘                        └───────────────┬───────────┘
         │   (floor) DATA{rid}+ciphertext                              │
         │   STUNREQ/STUNRESP   ┌──────────────────────────────┐       │
         └─────────────────────►│ BLIND DERP-lite RELAY  :7404 │◄──────┘
            disco PING/PONG       │ table: rid -> {addr,lastSeen}│
            direct UDP (upgrade)  │ copy() only — never parse()  │
         ◄════════════ DIRECT WG (relay drops out) ═══════════►
              ┌──────────────────┘ TCP :443 rendezvous splice (UNTOUCHED)
              │ Noise/SSH sessions — relay.go handleConn/splice/copyHalf
```

Two invariants anchor the whole design:

- **The relay is payload-blind and identity-blind.** It sees only `{8-byte header with an
  opaque rid, opaque bytes}`. WG payload is AEAD-sealed end to end; rids are controller-minted
  random tokens with no relation to WG pubkeys, names, or VNIs.
- **Signaling never depends on the overlay.** Disco/candidate exchange rides the already-
  authenticated mTLS control streams that exist before any overlay does, so peers can
  discover and punch before a data path exists, and a relay outage cannot break signaling.

---

## 2. Component specs grounded in the real wireguard-go API

All signatures below are from `golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173`.

### 2.1 The `conn.Bind` interface we implement (`conn/conn.go:34-58`)

```go
type Bind interface {
    Open(port uint16) (fns []ReceiveFunc, actualPort uint16, err error) // conn.go:38
    Close() error                                                        // conn.go:42
    SetMark(mark uint32) error                                           // conn.go:46
    Send(bufs [][]byte, ep Endpoint) error                              // conn.go:50
    ParseEndpoint(s string) (Endpoint, error)                          // conn.go:53
    BatchSize() int                                                     // conn.go:57
}
type ReceiveFunc func(packets [][]byte, sizes []int, eps []Endpoint) (n int, err error) // conn.go:28
```

Contract semantics we must honor (verified against the device driver):

- `Open(port)` returns a **slice** of `ReceiveFunc`; the device spawns one
  `RoutineReceiveIncoming` goroutine per fn (`device/device.go:519-525`). We return **exactly
  one** fn (single multiplexed UDP socket) — fully supported (a custom single-relay bind is
  the documented case). `actualPort` is the bound UDP port (what `ListenPort` reports up).
- After `Close()`, the fn(s) **must** return `net.ErrClosed` so the receive goroutines exit
  (`conn/conn.go:41`). A `*net.UDPConn` whose `Close()` was called returns exactly that, so
  the read-loop body propagates the read error directly.
- `Send(bufs, ep)`: `len(bufs) <= BatchSize()`. Called from `Peer.SendBuffers` →
  `peer.device.net.bind.Send(buffers, endpoint)` (`device/peer.go:136`). The `ep` is the
  opaque `conn.Endpoint` the peer currently carries; **we** decide its destination address.
- `ParseEndpoint(s)` turns the UAPI `endpoint=` string into our `Endpoint` type. It does
  **not** have to be `ip:port` (the default `StdNetBind` parses `netip.ParseAddrPort`,
  `conn/bind_std.go:90-98`, but we override it).
- `BatchSize()`: return `1` (non-batched). `conn.IdealBatchSize = 128` (`conn/conn.go:19`) is
  the recvmmsg/sendmmsg fast path; we start non-batched for correctness and may raise later.
- `SetMark`: no-op (we do not need SO_MARK on a userspace relay bind).
- Sentinels we use: `conn.ErrBindAlreadyOpen`, `conn.ErrWrongEndpointType`
  (`conn/conn.go:88-89`).

### 2.2 The endpoint model (`conn.Endpoint`, `conn/conn.go:78-85`)

```go
type Endpoint interface {
    ClearSrc()           // clears the source address (roam/rebind)
    SrcToString() string
    DstToString() string // serialized back by IpcGet as endpoint=  (device/uapi.go:109)
    DstToBytes() []byte   // feeds mac2 cookie computation — must be a STABLE byte encoding
    DstIP() netip.Addr
    SrcIP() netip.Addr
}
```

The device is address-agnostic: it carries one opaque `conn.Endpoint` per peer and hands it
straight to `Bind.Send`. The bind type-asserts to its own concrete type (mismatch is what
`ErrWrongEndpointType` guards) and turns it into a destination. **This is the key lever**:
our endpoint encodes the *peer identity*, not an address, so the underlying path can float
underneath a stable endpoint object — wireguard-go never re-handshakes on a path switch.

```go
// internal/vpn/bind.go
// genezaEndpoint identifies a PEER (by WG pubkey), not an address. The live path
// (direct addr vs relay rid) is looked up in genezaBind.peers[wgPub] per Send.
type genezaEndpoint struct {
    wgPub [32]byte // stable peer identity, == WGPeer.wg_pubkey
}

func (e *genezaEndpoint) ClearSrc()           {}                       // no sticky src; no-op
func (e *genezaEndpoint) SrcToString() string { return "" }
func (e *genezaEndpoint) DstToString() string { return "gz:" + hex.EncodeToString(e.wgPub[:]) }
func (e *genezaEndpoint) DstToBytes() []byte  { b := make([]byte, 32); copy(b, e.wgPub[:]); return b } // stable, for mac2
func (e *genezaEndpoint) DstIP() netip.Addr   { return netip.Addr{} } // unknown / floats
func (e *genezaEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

var _ conn.Endpoint = (*genezaEndpoint)(nil)
```

Notes on the interface obligations:

- `DstToString()` must round-trip through `ParseEndpoint`: we emit `gz:<64hex>` and accept it
  back (so `IpcGet`→`IpcSet` is stable). It is also what shows up in UAPI dumps.
- `DstToBytes()` feeds the mac2 cookie; the 32-byte pubkey is a stable encoding (it only has
  to be deterministic per-peer, not an address).
- `DstIP().Is6()` is consulted by the stdlib bind to pick a v4/v6 socket; **our** bind owns a
  single socket and ignores it, so returning the zero `netip.Addr{}` is fine.
- `ClearSrc()` is invoked before TX on roam (`device/peer.go:130-133`); with no sticky source
  it is a no-op.

### 2.3 The bind shape

```go
// internal/vpn/bind.go
type genezaBind struct {
    mu    sync.Mutex
    uc    *net.UDPConn               // the ONE magicsock socket for this VNI
    port  uint16
    vni   uint32

    peersMu sync.RWMutex
    peers   map[[32]byte]*peerState  // by WG pubkey
    byRid   map[uint48]*peerState    // inbound DATA{rid==relaySelf} -> peer (P2+)

    disco  *discoEngine              // candidate exchange + ping/pong (P2+)
    stun   *stunClient               // STUN-lite over the relay (P2+)
    sig    signalSink                // pushes EndpointUpdate up the control stream (P2+)
    log    *device.Logger
}

var _ conn.Bind = (*genezaBind)(nil)

func newGenezaBind(vni uint32, log *device.Logger) *genezaBind { /* ... */ }
```

`Open` / `Close` / `SetMark` / `BatchSize` mirror the verified minimal bind from Research 1
(`net.ListenUDP("udp4", …)`; `Close()` makes the in-flight `ReadFromUDPAddrPort` return
`net.ErrClosed`; `SetMark` no-op; `BatchSize()==1`). The substance is in `Send`, the
`ReceiveFunc`, and `ParseEndpoint` (§4.3, §4.4).

### 2.4 Constructing the device + TUN (`device/device.go:284`, `tun/tun_linux.go:551`)

```go
import (
    "golang.zx2c4.com/wireguard/conn"
    "golang.zx2c4.com/wireguard/device"
    "golang.zx2c4.com/wireguard/tun"
)

func NewDevice(tunDevice tun.Device, bind conn.Bind, logger *Logger) *Device  // device.go:284
func CreateTUN(name string, mtu int) (Device, error)                          // tun_linux.go:551
```

- `NewDevice` snapshots `tunDevice.MTU()` at construction; on read error it falls back to
  `device.DefaultMTU = 1420` (`device/device.go:291-296`, `device/tun.go:14`). It starts all
  crypto/handshake workers + the TUN reader immediately, in `deviceStateDown`. **We must call
  `dev.Up()`** to open the bind and start peers.
- `CreateTUN("gnzw<vni>", device.DefaultMTU)` opens `/dev/net/tun`, sets
  `IFF_TUN|IFF_NO_PI|IFF_VNET_HDR` (enabling GSO/GRO; `batchSize` becomes 128 internally),
  applies MTU via `SIOCSIFMTU`, and returns a `*NativeTun`. We do **not** assign addresses or
  bring the link up in-process — we keep the existing out-of-band `ip addr add` / `ip link set
  up` / `ip route` approach (same as today's kernel path) keyed on `dev.Name()`.
- Overlay MTU: 1420 is correct for a 1500 underlay (WG overhead 60 for v4/UDP, 80 for v6).
  The relay header adds 8 bytes on the floor; see §3.7 for the relay-path MTU note.

Lifecycle methods used: `dev.Up()` / `dev.Down()` (`device/device.go:209-215`), `dev.Close()`
(`:370`), `dev.Wait() <-chan struct{}` (`:402`). Logger: `device.NewLogger(level, prepend)`
(`device/logger.go:36`) or a hand-built `&device.Logger{Verbosef, Errorf}` wired to geneza's
`slog` (`device/logger.go:18`, levels `:25-27`).

### 2.5 Configuring peers + roaming their endpoints via UAPI / `IpcSet`

`IpcSet(s string) error` (`device/uapi.go:404`) parses line-by-line `key=value`; a blank line
terminates. Lines before the first `public_key` are device-level; lines after apply to that
peer. We **render a UAPI string from `[]wgtypes.PeerConfig`** (the existing `toPeerConfigs`
output, `network.go:191`), so the conversion logic is reused — only the sink changes from
`wgctrl.ConfigureDevice` to `dev.IpcSet`.

Device-level keys (`device/uapi.go:197-248`): `private_key=<64hex>`,
`listen_port=<uint16>` (triggers `BindUpdate` → re-`Open`), `fwmark=<uint32>`,
`replace_peers=true`.

Peer keys (`device/uapi.go:304-394`): `public_key=<64hex>`, `update_only=true`, `remove=true`,
`preshared_key=<64hex>`, `endpoint=<string>` (passed verbatim to **our** `ParseEndpoint`),
`persistent_keepalive_interval=<secs>`, `replace_allowed_ips=true`, `allowed_ip=<CIDR>`.

Full-sync config string (maps `ReplacePeers:true` → `replace_peers=true`; one peer shown). The
`endpoint=` value is our `gz:<64hex>` peer-identity token, which `ParseEndpoint` turns into a
`genezaEndpoint` (the bind then resolves the live path):

```
private_key=<64hex of m.wgPriv>
listen_port=0
replace_peers=true
public_key=<64hex peer wg pubkey>
endpoint=gz:<64hex peer wg pubkey>
persistent_keepalive_interval=25
replace_allowed_ips=true
allowed_ip=100.64.0.3/32
```

`listen_port=0` means "ephemeral" — but the **bind** picks the port in `Open(0)` and returns
it as `actualPort`; `ListenPort` returns that to the report loop. (Today `Configure(name,
priv, 0, peers)` at `network.go:159` lets the *kernel* pick; the seam is identical, only the
owner of the socket changes.)

**Runtime endpoint roam (relay→direct), no teardown** — used only if we ever expose the path
to the device (we generally do **not**, because our endpoint floats internally; see §4.5). The
supported primitive is a partial `IpcSet` with `update_only=true` (`device/uapi.go:290-293,
340-348`), which re-parses `endpoint=` under the peer's endpoint lock and touches nothing else
(keypairs, allowed-ips, session, routines all preserved):

```go
dev.IpcSet("public_key=" + peerHex + "\nupdate_only=true\nendpoint=" + newEP + "\n")
```

There is **no exported `Peer.SetEndpoint`**; `Peer.SetEndpointFromPacket` (`device/peer.go:279`)
is inbound-roaming-only and gated by `disableRoaming`. The partial `IpcSet` is the only safe
external path. **Our design avoids it entirely** for the common case: because the
`genezaEndpoint` is keyed by pubkey and the path floats inside the bind, path upgrade/fallback
is invisible to the device — no `IpcSet` per switch, no possibility of a races against the
handshake. We keep the partial-`IpcSet` roam in the toolbox only as a fallback diagnostic.

---

## 3. The blind DERP-lite relay protocol

A **new UDP listener** co-resident in the existing `Relay` process, sharing `cfg`, `Shutdown`,
and the `r.wg` WaitGroup. The existing TCP rendezvous (`relay.go:76` `tls.Listen`, `handleConn:219`,
`splice:328`, `copyHalf:381`) is **edited zero bytes** — it keeps carrying Noise/SSH sessions.
New file: `internal/relay/udpforward.go`.

### 3.1 Why a separate plaintext UDP surface

- WG datagrams are already E2E AEAD-encrypted; wrapping them in TLS would add a handshake and
  per-packet overhead and would break the stateless/blind property.
- The forwarder is **connectionless**: a single read loop + a sharded map, no goroutine and no
  FD per peer. A flood costs map lookups, not sockets — it cannot exhaust FDs the way the TCP
  `maxConns` guard worries about.
- It binds a separate UDP port `defaults.RelayDataPort = 7404` (the TCP rendezvous stays on
  `cfg.Listen`). `cfg.TLS`/cert config is irrelevant here.

### 3.2 Framing (8-byte header + opaque payload)

```
byte 0      : magic/version = 0x91     — cheap discriminator + anti-amplification gate
byte 1      : type          = REG(1) | DATA(2) | KEEPALIVE(3) | STUNREQ(4) | STUNRESP(5) | CLOSE(6)
bytes 2..7  : routing id (rid) = 48-bit big-endian, opaque, controller-minted (§3.5)
bytes 8..N  : opaque payload   (DATA: WG ciphertext; others: §3.3/§3.4)
```

The header is deliberately tiny (DERP's frame header is ~5 bytes; we add the rid because we are
mailbox-keyed by rid, not by a socket-bound session). 48-bit rid = 2.8e14 space: infeasible to
guess, small enough to keep the header ≤ 8 bytes → exactly one header of MTU cost on the floor
vs. direct.

`0x91` is unambiguous against raw WG: a WireGuard message's first byte is its type 1–4, never
`0x91`. So the bind's receive loop demuxes relay/disco frames vs. direct WG by the first byte
(plus, for safety, only treating `0x91` frames *from the known relay address* as relay frames;
§4.4).

### 3.3 Registration (claim a routing id) — no relay-side auth, by design

The relay is zero-trust and holds **no** key material (no WG key, no Noise key, no
`flowSecret`). An endpoint "claims" its rid simply by being the first to send a `REG` for it
from a source address. Possession of the controller-minted rid (delivered only over mTLS to the two
legitimate endpoints) *is* the capability:

1. Controller mints `{ridA, ridB}` for an ordered peer pair `(A,B)` in a VNI plus a 16-byte
   `flowSecret`, and pushes to A "register `ridA`, send peer-B traffic to `ridB`" (mirror to B).
   Carried in `WGPeer.relay` (§6, the proto delta).
2. A sends `REG{rid=ridA, payload=HMAC(flowSecret, ridA‖srcGuess)}` (a 32-byte tail). The relay
   records `table[ridA] = {addr: observed-source-addr, lastSeen: now}`. The relay **cannot
   verify** the HMAC (no secret) — it only checks the tail is ≥16 bytes as a cheap shape gate
   against scanners (anti-amplification, §3.8). The real authentication is WG AEAD end to end.
3. Thereafter A sends `DATA{rid=ridB, payload=wgCiphertext}`. Relay looks up `table[ridB]` →
   B's recorded reflexive addr → forwards `DATA{rid=ridB, payload}` **unchanged**. We forward
   the **destination** rid so the receiver's bind can demux which flow it is (§4.4).

Central adaptation away from DERP: **the rid is minted by the controller, NOT derived from a WG
pubkey.** DERP mailboxes are keyed by node pubkey, so DERP learns every node's stable identity
and who-talks-to-whom. Here the relay learns only ephemeral per-flow rids that mean nothing
without the controller's private `rid → (VNI,pair)` map, which the relay never sees.

### 3.4 STUN-via-relay (STUN-lite — no external STUN servers)

The relay doubles as a one-packet STUN server on the same UDP port, collapsing netcheck into
the same surface (deployment stays "controller + relay", no third service):

```
STUNREQ : {0x91, STUNREQ, rid=0}  + 16-byte random txid
STUNRESP: {0x91, STUNRESP, rid=0} + 16-byte txid (echoed)
                                   + 1-byte family (4|6) + observed ip (4|16) + 2-byte port
```

- The endpoint sends `STUNREQ` **from its magicsock socket** (the same socket WG/relay-DATA
  use), so the reflexive address learned is exactly the mapping peers must target. This is the
  classic STUN pitfall: a different socket would get a different external port.
- The relay replies with the **observed source addr** of the request (never a claimed one) —
  same trust model as registration. `txid` prevents off-path spoofed responses being accepted.
- Response size ≤ request-derived size → no amplification (§3.8).

netcheck-lite: by sending repeated `STUNREQ` and watching whether the reflexive port equals the
local port / is stable across destinations, the endpoint classifies its NAT (cone vs symmetric)
and reports a `nat_class` hint up the control stream so the controller can decide whether a punch is
even worth attempting (§5.3, §5.4).

### 3.5 Opaque per-Network routing ids + scoping

rids are minted **per (VNI, ordered-pair)** by the controller, which keeps the authoritative
`rid → (VNI, pairKey)` map privately. The relay's table is flat (`rid → {addr, lastSeen}`) and
carries **no VNI tag on the wire** — the relay is tenant-blind. Isolation holds because:

- a rid is only ever handed to the two endpoints of one pair in one VNI;
- a different VNI's pair gets a fresh independent rid from the 48-bit space;
- so a node in VNI-B does not *possess* any rid for VNI-A's flows and cannot inject
  `DATA{rid_of_A}` into a cross-tenant flow. Even a guessed foreign rid (48-bit search) only
  delivers ciphertext that the target's WG drops (no matching peer key for that VNI device).

Tenant isolation is therefore **defense in depth**: rid-secrecy (probabilistic) + WG-key-per-VNI
(structural — exactly the invariant the kernel path already relies on: "no membership ⇒ no peer
key ⇒ device drops the packet"). See §5.

### 3.6 Keepalive + NAT-rebind tracking

- Floor keepalive: the bind sends `KEEPALIVE{rid=relaySelf}` to the relay every **15 s** (under
  the typical 30 s UDP NAT timeout; conservative vs. Tailscale's ~25 s). This refreshes
  `table[relaySelf].addr/lastSeen` (so peers can still reach us) and holds our endpoint→relay
  NAT mapping open.
- NAT-rebind survival: the relay records `table[rid].addr = observed source addr` on **every**
  `REG`/`DATA`/`KEEPALIVE`. So if our NAT rebinds to a new public port, the next packet we send
  silently updates the table and the peer's traffic to our rid follows — no signaling, exactly
  how DERP tracks live sockets and how the controller's existing `setObservedIP` trick works.
- Direct path keepalive: WG's own `PersistentKeepalive = 25 s` (already set, `network.go:192`)
  holds the punched mapping once upgraded.

### 3.7 Coexistence with the existing TCP rendezvous relay

One `Relay` now owns a `tls.Listener` (TCP, untouched) **and** a `*net.UDPConn` (new). The UDP
recv goroutine and the table-sweeper join the existing `r.wg` WaitGroup so the drain logic in
`Shutdown` (`relay.go:168-208`) already covers them; `Shutdown` additionally closes the
`*net.UDPConn` and stops the sweeper. `statsLoop` (`relay.go:411`) gains a UDP-table-size gauge.
`ListenAndServe` gains a parallel `go r.serveUDP()`. The TCP `Serve`/`handleConn`/`splice`/
`copyHalf` functions are **not edited**.

The blindness invariant is literally extended: the forward loop does `copy()` on the inner
payload, never `parse()` — the same property already enforced for TCP at `relay.go:327`
("from here on, not a single byte is parsed — only copied").

### 3.8 DoS / anti-amplification guards

- **Table cap** `MaxRelayEntries` (default 65536): at cap, a `REG` for an unknown rid is
  dropped (fail-closed, mirroring the TCP `pending`-full handling at `relay.go:286`).
- **Idle expiry** `RelayDataIdle` (default 60 s — tighter than the TCP idle close because UDP
  entries are cheap and NAT mappings die fast): a sweeper goroutine reaps `now-lastSeen >
  RelayDataIdle`, reusing the `statsLoop` ticker pattern.
- **Anti-amplification**:
  - `STUNRESP` is never larger than a `STUNREQ`-derived size; we require magic byte + ≥16-byte
    `txid` tail on `STUNREQ`, so a 1-byte spoofed packet gets no reply.
  - `DATA` is forwarded only to an **already-registered** rid: the relay never reflects to an
    address that has not itself sent a packet → cannot be used as a reflector toward an
    arbitrary victim. A `DATA` with an unknown rid is dropped **silently** (no error packet →
    no amplification, no oracle).
- **Per-source rate**: a token-bucket per source `/24` on the unsolicited types
  (`REG`/`STUNREQ`); `DATA` to a known rid is implicitly rate-limited by being a real flow.
- **Sharding**: the table is sharded (e.g. 256 shards by `rid % 256`) so lookups don't contend
  under load.

### 3.9 New relay config / defaults

```go
// internal/relay/config.go — additive
type Config struct {
    // ... existing fields (Listen, TLS, MatchTTL, IdleTimeout, MaxPending, ...) unchanged
    UDPListen       string // host:port for the data forwarder; default ":7404"
    RelayDataIdle   time.Duration // default 60s
    MaxRelayEntries int           // default 65536
    RelayKeepalive  time.Duration // advisory; endpoints use 15s
}
// internal/defaults — additive: RelayDataPort=7404, RelayDataIdle=60s, MaxRelayEntries=65536
```

---

## 4. magicsock-lite at the endpoint

### 4.1 Peer model

Per VNI the bind keeps a `peerState` keyed by WG pubkey (the stable identity the device already
uses). A peer can be reachable via a direct addr **and/or** a relay rid simultaneously; the
state machine decides which `Send` actually uses.

```go
// internal/vpn/bind.go
type pathState int
const ( stRelay pathState = iota; stProbing; stDirect; stFallback )

type peerState struct {
    wgPub      [32]byte

    // DIRECT candidates (from disco, §5):
    candidates []netip.AddrPort
    bestDirect netip.AddrPort     // confirmed direct path (zero = none)
    directOK   atomic.Bool        // a disco Pong arrived on bestDirect recently
    lastDirect atomic.Int64       // unix-nanos of last inbound DIRECT datagram

    // RELAY floor:
    relaySelf  uint48             // OUR rid; we REG this and recv DATA{relaySelf}
    relayPeer  uint48             // we Send DATA{relayPeer}
    relayAddr  netip.AddrPort     // relay UDP addr (from WGPeer.relay)
    flowSecret [16]byte

    state      atomic.Int32       // pathState
}
```

### 4.2 `Open` / `Close` / `BatchSize` / `SetMark`

Per the verified minimal bind (Research 1 §8): `Open(port)` does `net.ListenUDP("udp4",
&net.UDPAddr{Port:int(port)})`, records `actualPort`, returns exactly one `ReceiveFunc`;
`Close()` closes the socket (in-flight read returns `net.ErrClosed`); `BatchSize() == 1`;
`SetMark` no-op. `Open` also starts the floor keepalive ticker (§3.6) and, in P2+, the
STUN-lite probe loop.

### 4.3 `Send` — path selection per packet

```go
func (b *genezaBind) Send(bufs [][]byte, ep conn.Endpoint) error {
    ge, ok := ep.(*genezaEndpoint)
    if !ok { return conn.ErrWrongEndpointType }
    b.peersMu.RLock(); ps := b.peers[ge.wgPub]; b.peersMu.RUnlock()
    if ps == nil { return nil } // peer gone mid-flight; drop (next reconcile fixes it)

    uc := b.socket()
    if uc == nil { return net.ErrClosed }

    if pathState(ps.state.Load()) == stDirect && ps.directOK.Load() {
        for _, buf := range bufs {                              // raw WG ciphertext, NO header
            if _, err := uc.WriteToUDPAddrPort(buf, ps.bestDirect); err != nil { return err }
        }
        return nil
    }
    // relay floor: 8-byte header{0x91, DATA, relayPeer} + ciphertext
    for _, buf := range bufs {
        frame := encodeFrame(typeDATA, ps.relayPeer, buf)      // pooled buffer
        if _, err := uc.WriteToUDPAddrPort(frame, ps.relayAddr); err != nil { return err }
    }
    return nil
}
```

### 4.4 `ReceiveFunc` — demux direct vs relay/disco

```go
recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
    n, src, err := b.uc.ReadFromUDPAddrPort(packets[0]) // net.ErrClosed after Close()
    if err != nil { return 0, err }
    pkt := packets[0][:n]

    // Relay/disco frame? Only if it carries the magic AND comes from the relay addr.
    if n >= 8 && pkt[0] == 0x91 && src == b.relayAddrFor(src) {
        switch pkt[1] {
        case typeDATA:
            rid := readRid(pkt[2:8])
            ps := b.byRid[rid]            // rid == OUR relaySelf for this peer
            if ps == nil { return 0, nil } // unknown rid -> ignore, recv again
            copy(packets[0], pkt[8:]); sizes[0] = n - 8
            eps[0] = &genezaEndpoint{wgPub: ps.wgPub}
            // (relay path liveness tracked separately; does NOT set directOK)
            return 1, nil
        case typeSTUNRESP: b.stun.onResp(pkt); return 0, nil   // consumed, recv again
        // CLOSE/etc.: handle, return 0, nil
        }
        return 0, nil
    }
    // Disco PING/PONG arrive DIRECT (small 0x91 frames not from the relay) — §5.5
    if n >= 2 && pkt[0] == 0x91 && (pkt[1] == typeDiscoPing || pkt[1] == typeDiscoPong) {
        b.disco.onDirect(pkt, src); return 0, nil
    }
    // Otherwise: raw WG ciphertext arriving DIRECT. Source is a candidate.
    ps := b.disco.peerForCandidate(src) // map src addr -> peerState (learned in probing)
    if ps == nil { return 0, nil }      // unsolicited direct from unknown src -> drop
    sizes[0] = n
    eps[0] = &genezaEndpoint{wgPub: ps.wgPub}
    ps.bestDirect = src; ps.directOK.Store(true); ps.lastDirect.Store(time.Now().UnixNano())
    return 1, nil
}
```

The crucial property: an inbound **direct** WG datagram and an inbound **relay** DATA both get
handed to wireguard-go tagged with the **same** `genezaEndpoint{wgPub}`. wireguard-go's peer
endpoint never changes; only the bind's internal routing does → no re-handshake on a path
switch (the Tailscale property).

Demux unambiguity: WG message types are 1–4 in byte 0, never `0x91`. We additionally only treat
`0x91` frames *from the relay address* as relay frames, and `0x91` PING/PONG *not* from the
relay as disco. Everything else is raw direct WG.

### 4.5 `ParseEndpoint` — the UAPI hook

```go
func (b *genezaBind) ParseEndpoint(s string) (conn.Endpoint, error) {
    // accept "gz:<64hex>" (our peer-identity token) — round-trips with DstToString
    if rest, ok := strings.CutPrefix(s, "gz:"); ok {
        raw, err := hex.DecodeString(rest)
        if err != nil || len(raw) != 32 { return nil, errors.New("bad gz endpoint") }
        var k [32]byte; copy(k[:], raw)
        return &genezaEndpoint{wgPub: k}, nil
    }
    return nil, conn.ErrWrongEndpointType
}
```

Because the endpoint identifies a peer (not an address), the path floats inside the bind and we
**never** issue a per-switch `IpcSet` roam in the steady state (§2.5).

### 4.6 Path-upgrade state machine

```
   ┌─────────┐  controller: CallMeMaybe{cands}     ┌──────────┐
   │  RELAY  │ + PunchAt{t0}                    │ PROBING  │
   │ (floor) │ ───────────────────────────────►│          │
   └────┬────┘   data keeps flowing via relay   └────┬─────┘
        │ ▲                                          │ disco Pong on
        │ │ keepalive 15s (relaySelf stays warm)     │ a direct candidate
        │ │                                          ▼
        │ │                                     ┌─────────┐
        │ └─────────────────────────────────── │ DIRECT  │
        │  no direct pkt for DirectDeadTimeout  │         │
        │  (3s) -> directOK=false, back to floor└────┬────┘
        │                                            │ direct keeps working
        └────────────────────────────────────────────┘
            FALLBACK is transient: send via relay while re-probing in
            the background. The floor is ALWAYS warm -> never hard-down.
```

- **RELAY (start/floor)**: on `upOrSyncLocked` the peer comes up `state=relay`; the bind
  `REG`s `relaySelf` and data flows via the relay immediately. **Connectivity is instant** — no
  punch required first; the WG handshake completes over the relay. ("DERP is the floor, never
  below it.")
- **PROBING**: triggered when the controller delivers `CallMeMaybe{candidates}` + `PunchAt{t0}`.
  The bind sprays disco `Ping` to every candidate at `t0` (§5.6). Data keeps flowing on the
  relay throughout — zero interruption.
- **DIRECT**: a disco `Pong` returns on candidate X → `bestDirect=X`, `directOK=true`,
  `state=direct`. From the next `Send`, WG ciphertext goes straight to X with no relay header.
  The relay sees the flow go quiet and idle-expires it, but keepalive keeps `relaySelf`
  registered so fallback is instant.
- **FALLBACK**: no direct packet for `DirectDeadTimeout` (3 s) → `directOK=false`,
  `state=relay`, data immediately resumes on the warm floor, and a background re-probe starts.
  Seamless (one relay RTT). The invariant: **data never stops** — relay carries everything from
  t0, a punch is a transparent upgrade, a failed/lost punch is a no-op the user only notices in
  latency/throughput.

### 4.7 Where the bind is created / wired

The new `userspaceWGBackend.Create(name)` (§6) builds `tun.CreateTUN(name,
device.DefaultMTU)`, a fresh `genezaBind(vni)`, `dev := device.NewDevice(tun, bind, logger)`,
`dev.Up()`, and stores `{dev, bind, tun}` keyed by VNI. The bind holds a `signalSink` handle so
it can push `EndpointUpdate` up and receive `CallMeMaybe`/`PunchAt`; that handle is wired from
the worker's control-stream loop (§5).

---

## 5. Signaling over the controller control stream + hole-punch

All candidate/reflexive exchange and punch timing ride the **existing dial-out mTLS streams**,
which exist before and independently of any overlay. The actual ping/pong reachability test goes
**direct over UDP**; only coordination goes over control. This matches Tailscale's split
(coordination via control server, reachability via disco-over-UDP) but uses the controller as the
disco relay because it is already trusted and already connected to both sides.

### 5.1 Proto delta (additive; backward-compatible)

```proto
// AgentMsg.oneof — free tag 7 (1-6 used at control.proto:64-71):
DiscoMsg disco = 7;
// ControllerMsg.oneof — free tag 7 (1-6 used at control.proto:88-95):
DiscoMsg disco = 7;

message DiscoMsg {
  uint32 vni        = 1;       // which Network this concerns (VNI-scoped, always)
  bytes  peer_wgpub = 2;       // the OTHER endpoint (controller fills this on relay)
  oneof body {
    CallMeMaybe    call_me_maybe = 3;  // gw->ep: peer's candidate set + NAT class
    PunchAt        punch_at      = 4;  // gw->both: coordinated simultaneous-open time
    EndpointUpdate endpoints     = 5;  // ep->gw: this peer's candidates + self NAT class
  }
}

message CallMeMaybe {                 // controller -> endpoint
  repeated string candidates = 1;     // ["192.168.1.5:41641","203.0.113.7:55000"] local+reflexive
  uint32 nat_class = 2;               // peer's classified NAT (0=unknown,1=cone,2=symmetric)
}
message PunchAt {                     // controller -> both endpoints
  int64  t0_unix_ms = 1;             // coordinated spray start (controller clock + lead)
  uint32 attempt    = 2;             // retry/backoff accounting
}
message EndpointUpdate {              // endpoint -> controller (rides AgentMsg.disco / WatchN up-channel)
  uint32 vni        = 1;
  repeated string local_addrs = 2;   // host candidates (LAN ifaces)
  string  reflexive = 3;             // STUN-lite result for THIS VNI's socket
  uint32  nat_class = 4;             // self-classification (§3.4 netcheck-lite)
}
```

`EndpointUpdate` **subsumes and extends** the existing `NetworkEndpoints`/`NetworkEndpoint`
(`control.proto:79-85`, today just `{vni, listen_port}`). We keep the controller's existing
"observed-source-IP + reported-port → direct candidate" derivation (`endpointFor`/`NodeEndpoint`
in `registry.go`) as the zero-extra-packet "server-reflexive guess from the control stream"
candidate — which already works on a shared LAN like the lab bridge — and **add** the STUN-lite
reflexive + LAN locals as richer candidates. The controller aggregates all of a peer's candidates
and ships them to co-members via `CallMeMaybe`.

`DiscoMsg` carries `vni` on every message, so candidate exchange and punch coordination never
cross Networks — a candidate learned for VNI-A is never offered to a VNI-B peer.

### 5.2 Carrying relay coordinates on `WGPeer` (the rid pair)

`WGPeer` today has `endpoint=2` (direct hint) + `rendezvous_token=4`. We replace the loose
token with a structured `relay` and keep `endpoint` as the optional direct-candidate hint:

```proto
message WGPeer {
  bytes  wg_pubkey   = 1;
  string endpoint    = 2;          // optional direct-candidate HINT (control-stream-observed)
  repeated string allowed_ips = 3;
  reserved 4;                       // was rendezvous_token (bytes); retired
  RelayPath relay    = 5;
}
message RelayPath {
  string  relay_addr  = 1;         // relay UDP host:port, e.g. "relay.lab:7404"
  fixed64 rid_self    = 2;         // 48-bit in low bits: WE register this
  fixed64 rid_peer    = 3;         // we send DATA{rid_peer}
  bytes   flow_secret = 4;         // 16 bytes, per-pair (HMAC shape-check tail)
}
```

The controller fills `WGPeer.relay` in `networkPeers` (`networkpush.go`) right where it already
fills the direct hint via `s.registry.NodeEndpoint(...)`. rid minting/rotation lives in a new
`internal/controller/relaypath.go` keyed off `(VNI, selfID, peerID)`, **persisted alongside
`BindingRecord`** so rids survive a controller restart (otherwise a restart silently reshuffles
every flow). On the user side the identical `WGPeer` rides `WatchNetworks` → the laptop's bind,
so client and node run the **same** magicsock-lite.

### 5.3 The streams (overlay-independent bootstrap)

- **Nodes — `NodeControl.Stream`** (`control.proto:55`, handler `nodecontrol.go:39`): persistent
  bidirectional mTLS, up the moment the agent connects, long before any device exists. The
  endpoint-discovery loop already lives here (`AgentMsg_NetworkEndpoints` →
  `setWGPort` → `repushAllNetworks`; controller→agent peer endpoints in `NetworkConfig`). The new
  `DiscoMsg` slots into the **same** `AgentMsg`/`ControllerMsg` oneofs and the **same** dispatch
  switches. The observed-source-IP capture (`setObservedIP`) already exploits this stream as a
  STUN-like vantage; magicsock's reflexive candidates augment it.
- **VPN clients — `UserAPI.WatchNetworks`** (planned; `UserAPI` at `control.proto:234`):
  `rpc WatchNetworks(WatchNetworksRequest) returns (stream NetworkConfig)` over the existing
  user-mTLS interceptor, with a paired up-channel for `EndpointUpdate`/disco. A client registry
  mirrors `Registry`/`agentHandle` (the `sendMu`+`netVersion` pattern) so clients get realtime
  pushes and report candidates identically to nodes.

Why overlay-independent: the control streams are mTLS over the controller's TLS listener
(`geneza://node/...` / `geneza://user/...` certs), reached over the underlay — never over the
overlay being established. Disco bootstraps the data plane rather than depending on it; the blind
relay only ever sees opaque rid-keyed datagrams, never the signaling.

### 5.4 Controller disco router (new)

A `discoRouter` on the controller:

1. Receives `AgentMsg.disco{EndpointUpdate}` from each endpoint; stores `candidates[principal][vni]
   = {local_addrs, reflexive, nat_class}`, merged with the existing observed-IP+port candidate.
2. On membership/candidate change for a VNI, for each co-member pair `(A,B)` it emits
   `ControllerMsg.disco{CallMeMaybe{B's candidates}}` to A and the mirror to B.
3. **Punch decision** from `nat_class`: if either side is cone (or unknown), it picks
   `t0 = now + lead` (e.g. +500 ms, enough for both `PunchAt` to arrive) and emits
   `PunchAt{t0, attempt}` to both. If **both** are symmetric, it **skips the punch** — the pair
   stays on the relay floor permanently (fully functional; graceful degradation).
4. Re-attempt with backoff on timeout (`PunchAt.attempt++`; 5 s → 30 s → 5 min, capped) since
   NAT conditions change.

### 5.5 Disco ping/pong (direct UDP, not over control)

Small `0x91` frames on the magicsock socket, peer↔peer:

```
DISCO_PING: {0x91, DISCO_PING, rid=0} + 16-byte txid + sender wgpub-hash(8B)
DISCO_PONG: {0x91, DISCO_PONG, rid=0} + 16-byte txid (echoed) + observed src addr
```

A returning Pong both **confirms** the direct path (→ `directOK`) and reports our reflexive
address as seen by that specific peer (useful for per-destination symmetric-NAT detection). The
receive loop intercepts these (§4.4) and they never reach wireguard-go.

### 5.6 Simultaneous hole-punch choreography

1. Both endpoints are on the floor and have reported `EndpointUpdate` (local + reflexive +
   nat_class).
2. Controller sends `CallMeMaybe{peer candidates}` + `PunchAt{t0}` to both.
3. At `t0` each side sprays `DISCO_PING` to **every** candidate of the peer (LAN locals first —
   instant on same L2; then reflexive). Simultaneous outbound from both opens both NATs'
   mappings toward each other.
4. First `Pong` on candidate X → promote X to `bestDirect`, `probing→direct`. The flow leaves
   the relay.

NAT-pair outcomes:

- **cone × cone / restricted / port-restricted**: punch succeeds (stable reflexive). Common case.
- **cone × symmetric**: usually succeeds — the symmetric side dials the cone side's stable
  reflexive; the cone side's mapping opens after it also sprays.
- **symmetric × symmetric**: reflexive port is unpredictable per-destination → the distributed
  candidate is stale. We **do not** attempt birthday-paradox port prediction (not worth the
  complexity for the lab/SCS target). Controller sees both symmetric, skips the punch, the pair
  stays on the floor — the graceful-degradation contract.

---

## 6. Zero-trust / blindness + multi-tenancy isolation

### 6.1 What a malicious relay can and cannot do

| Capability | Relay can? | Why |
|---|---|---|
| Read WG payload | **No** | DATA payload is WG-AEAD ciphertext sealed to peer static keys; relay only `copy()`s it. No key material at the relay. |
| Forge/inject into a flow | **No (undetectably)** | It can emit `DATA{rid}` to a registered addr, but bytes that aren't a valid WG transport message under the peers' session keys fail AEAD verify → dropped. |
| Learn node/user/tenant identity | **No** | rids are controller-minted random 48-bit tokens unrelated to pubkeys/names; the relay's table is `rid → ephemeral UDPaddr`. No pubkey, name, or VNI ever reaches it. |
| Join a cross-tenant flow | **No** | Needs a foreign rid (48-bit secret never handed to it) AND a valid WG peer key for that VNI (structurally absent). Two independent barriers. |
| Drop packets | **Yes** | It's in the path on the floor. Mitigation: a working direct path bypasses it; multiple relays can be offered; WG retransmits. |
| Delay / reorder | **Yes** | WG/transport tolerates reordering; delay shows as latency. |
| Misroute A's DATA | **Limited & self-defeating** | It can forward to a wrong registered addr, but that endpoint's WG drops it (wrong session) → effectively a drop, not a leak. It cannot deliver A's ciphertext to anyone who can decrypt it (only B has the key). |
| Traffic-analysis (timing/volume correlate two rids) | **Yes, metadata only** | A relay can infer "rid X and rid Y exchange packets" by timing. It still cannot read content or name the parties. Same residual leak DERP has; mitigated by preferring direct (relay drops out) + rid rotation on membership change. Documented, not eliminated. |

Net: a malicious relay is reduced to a **DoS / metadata-timing** adversary — it cannot read,
forge, misdeliver-to-a-decryptor, or cross tenants. Correctness rests on WG E2E AEAD + the
controller's private rid↔identity map. This is the DERP trust model, made **stronger on identity**
(DERP knows your pubkey; our relay knows nothing but a random rid).

Proof obligations (must hold in code review): (a) no key material constructed/stored in
`internal/relay/udpforward.go`; (b) DATA path is `copy()` only, never decode; (c) rid minting in
`relaypath.go` uses a CSPRNG and never derives from pubkey/name; (d) the `rid → (VNI,pair)` map
lives only in the controller and is never serialized to the relay.

### 6.2 Multi-tenancy layering

```
Workspace (tenant)
  └── Network ── VNI (24-bit; one device.Device gnzw<vni> / one genezaBind / one UDP socket)
        ├── overlay CIDR (per-Network IPAM; BindingRecord FIB)
        ├── members = principals whose labels match Network.Selector (policy.LabelsMatch)
        └── for each ordered member pair (A,B):
              ├── WG: A has B.wgPub as a peer ONLY on this VNI's device
              ├── relay rids {ridA,ridB} minted per (VNI,pair), 48-bit, controller-private map
              └── flowSecret per pair (HMAC shape-check tail)
```

- One bind / one socket / one rid-space per VNI. A node not in VNI-B has no `gnzw<vniB>` device,
  no bind, no rids, no peer keys for B — the structural isolation the kernel path already proves
  ("no key ⇒ dropped"). magicsock-lite operates *inside* a VNI's bind and changes nothing here.
- rids carry no VNI tag on the wire (relay tenant-blind) but are minted per-VNI and delivered
  only to that VNI's two endpoints. The VNI lives only in the controller's private map.
- **Membership change → rid rotation.** `repushAllNetworks` already fans out on any
  membership/label/approval change. Each `WGPeer` now carries `RelayPath`; a departed member's
  pairs get no new rids and their relay table entries idle-expire, so the floor path dies in
  lockstep with the structural WG-key removal.
- Disco is VNI-scoped (every `DiscoMsg` carries `vni`) → candidate exchange never crosses
  Networks.

---

## 7. KEEP vs REPLACE

### 7.1 KEEP (reused verbatim — the control plane was built data-plane-opaque)

- **Membership / tag-gating**: `desiredNetworks`/`networkPeers` gate purely on
  `policy.LabelsMatch(net.Selector, …Labels)`. The userspace device gets the identical desired
  set / peer set. The isolation invariant ("no membership ⇒ no peer key ⇒ device drops")
  holds identically for wireguard-go.
- **`NetworkConfig` push**: `networkConfigProto`/`pushNodeNetworks`/`repushAllNetworks`/
  `registry.SendNetworkConfig` and the `ControllerMsg_NetworkConfig` oneof — none touch transport.
  The push-on-connect (`pushNodeNetworks` in `nodecontrol.go`) stays.
- **IPAM / bindings**: `networkOverlayIP`, `ensureNodeOverlayIP`, `allocIPInCIDR`,
  `Store.PutBinding/GetBinding/ListBindings` over `BindingRecord`. The device is told its
  `overlay_cidr` and peers' `/32` allowedIPs exactly as today.
- **Monotonic reconcile**: `networkManager`, `nextNetVersion`, the `cfg.GetVersion() <
  m.version` drop-stale guard (`network.go:96`), and the reconcile loop body
  (`reconcile`/`upOrSyncLocked`/`downLocked`, `network.go:88-180`) — **line-for-line
  unchanged**. Only what they call *through `m.wg`* changes.
- **`toPeerConfigs`** (`network.go:191`): reused — the UAPI config string is rendered *from*
  `[]wgtypes.PeerConfig`, so the conversion survives. (`wgtypes.Key`/`PeerConfig` stay as a type
  vocabulary; no `wgctrl.ConfigureDevice` netlink call remains on the userspace path.)
- **Endpoint report loop**: `reportEndpointsLocked` → `report` callback →
  `AgentMsg_NetworkEndpoints` → `setWGPort` → `repushAllNetworks`, all unchanged. The port now
  comes from the bind's `ListenPort` instead of the kernel.
- **Relay TCP rendezvous**: `relay.go` `Serve`/`handleConn`/`splice`/`copyHalf` and
  `relay.Config` — untouched; still carries Noise/SSH sessions.

### 7.2 REPLACE (one interface, behind the `wgBackend` seam)

The whole migration hides behind `wgBackend` (`network.go:43`):

```go
type wgBackend interface {
    Create(name string) error
    SetAddr(name, cidr string) error
    Configure(name string, priv wgtypes.Key, listenPort int, peers []wgtypes.PeerConfig) error
    ListenPort(name string) (int, error)
    Delete(name string) error
}
```

Every caller — `upOrSyncLocked`, `downLocked`, `reportEndpointsLocked` — stays unchanged. The
only edit is the single assignment in `newNetworkManager` (`network.go:80`):
`wg: realWGBackend{}` → `wg: newUserspaceBackend(...)` (gated by a config switch so the kernel
path remains selectable).

New `userspaceWGBackend` (new file `internal/agentd/wg_userspace.go`) holds per VNI a
`{dev *device.Device, bind *genezaBind, tun tun.Device}`:

- `Create(name)` → `tun.CreateTUN(name, device.DefaultMTU)` + `newGenezaBind(vni)` +
  `device.NewDevice(tun, bind, logger)` + `dev.Up()`; store keyed by VNI. (This is also where
  the macOS-utun follow-up lands — the OS link is now a TUN, not a kernel WG type.)
- `Configure(name, priv, 0, peers)` → render the UAPI string from `priv` + `peers` (reuse
  `toPeerConfigs`; emit `replace_peers=true`, per-peer `endpoint=gz:<hex>`) and call
  `dev.IpcSet(uapiConf)`.
- `SetAddr(name, cidr)` → same out-of-band `ip addr add` / `ip link set up` as today (reuse
  `ipCmd` from `tun_linux.go`); no kernel WG involved.
- `ListenPort(name)` → the **bind's** bound UDP port (the bind owns the socket now).
- `Delete(name)` → `dev.Down(); dev.Close(); <-dev.Wait()`, drop from the map.

Retire on the userspace path: `realWGBackend` (kept behind the config switch) and
`internal/vpn/wg_linux.go`'s `wgctrl` calls. `wgctrl`/`wgtypes` survive only as a type
vocabulary.

---

## 8. Phased implementation plan

Each phase is independently green (compiles + existing tests pass), introduces stub-first seams,
and ends with a specific lab proof. Lab geneza1: bridge `vmbr5` (`10.70.70.0/24`), controller+relay
on VM 105 (geneza-core), agents on VM 106/107.

### P0 — promote the dependency + scaffold (no behavior change)

- **Changes**: promote `golang.zx2c4.com/wireguard` from `// indirect` to direct in `go.mod`.
  Add empty seams that compile: `internal/vpn/bind.go` (`genezaBind`/`genezaEndpoint` with the
  verified minimal-bind bodies from Research 1 §8, peer routing **stubbed to direct-only** so it
  is just a UDP bind), `internal/relay/udpforward.go` (unexported, not wired), proto stubs behind
  a new oneof tag but unused.
- **Green**: `go build ./...`, `go test ./...`, existing `scripts/e2e.sh` (kernel path still
  default). `internal/agentd/network_test.go` unchanged (it tests reconcile via a fake
  `wgBackend`).
- **Proof**: build + unit tests pass; `go list -m golang.zx2c4.com/wireguard` resolves
  `20231211`.

### P1 — MINIMAL FIRST SLICE: relay-only data path (proves the spine)

The single most important slice: **userspace WG device up via wireguard-go + a relay-only data
path between two nodes → overlay ping works through the blind relay.** No STUN, no direct, no
hole-punch.

- **Relay (`internal/relay/udpforward.go`)**: implement `serveUDP` — REG records
  `table[rid]={addr,lastSeen}`; DATA looks up dst rid and forwards bytes verbatim; sweeper +
  table cap; join `r.wg`; `Shutdown` closes the UDPConn. STUNREQ/STUNRESP **stubbed to drop**
  (P2). Wire `go r.serveUDP()` into `ListenAndServe`, default `UDPListen=":7404"`.
- **Bind (`internal/vpn/bind.go`)**: full relay floor — `Send` always frames `DATA{relayPeer}`
  to `relayAddr`; `recv` demuxes `0x91 DATA` (strip header, tag with `genezaEndpoint`) vs raw;
  `Open` starts the 15 s `KEEPALIVE{relaySelf}` ticker; `peerState.state` pinned to `stRelay`.
- **Agent backend (`internal/agentd/wg_userspace.go`)**: `userspaceWGBackend` per §7.2;
  `Configure` renders UAPI with `endpoint=gz:<hex>`; populate `peerState.relay*` from the new
  `WGPeer.relay` (P1 minting below). Flip `newNetworkManager` to it behind a config flag
  `dataplane: userspace`.
- **Controller (`internal/controller/relaypath.go`)**: mint a deterministic-per-(VNI,pair) rid pair +
  `flowSecret` (CSPRNG, persisted alongside `BindingRecord`); fill `WGPeer.relay` in
  `networkPeers`. **No disco yet** — `WGPeer.endpoint` left empty so nothing tries direct.
- **Proto**: add `RelayPath` + `WGPeer.relay=5`, reserve `4`; regenerate. (No `DiscoMsg` yet.)
- **Green**: `go build/test ./...`; relay tests get a UDP forward+expiry test; a bind unit test
  with two in-process binds + a fake relay socket proving a WG handshake completes over the
  floor.
- **Lab proof**: on geneza1, set both agents (VM 106/107) to `dataplane: userspace`, one Network
  with both as members, relay running on VM 105. `ip addr` shows `gnzw<vni>` (a TUN) with the
  overlay IP; `ping <peer overlay IP>` succeeds; `tcpdump` on VM 105 `:7404` shows only
  `0x91`-prefixed opaque datagrams (no plaintext); `wg`-equivalent (`dev.IpcGet`) shows a
  completed handshake with `endpoint=gz:<hex>`. Kill the relay → ping stops (proves the path is
  truly through the relay).
- **Riskiest**: TUN creation + out-of-band addressing parity with the kernel path (TUN vs WG
  link naming, MTU). Mitigation: reuse `ipCmd`/naming from `tun_linux.go`; assert `dev.MTU()==
  1420`. Stub seam: STUN/disco are absent, so this phase has zero NAT-traversal surface to debug.

### P2 — STUN-via-relay + direct-path probe + transparent upgrade (no NAT yet)

On the flat lab L2, peers already have routable addresses, so this proves the **upgrade
mechanism** without NAT.

- **Relay**: implement STUNREQ→STUNRESP (echo observed src addr; size-bounded; txid).
- **Bind**: `stunClient` (probe loop on the magicsock socket, classify `nat_class`),
  `discoEngine` (DISCO_PING/PONG over direct UDP, `peerForCandidate` map), and the path state
  machine RELAY→PROBING→DIRECT→FALLBACK with `DirectDeadTimeout=3s`. `Send` switches to
  direct when `directOK`.
- **Controller**: `discoRouter` — handle `AgentMsg.disco{EndpointUpdate}`, aggregate candidates
  (including the existing observed-IP+port one), emit `CallMeMaybe`+`PunchAt` to co-members;
  pick `t0`.
- **Proto**: add `DiscoMsg`/`CallMeMaybe`/`PunchAt`/`EndpointUpdate`; `AgentMsg.disco=7`,
  `ControllerMsg.disco=7`. Worker + nodecontrol dispatch the new oneof.
- **Green**: build/test; a bind test simulating CallMeMaybe→Ping→Pong→`stDirect`; a fallback
  test (stop direct, assert return to floor within 3 s).
- **Lab proof**: VM 106↔107 on the flat bridge. Start on the floor (`tcpdump :7404` busy), watch
  the upgrade: after `CallMeMaybe`/`PunchAt`, `tcpdump :7404` goes quiet while
  `tcpdump`/the magicsock port shows direct WG between the two overlay IPs; latency drops; ping
  uninterrupted throughout. Then `iptables -j DROP` the direct path → within 3 s `:7404` busies
  again and ping never drops (fallback). Riskiest: socket sameness for STUN (must reuse the
  magicsock socket or the reflexive port is wrong) — assert STUN source port == bind port.

### P3 — hole-punch for real NAT (between two NAT'd VMs)

- **New lab bridge**: add `vmbr6` (`10.70.71.0/24`) on the hypervisor with **SNAT/MASQUERADE
  only** (no DNAT, no inbound) to emulate a cone NAT, persisted in
  `/etc/network/interfaces.d/vmbr`. Move VM 106 behind it.
- **Changes**: usually none beyond P2 — the choreography already sprays at `t0`. Add the
  `nat_class`-driven punch decision (skip when both symmetric) and backoff re-attempt in the
  `discoRouter`; add `natClass` self-classification thresholds in `stunClient`.
- **Green**: build/test; a discoRouter unit test for the skip-when-both-symmetric and the
  backoff schedule.
- **Lab proof**: VM 106 (behind `vmbr6` SNAT) ↔ VM 107 (flat). Confirm they start on the floor,
  then punch to direct (one side cone via SNAT, one side reachable). `conntrack -L` on the
  hypervisor shows the punched UDP mapping; `tcpdump :7404` quiet post-upgrade. Force symmetric
  (rewrite source port per-dest via an nftables hack) → confirm graceful permanent-floor
  (controller logs "skip punch: both symmetric", ping still works).
- **Riskiest**: punch timing/`t0` clock skew between VMs and NAT mapping lifetime. Mitigations:
  `lead=500ms`, retry with backoff, 15 s relay keepalive holds the floor mapping; clock skew is
  tolerated because the spray retries (the punch is best-effort, the floor is the guarantee).

### P4 — the NAT'd-laptop proof (end-to-end NAT traversal demonstration)

- **Changes**: none structural — this is the **proof** that the system works for the canonical
  "laptop behind home NAT" case using the same node binary.
- **Lab proof**: a third VM (or VM 106 reused) entirely behind `vmbr6` SNAT-only, no inbound
  ports, dialing out only. It enrolls, comes up on the relay floor (instant connectivity),
  reports STUN reflexive, and upgrades to direct against VM 107. Demonstrate: (a) it never opens
  an inbound port (`ss -lun` shows only its ephemeral magicsock); (b) `ping`/`iperf3` over the
  overlay; (c) relay restart on VM 105 → if already direct, no interruption; if on the floor, a
  brief blip then recovery. This is the visible Tailscale-parity milestone.
- **Riskiest**: matching real-home-NAT behavior with SNAT-only emulation. Mitigation: SNAT-only
  (no DNAT) is exactly the "outbound-only, no port forward" property; document that true
  symmetric-NAT homes fall back to the floor (the §5.6 contract).

### P5 — the VPN-client path (`UserAPI.WatchNetworks` + the same Bind)

- **Proto/controller**: add `rpc WatchNetworks(WatchNetworksRequest) returns (stream NetworkConfig)`
  to `UserAPI`, plus a paired client→server channel for `EndpointUpdate`/disco. A client registry
  mirrors `Registry`/`agentHandle` (`sendMu`+`netVersion`). DNS-reachability projection
  (`dnsCanReach` in `dns.go`) is the membership source for clients, keeping WG membership and DNS
  consistent.
- **Client**: the `geneza` CLI's VPN mode creates a `tun.CreateTUN` + the **same** `genezaBind`
  + `device.NewDevice`, driven by `WatchNetworks` pushes through the **same** reconcile logic.
  On macOS this exercises the utun follow-up (the OS link is a TUN).
- **Green**: build/test on linux + darwin (TUN constructors differ; bind is identical). Reuse the
  node reconcile by extracting it behind the existing seam.
- **Lab proof**: operator laptop (or a VM acting as a client) runs `geneza vpn up`, joins a
  Network with VM 107, resolves a machine name via the the miekg/dns library (task #33), and
  `ssh`/`ping`s over the overlay — floor first, then direct upgrade — with the identical
  magicsock-lite as nodes.
- **Riskiest**: cross-platform TUN + client-side privilege (utun on macOS, `/dev/net/tun` on
  linux). Mitigation: the bind/device/disco code is OS-agnostic; only the TUN constructor and
  out-of-band address/route commands are platform-specific (already split today across
  `tun_linux.go`/`tun_darwin.go`/`resolver_*`).

### Cross-cutting risks + mitigations

- **wireguard-go pseudo-version drift**: a newer copy
  (`v0.0.0-20260522210424-ecfc5a8d5446`) sits in the cache but `go list -m` resolves
  `20231211`. Pin explicitly in `go.mod`; all cited line numbers are for `20231211`. CI asserts
  the resolved version.
- **rid persistence on controller restart**: if rids aren't persisted, a restart reshuffles every
  flow (both endpoints re-REG, brief floor blip). Mitigation: persist `relaypath` records next to
  `BindingRecord` (P1). Acceptance: kill+restart the controller, confirm flows recover without
  re-handshake.
- **GSO/GRO offload interaction**: `IFF_VNET_HDR` sets the TUN's internal `batchSize` to 128.
  Our bind `BatchSize()==1` is independent (it governs the UDP side, not the TUN side) and is
  the conservative correct choice; raise to `conn.IdealBatchSize` with recvmmsg only after P5 if
  throughput needs it. Risk is low because the device handles the TUN/bind batch mismatch.
- **Demux false-positives**: a raw WG datagram whose first byte is coincidentally `0x91` is
  impossible (WG type is 1–4), and we additionally gate relay-frame interpretation on
  source==relayAddr. Disco PING/PONG are `0x91` but distinguished by type byte and by *not*
  coming from the relay.
- **Stub-first seams** (so each phase compiles green before the next): the relay STUN handler is
  a drop-stub until P2; the bind's disco/stun engines are nil-checked no-ops until P2; the punch
  decision is "always relay" until P3; `WatchNetworks` is unimplemented until P5. Every phase's
  default config keeps the kernel path selectable (`dataplane: kernel|userspace`) so a regression
  is one config flip away from bisecting.

---

## 9. Implementation seam summary (where each piece lands)

- **New** `internal/relay/udpforward.go` — blind UDP forwarder + STUN-lite, separate listener
  `:7404`, sharded `map[rid]entry`, sweeper, rate-buckets; shares `cfg`/`Shutdown`/`r.wg`. New
  defaults `RelayDataPort=7404`, `RelayDataIdle=60s`, `MaxRelayEntries=65536`.
- **New** `internal/vpn/bind.go` — `genezaBind` (`conn.Bind`) + `genezaEndpoint`
  (`conn.Endpoint`) + path state machine + disco-over-UDP + STUN-lite client + netcheck-lite
  classifier.
- **New** `internal/agentd/wg_userspace.go` — `userspaceWGBackend` behind the existing
  `wgBackend` seam; `Create` spins a `device.Device` bound to a `genezaBind`; peer endpoints are
  `genezaEndpoint{wgPub}`.
- **New** `internal/controller/relaypath.go` — rid minting/rotation/persistence keyed off
  `(VNI, selfID, peerID)`, persisted alongside `BindingRecord`.
- **Change** `internal/agentd/network.go:80` — the one `wg:` assignment (config-gated). Reconcile
  (`88-180`), `toPeerConfigs` (`191`), `reportEndpointsLocked` (`120`) unchanged.
- **Change** `internal/controller/networkpush.go` — fill `WGPeer.relay` next to the direct-hint
  logic; add the controller disco router (handle `DiscoMsg` on `nodecontrol.go` switch + on
  `WatchNetworks`; aggregate `EndpointUpdate`; emit `CallMeMaybe`+`PunchAt`).
- **Proto** `control.proto` — `DiscoMsg` (`AgentMsg.disco=7`, `ControllerMsg.disco=7`; mirror in
  `WatchNetworks`), `CallMeMaybe`/`PunchAt`/`EndpointUpdate`, `RelayPath` + `WGPeer.relay=5`
  (`rendezvous_token` tag 4 reserved), `UserAPI.WatchNetworks` stream.
- **Untouched** — TCP rendezvous splice (`relay.go` Noise/SSH), `NetworkConfig` reconcile
  semantics, IPAM/`BindingRecord`, membership/isolation model, the endpoint-report loop.

The userspace migration is a **one-interface REPLACE** (`wgBackend` → `userspaceWGBackend` =
wireguard-go `Device` + magicsock-lite `conn.Bind`) plus a **purely additive UDP forwarder** on
the relay and **additive disco proto** on streams that already exist. The kernel-WG → userspace-WG
swap behind `wgBackend` is the single prerequisite that makes per-packet path selection — and
therefore everything Tailscale-like — possible.
