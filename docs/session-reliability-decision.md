<!-- Provenance: geneza-session-reliability-layer decisional workflow (3 architects + 3 red-teamers + synth). Resolves the docs/p2p-transport-spec.md F1 gap (ice.Conn is unreliable UDP; Noise+SSH need a reliable ordered stream). Drives session-p2p Phase 2. -->

# EXECUTIVE DECISION — Geneza Session Reliability over the ICE Conn (Phase 2)

## 1. THE DECISION

**Run a single pion/sctp `Association` over the Phase‑1 `ice.Conn`, open exactly ONE reliable+ordered `*sctp.Stream`, and expose it to `tunnel.Client/Server` through a `sctpConn` adapter that (a) adds `LocalAddr`/`RemoteAddr` and (b) drains each SCTP message into a byte‑stream buffer so the layer above sees true `net.Conn` byte semantics — NOT raw message boundaries.** This is the WebRTC DataChannel model minus DTLS: SCTP supplies reliability/ordering *below* an unchanged Noise IK gate, which already supplies mutual auth + AEAD, so DTLS would be redundant double‑encryption and is deliberately dropped (`pion/dtls/v3` stays an unused indirect dep). It beats **Option B (kcp‑go / quic‑go)**: quic‑go mandates a non‑nil `tls.Config` with a certificate and `NextProtos` — it cannot run anonymously, so it either *replaces* the Noise+grant gate (forbidden by F4/F7 MUST) or sits *under* an unchanged Noise and pays a second TLS handshake + second AEAD over a throwaway self‑signed cert that proves nothing; and kcp‑go drags in **five** new third‑party modules (verified `go get`: `klauspost/reedsolomon`, `klauspost/cpuid/v2`, `tjfoc/gmsm` SM4 GM‑crypto, archived `pkg/errors`) that compile in even though FEC and KCP‑crypto are disabled — pure supply‑chain surface for a security product whose CARDINAL principle is *reuse the proven pion stack, don't import a GM‑crypto library you never call*. It beats **Option C (ICE‑TCP / TURN‑TCP)** decisively: a passive ICE‑TCP candidate is a TCP *listener* = an inbound port (breaks the no‑inbound‑ports invariant), pion/turn's `Allocate` is UDP‑only so TURN‑TCP changes the audited relay, and TCP‑over‑TCP melts down when the inner SSH retransmits — while making NAT traversal strictly *worse* than UDP hole‑punching. SCTP keeps the proven UDP substrate (the same pion ICE+TURN path the L3 overlay drove at 1.29 Gbit/s), adds reliability in pure‑Go userspace where we control loss recovery, and is one new module inside an org Geneza already fully trusts.

**Honesty correction to the design inputs (verified against the live module cache + source):** pion/sctp is **NOT** in the module graph today (`go mod graph | grep sctp` is empty; the cache zip is a leftover) — so it is a genuine *new direct require*, exactly like KCP would be. The "zero‑add / closure already in go.mod" argument in the proposals is **false** and is discarded. The decision stands on merits, not a free lunch: `go get github.com/pion/sctp@v1.10.0` resolves to floor `transport/v4 v4.0.1`, and Geneza already pins `v4.0.2` (higher), so MVS keeps `v4.0.2` — *no downgrade, no DTLS pulled into the build, and `logging`+`randutil` are already indirect deps*. SCTP adds exactly one module; KCP adds five. That dep‑cleanliness, plus the no‑TLS‑conflict and the no‑inbound‑port properties, is why SCTP wins.

---

## 2. EXACT LAYERING

```
pion ICE pair selection  (direct host/srflx hole-punch  OR  TURN-UDP relay :7404 floor)
  └─ *ice.Conn  (sessionConn, net.Conn — UNRELIABLE / UNORDERED datagrams)
       └─ sctp.Association   (Client | Server over that net.Conn)
            └─ *sctp.Stream  (id 0, reliable + ordered, default — MESSAGE-oriented)
                 └─ sctpConn  (NEW adapter: byte-stream drain + LocalAddr/RemoteAddr + chained Close)   ← net.Conn
                      └─ tunnel.Client / tunnel.Server      (UNCHANGED — Noise IK + signed-grant authorize, the security boundary)
                           └─ *tunnel.Conn                  (UNCHANGED — wire-framed Noise ciphertext)
                                └─ ssh.NewClientConn / serveSSH   (UNCHANGED — exec/ssh/sftp/forward)
                                     OR  bare tunnel conn (ActionVPN — IP packet pump)
```

**Role from the ICE controlling bit** (one source of truth — the same `cfg.Controlling` that already drives ICE `Dial` vs `Accept` in `ice.go:203`):

| ICE bit | ICE op (today) | SCTP role | Stream op | Noise role | Geneza principal |
|---|---|---|---|---|---|
| `Controlling == true` | `a.Dial` | `sctp.Client(cfg)` | `OpenStream(0, …)` | initiator (`tunnel.Client`) | **client** |
| `Controlling == false` | `a.Accept` | `sctp.Server(cfg)` | `AcceptStream()` | responder (`tunnel.Server`) | **agent** |

SCTP is symmetric at the protocol level, so even if the controller ever flips the bit, client/server derive deterministically from it with no new negotiation. `sctpConn`'s `LocalAddr`/`RemoteAddr` delegate to the underlying `ice.Conn`; everything from `tunnel.Server/Client` upward is byte‑for‑byte unchanged, so the §4.7 authorize‑sequence invariant (`offer.go:182`: `VerifyGrant` → `g2.ID==grant.ID` → `remoteStatic==grant.ClientNoisePub`) is trivially preserved.

---

## 3. go.mod ADDITIONS + MINIMAL `internal/sessionconn` CODE

**go.mod** (run `go get github.com/pion/sctp@v1.10.0` then `go mod tidy`; the import promotes it from `// indirect` to a direct require):

```
require (
    github.com/pion/sctp v1.10.0   // single new module; transport/v4 stays v4.0.2 via MVS, no DTLS in the build path
)
```

**`internal/sessionconn/sctp.go`** (the entire new reliability layer — the wrap point the spec's F1/§3 missed). The non‑obvious correctness work is in `sctpConn.Read`: pion's `*sctp.Stream` is **message‑oriented** (`Read`→`ReadSCTP`→`reassemblyQueue.read`), and on a buffer smaller than the next message it returns `(n, io.ErrShortBuffer)` **retaining** the message (v1.10.0 does NOT pop on short‑buffer — verified — so it is recoverable, not lost). But relying on `wire.WriteFrame`'s accidental two‑writes‑per‑frame to keep boundaries aligned is fragile: a future `bufio` wrap or coalesced write would corrupt the stream. The adapter therefore **converts message semantics into byte semantics once, here**, by reading whole messages into a leftover buffer and serving `Read(p)` from it — so the Noise/SSH layer above gets a real byte stream regardless of how `wire` frames.

```go
package sessionconn

import (
	"io"
	"net"
	"sync"

	"github.com/pion/logging"
	"github.com/pion/sctp"
)

// reliableMTU pins SCTP's send MTU below both the direct and the TURN-framed
// floor; see the MTU section. We reuse the overlay's proven receive ceiling
// (iceReadBuf=1600 in internal/vpn) — do NOT invent a new magic number.
const reliableMTU = 1200

// sctpConn turns the MESSAGE-oriented *sctp.Stream into a true byte-stream
// net.Conn for the Noise+SSH stack. Read drains each SCTP message into `pend`
// so callers see bytes, never message boundaries — this severs the load-bearing
// (and fragile) dependency on wire.WriteFrame emitting one message per frame.
type sctpConn struct {
	*sctp.Stream
	assoc *sctp.Association
	ice   net.Conn

	rmu  sync.Mutex
	pend []byte
	rbuf []byte // reusable per-message scratch, >= MaxMessageSize
}

func (c *sctpConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.pend) == 0 {
		n, err := c.Stream.Read(c.rbuf) // exactly one SCTP message
		if n > 0 {
			c.pend = append(c.pend[:0], c.rbuf[:n]...)
		}
		if err != nil {
			if err == io.ErrShortBuffer {
				continue // message > rbuf: impossible (rbuf == MaxMessageSize), but never truncate
			}
			if len(c.pend) == 0 {
				return 0, err
			}
			break
		}
	}
	n := copy(p, c.pend)
	c.pend = c.pend[n:]
	return n, nil
}

func (c *sctpConn) LocalAddr() net.Addr  { return c.ice.LocalAddr() }
func (c *sctpConn) RemoteAddr() net.Addr { return c.ice.RemoteAddr() }

// Close tears the whole substack in order: SSN-RESET the stream (peer Read -> EOF),
// ABORT/SHUTDOWN the association, then close the ice.Conn (sessionConn.Close
// cancels the candidate loop + closes the agent). Single Close from tunnel.Conn
// chains all the way down — no new teardown wiring at the call sites.
func (c *sctpConn) Close() error {
	_ = c.Stream.Close()
	_ = c.assoc.Close()
	return c.ice.Close()
}

func sctpConfig(ic net.Conn) sctp.Config {
	return sctp.Config{
		NetConn:            ic,
		MTU:                reliableMTU,
		BlockWrite:         true,  // RED-TEAM #4: restore TCP-style backpressure for a slow sftp reader
		EnableZeroChecksum: true,  // RED-TEAM CRC: skip per-packet CRC32c (Noise AEAD covers integrity); both ends opt in
		MaxMessageSize:     64 * 1024,
		LoggerFactory:      logging.NewDefaultLoggerFactory(),
	}
}

func newStreamConn(ic net.Conn, s *sctp.Stream, a *sctp.Association) *sctpConn {
	return &sctpConn{Stream: s, assoc: a, ice: ic, rbuf: make([]byte, 64*1024)}
}

func clientStream(ic net.Conn) (net.Conn, error) {
	a, err := sctp.Client(sctpConfig(ic))
	if err != nil {
		return nil, err
	}
	s, err := a.OpenStream(0, sctp.PayloadTypeWebRTCBinary)
	if err != nil {
		_ = a.Close()
		return nil, err
	}
	return newStreamConn(ic, s, a), nil
}

func serverStream(ic net.Conn) (net.Conn, error) {
	a, err := sctp.Server(sctpConfig(ic))
	if err != nil {
		return nil, err
	}
	s, err := a.AcceptStream()
	if err != nil {
		_ = a.Close()
		return nil, err
	}
	s.SetDefaultPayloadType(sctp.PayloadTypeWebRTCBinary)
	return newStreamConn(ic, s, a), nil
}
```

**`internal/sessionconn/sctp.go` (`Dial` / `Accept`)** — thin wrappers that fuse Connect + reliability, returning the same `(net.Conn, path)` shape the call sites already expect, so the cutover is a near drop‑in:

```go
// Dial: client/controlling side. Returns a reliable net.Conn ready for tunnel.Client.
func Dial(ctx context.Context, cfg Config, sig Signaler) (net.Conn, string, error) {
	ic, path, err := Connect(ctx, cfg, sig) // cfg.Controlling = true
	if err != nil {
		return nil, "", err
	}
	sc, err := clientStream(ic)
	if err != nil {
		_ = ic.Close()
		return nil, "", err
	}
	return sc, path, nil
}

// Accept: agent/controlled side. Returns a reliable net.Conn ready for tunnel.Server.
func Accept(ctx context.Context, cfg Config, sig Signaler) (net.Conn, string, error) {
	ic, path, err := Connect(ctx, cfg, sig) // cfg.Controlling = false
	if err != nil {
		return nil, "", err
	}
	sc, err := serverStream(ic)
	if err != nil {
		_ = ic.Close()
		return nil, "", err
	}
	return sc, path, nil
}
```

**Call‑site cutover (replacing the deleted relay‑TLS blocks):**
- `internal/client/session.go` `DialGrantVia` lines ~151‑188 (the `tls.Dialer` + `RelayHello`/`RelayResp` rendezvous) → `conn, path, err := p2p.Dial(ctx, cfgFromResp(resp), clientSignaler)`; then the **unchanged** `tunnel.Client(conn, key, resp.GetAgentNoisePub(), resp.GetSessionId(), resp.GetSignedGrant())`. Keep `tunnelHandshakeTimeout` as the deadline (apply via `conn.SetReadDeadline`, which reaches the Stream).
- `internal/agentd/offer.go` `runSession` lines ~154‑177 (the `tls.DialWithDialer` + `RelayHello` responder) → `conn, path, err := p2p.Accept(ctx, cfgFromGrant(grant), sessionSignaler)`; then the **unchanged** `tunnel.Server(conn, w.st.Noise, grant.ID, authorize)`. The `probeSessionICE` shims (Connect‑then‑Close) are promoted into this real `Accept` data path.
- Remove `relay_addr`/`relay_token` from the session path, `wire.RelayHello`/`RelayResp` usage on sessions, and the `:7403` TCP rendezvous — **but see §5/red‑team carve‑out for the web‑shell.**

---

## 4. MTU / DATAGRAM HANDLING OVER TURN

**Pin SCTP's send MTU to 1200 (`Config.MTU`); do NOT rely on PMTUD/ICMP** — over TURN, ICMP‑needs‑frag is unreliable and the path can switch direct↔relay mid‑session, so a static conservative floor is the only robust choice (the same fixed‑MTU discipline the overlay uses). Budget on the relay floor: each SCTP packet becomes a UDP4 datagram that the TURN server wraps in `ChannelData` (+4 bytes) **or — for the first packets of a session before a channel is bound — a `Send`/`Data` *indication*, which is a full STUN message (~36+ bytes), not 4**. With SCTP's own common header (12) + DATA chunk header (16), MTU=1200 keeps the whole datagram well under 1280 even through Send‑indication framing + any OpenStack double‑NAT clamp, so **setup packets never fragment** (the most damaging place to lose a fragment). 1200 leaves throughput on the table vs a tighter pin, but that is the correct trade for a path that can't be probed; SCTP self‑fragments larger messages across DATA chunks and reassembles in order, so MTU never leaks up to Noise/SSH. The Noise layer above writes up to `MaxPlaintext=32 KiB` ciphertext frames; SCTP segments/reassembles them transparently. **Receive side:** SCTP owns its own reassembly (`MaxReceiveBufferSize`), so the overlay's per‑datagram `iceReadBuf=1600` short‑read pool is irrelevant here — but the `sctpConn.rbuf` is sized to `MaxMessageSize` (64 KiB) so a `Read` can never short‑buffer‑truncate a reassembled message. We never set DF.

---

## 5. FAILURE / FALLBACK UNDER NO‑LEGACY

The degradation ladder is enforced **entirely inside ICE candidate selection** — `Connect` already gathers Host + ServerReflexive + Relay (`iceURLs`, UDP4‑only). The SCTP association rides whatever `ice.Conn` pion selected, identically:

```
direct-UDP  (host/srflx hole-punch)
   ↓  (hard / symmetric NAT both ends)
TURN-UDP    (blind relay :7404 — the floor; relay forwards ChannelData of SCTP-framed Noise ciphertext)
   ↓  (no selectable pair, OR sctp.Client/Server fails within the deadline)
FAIL closed   — NO relay-TCP, NO ICE-TCP, NO TURN-TCP
```

If `Connect` returns an error (no pair / signal egress blocked / both hard‑NAT with relay unreachable) **or** the association doesn't form within `tunnelHandshakeTimeout`, `Dial`/`Accept` returns an error and the session fails closed — it does **not** fall back to the deleted relay‑TCP path. This is the DERP guarantee on one substrate. **Documented accepted loss:** a client behind a firewall that blocks *all* outbound UDP but permits TCP/443 connected via the old relay‑TCP `:7403` and now has no path. That population is unsupported in Phase 2 by design; the correct future re‑add is a TURN‑over‑TCP/TLS:443 *relay allocation* as a last‑resort ICE candidate **below** the UDP floor — never the relay‑TCP rendezvous.

**Two mandatory red‑team carve‑outs gating the cutover:**

1. **ICE‑failure deadlock (CRITICAL, red‑team #1).** On `ConnectionStateFailed`, pion v4.2.7 does **not** unblock a reader parked in `ice.Conn.Read`, and a post‑Failed `Write` returns `(0, nil)` — a silent success. SCTP's `readLoop` only breaks on a `NetConn.Read` error that never comes, so the SSH session hangs forever. **Fix (mirror `internal/vpn/icebind.go`):** register `OnConnectionStateChange` on the session `*ice.Agent`; on `Failed` (and on a `lastRX`‑stale heartbeat for the relay‑restart case pion's consent freshness misses) call `sessionConn.Close()` → `agent.Close()` → unblocks the parked `Read` with `net.ErrClosed` → SCTP errors → Noise errors → SSH tears down cleanly. **Independently add an `ssh` keepalive** (the client runs none today) so a wedged‑but‑not‑Failed path fails fast.

2. **ICE‑conn lifetime bound to the gather deadline (CRITICAL, red‑team #16).** In `ice.go`, the returned `*ice.Conn` rides `connCtx = WithTimeout(ctx, gather)` and `sessionConn.Close` cancels *that* cancel — so the substrate self‑destructs ~8–15 s after connect, regardless of session length. Latent today only because Phase‑1 probes immediately Close. **Fix in `Connect`:** split availability from connect — keep the bounded `connCtx` for gather+Dial/Accept only; on success derive a separate `context.WithCancel(context.Background())` for the session, store *its* cancel in `sessionConn`, and run the candidate‑receive goroutine on the session context so trickle keeps flowing for re‑nomination for the whole session.

**Also fold in (cheap, high‑value):** `BlockWrite:true` (backpressure for a slow sftp reader, red‑team #4); `EnableZeroChecksum:true` on both ends (drop per‑packet CRC32c — Noise AEAD covers integrity, red‑team CRC); and a per‑agent **live‑grant set** rejecting a second association presenting an already‑active `grant.ID` (restores the single‑use property the deleted relay token gave, red‑team #11 — wire it now or land it with Phase 3's epoch machinery, but do not ship the cutover without it).

---

## 6. SECURITY / BLINDNESS ARGUMENT

**The reliability layer sits strictly BELOW Noise**, so the security boundary is untouched: the agent still verifies the controller‑signed grant and `remoteStatic == grant.ClientNoisePub` *inside* the Noise IK handshake (`offer.go:182`), and the relay/path see only `ChannelData` whose inner bytes are **SCTP‑framed Noise ciphertext** they cannot decrypt. The §4.14 confidentiality invariant holds — the relay payload is opaque AEAD. **Two honest integrity caveats the threat model must now state explicitly** (the relay is *payload‑blind*, not *integrity‑protecting* the sub‑Noise transport):

- **Blind RESET injection (red‑team #8, HIGH).** SCTP chunk headers ride in cleartext inside `ChannelData`; an off‑path attacker who can forge a UDP datagram to the relay's allocated transport address could inject an `ABORT` that tears the association below Noise. Containment: pion's `RemoteIPFilter` + per‑allocation TURN permission shrink the spoofable set, and — critically — **an association/stream death MUST fail the session CLOSED (re‑evaluating the grant on any reconnect), never silently downgrade or force a fallback.** The §4.14 test gets an **integrity arm**: an injected `ABORT`/forged chunk ends the session cleanly with no desync into the Noise framer and no downgrade.
- **New metadata vs the old TCP splice (red‑team #3/#9, MEDIUM).** The relay now sees per‑datagram size/direction/count, SCTP chunk types (INIT/COOKIE = setup, DATA:SACK ratio = interactivity, SHUTDOWN = teardown timing) — but **no grant id, user, node id, or session_id**, which stay inside the Noise envelope. Update §4.14 to say precisely what the relay still observes; document that `require_relay` forces the floor but does **not** buy header‑metadata hiding.

**Pre‑auth resource burn (red‑team #10, MEDIUM):** the association forms before the Noise authorize runs, so a stranger who hole‑punches the agent's ICE socket can hold an association. Mitigate with a short `SetReadDeadline` on the stream that is only extended once a valid Noise msg1 (carrying the signed grant) authorizes — an association that sends no valid msg1 within ~3 s is torn down — plus a cap on concurrent un‑authorized associations per agent. The ICE socket is already gated behind `EvaluateOffer` (gathered only after a signed, in‑window grant), bounding *who* learns the candidate.

---

## 7. BATTLE‑TEST PLAN

**A. Unit — message↔byte‑stream correctness (the load‑bearing finding).** In `internal/sessionconn`, run `clientStream`↔`serverStream` over a `net.Pipe`‑backed `ice.Conn` stub. Drive `wire.WriteFrame`/`ReadFrameLimit` through `sctpConn` with **split AND coalesced** writes (hdr+body in one `Write`, and a `bufio.Writer` over the conn) and assert byte‑exact, in‑order reassembly — proving `sctpConn.Read` severs the fragile message‑boundary dependency. Assert a `Read` with a buffer smaller than a frame never truncates.

**B. Unit — §4.7 authorize invariant.** Mirror `internal/tunnel/integration_test.go` but with the SCTP‑wrapped loopback: controller signs a grant, client embeds it in Noise msg1 over the `sctpConn`, agent runs the *unchanged* `authorize` (`VerifyGrant` → `g2.ID==grant.ID` → `remoteStatic==grant.ClientNoisePub`). Assert the authorize call sequence is byte‑identical to the relay path, and reject cases (bad sig, wrong `ClientNoisePub`, id mismatch) still fail before any app byte.

**C. Loss / reorder / dup injection.** Insert a lossy middlebox `net.Conn` between the stub `ice.Conn` and SCTP that drops/reorders/duplicates datagrams at configurable rates (e.g. 1%, 5%, 20% loss; reorder window 3). Assert: (i) a 10 MiB transfer arrives intact and ordered under 5% loss; (ii) an interactive single‑byte "keystroke" round‑trips and recovers a single lost packet via fast‑retransmit in ~1 RTT; (iii) `BlockWrite` bounds sender RSS when the reader pauses (slow‑sftp backpressure, red‑team #4) — measure RSS stays flat; (iv) a forged `ABORT` is contained (session ends clean, red‑team #8).

**D. Teardown / goroutine leak (red‑team #21).** `go.uber.org/goleak` is already a dep. Open+close N=200 sessions through `Dial`/`Accept`; assert zero residual goroutines and that the close order (stream → association → ice.Conn) leaves no SCTP readLoop/writeLoop or candidate‑receive goroutine spinning.

**E. Real lab e2e over the double‑NAT topology (`geneza1`, vmbr5 `10.70.70.0/24`, VMs 105/106/107).** Extend `scripts/e2e.sh`:
1. **Direct path:** `geneza exec`/`ssh`/`sftp`/`forward` client(106)↔agent(107); assert success and `path: direct`; **kill the relay process mid‑session** and assert the session survives (relay not in the data path — the Phase‑2 headline).
2. **Relay floor:** set `require_relay` (or `netem` symmetric‑NAT both ends so only the relayed pair selects); assert `path: relayed`, full exec+sftp success, and — the blindness arm — capture `ChannelData` at the relay and assert the inner bytes are undecryptable (no SSH banner, no plaintext, no grant/session id).
3. **Liveness/failure:** with a session live, **restart the relay**; assert the watchdog tears the session closed within the liveness window (no forever‑hang, red‑team #1) and a fresh `geneza exec` reconnects.
4. **Loss on the wire:** `tc qdisc netem loss 5% delay 30ms` on the agent vmbr5 link; assert interactive latency stays usable and a 50 MB `sftp` completes intact.
5. **Web‑shell carve‑out (red‑team #3, MUST):** the browser console (`console_shell.go` → `DialGrantVia(localRelayAddr)`) is a relay‑TCP consumer with no ICE identity. **Do NOT physically delete the relay‑TCP responder** — keep it as an internal, loopback‑only, controller‑co‑located rendezvous for the web‑shell (not a public no‑legacy path), and sequence the cutover: land ICE session transport → migrate the web‑shell to a session‑ICE client → only then remove relay‑TCP. Add an e2e check that the browser console still works after cutover.

---

**Files read for grounding (absolute):** `/root/geneza/internal/sessionconn/ice.go`, `/root/geneza/internal/sessionconn/doc.go`, `/root/geneza/internal/tunnel/noise.go`, `/root/geneza/internal/wire/frame.go`, `/root/geneza/internal/client/session.go`, `/root/geneza/internal/agentd/offer.go`, `/root/geneza/internal/vpn/icebind.go`, `/root/geneza/internal/controller/console_shell.go`, `/root/geneza/go.mod`, and the pion/sctp v1.10.0 source at `/root/go/pkg/mod/github.com/pion/sctp@v1.10.0/{association,stream,reassembly_queue}.go`.

**Net:** one new module (`pion/sctp v1.10.0`, transport stays `v4.0.2`, no DTLS, no new non‑pion vendor), ~90 lines of new `internal/sessionconn` code (the `sctpConn` byte‑stream adapter is the only protocol‑touching part), the unchanged Noise+grant+SSH+sessionhost stack above, and four mandatory red‑team fixes folded into the cutover (ICE‑failure watchdog, session‑lifetime context split, `BlockWrite` backpressure, live‑grant single‑use) before Phase 2 ships.
