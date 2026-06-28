# Geneza Conduits — Buildable Spec & Phased Plan

> **AMENDMENT 2 (operator directive, 2026-06-14): NAMING — "session", not
> "conduit".** Keep `session` as the single, consistent term across API, CLI, and
> internal code for the mesh-services layer (exec/ssh/sftp/forward). There is NO
> separate "conduit" noun — a session is a session; going direct-when-possible is
> just *how it connects*, surfaced as a `path: direct | relayed` attribute (on
> `SessionRecord`, `geneza ps`, the `/api/v1/sessions` JSON). The transport
> lives in `internal/sessionconn` (the per-session ICE+SCTP net.Conn), over the
> shared pion-ICE primitives in `internal/icewire` (also used by `internal/vpn`). The
> `AuthSession` (browser login session) naming overlap is deferred — for now,
> unqualified "session" = the remote-access session, "login/auth session" = the
> browser one. Read every "conduit" in this doc as "session (p2p path)".
>
> **AMENDMENT 1 (operator directive, 2026-06-14): NO LEGACY. This system is brand
> new — do not keep the relay-TCP session path as a dual-path fallback or behind
> a staged `conduit_direct` flag.** Conduit is THE session transport from the
> cutover on. The ONLY fallback is the blind **TURN-UDP relay floor (`:7404`)** —
> that is the DERP guarantee (direct-when-hole-punchable → TURN-relayed UDP under
> hard NAT) on the same pion-ICE substrate, NOT legacy. **Remove** the `:7403`
> TCP rendezvous, the `DialGrant` relay-TLS block, `runSession`'s relay dial, the
> `conduit_direct` kill-switch, the `conduit_transport: relay` option, and the
> Phase-6 "retire legacy" step. Revised phases: **1 signaling (additive, lab
> stays green on the incumbent transport) → 2 conduit transport (cut over +
> DELETE relay-TCP) → 3 lease/realtime-PEP → 4 per-op restrict + host SetCaps.**
> The §6 phase plan below is read through this lens (drop Phase 0's flag, drop
> Phase 6). Phase 1 keeps relay-TCP only as the still-current transport being
> replaced, never as a permanent fallback.

**Status:** synthesized executive spec. Supersedes the per-session relay-TCP rendezvous (`:7403`) for the session apps. Net change: session apps (exec / ssh / sftp / forward) become NAT-traversed P2P over the existing pion-ICE substrate, the agent becomes a realtime policy-enforcement point, and the relay is reduced to coordination-assist + payload-blind fallback.

---

## 1. The model in words

Geneza today has two planes:

- **Overlay (the VPN):** a per-Network userspace-WireGuard mesh. Each agent runs a `wireguard-go` device per VNI whose `conn.Bind` is pion ICE (`internal/vpn/icebind.go`): host/srflx direct when hole-punchable, a blind TURN floor on `:7404` when not, magicsock-style auto-upgrade. Proven 1.29 Gbit/s through OpenStack double-NAT. Keyed by WireGuard pubkey, tag-gated, node↔node only.
- **Sessions (the apps):** today exec/ssh/sftp/forward ride **SSH-inside-Noise** over a **relay-TCP rendezvous** (`:7403`). The relay splices the TCP stream; it is payload-blind but it *is* in the data path of every session, sees every session's existence/timing, and is the de-facto kill switch.

**Conduits** is the new layer that gives the session apps the overlay's NAT traversal *without* fusing them into the overlay. A **conduit** is one identity-bound, policy-gated, end-to-end session path that prefers a **direct E2E p2p** connection and falls back to the **blind relay**. It is the L7 session-app sibling of the L3 overlay: same pion ICE substrate, same blind relay floor, but **per-session / grant-gated** instead of per-Network / tag-gated.

Roles:

- **PDP — the controller (broker/coordinator).** Decides policy, signs grants, coordinates ICE candidate exchange (DERP-style), and pushes realtime authorization (leases + capability deltas). It is **never in the data path** of a direct conduit.
- **PEP — the agent.** The sole connect-time gate (it independently re-verifies the controller-signed grant against its own trusted keys) **and** the realtime enforcement point: it can cut, restrict, or downgrade a live conduit in-flight per pushed changes, and it **fails closed** when the controller goes silent.
- **DERP — the relay.** Coordination-assist (ICE candidate/cred relaying happens through the controller, not the relay; the relay is the TURN floor) plus **blind UDP fallback** (`:7404`) for hard/symmetric NAT. It carries opaque Noise-over-UDP it cannot decrypt and is no longer a session metadata observer for hole-punched conduits.
- **Direct = E2E p2p.** When both ends hole-punch, the conduit is a direct UDP path carrying the **unchanged E2E Noise tunnel**; the relay and the controller both see nothing.

### Explicit zero-trust delta

**Gains**

1. **Relay leaves the data path** on the common (hole-punchable) case: no longer a session metadata/timing observer, chokepoint, or SPOF. On fallback it sees only Noise-over-UDP ciphertext — strictly less than the old TCP rendezvous (which saw connection timing + rendezvous tokens).
2. **E2E preserved byte-for-byte.** The audited Noise IK tunnel + signed-grant authorize callback (`offer.go` `remoteStatic == grant.ClientNoisePub`) is unchanged. ICE is an availability layer, **not** the security boundary.
3. **No-inbound-ports preserved on both ends.** ICE is all-outbound (STUN binding, TURN allocate). Neither agent nor client ever listens on a public interface.
4. **Enforcement at the resource owner.** The agent (and the session-host, which owns the PTY) is now the PEP — the strongest place to enforce — and authority becomes per-operation, not whole-session-only.
5. **Fail-closed by design.** A mandatory data-path lease turns "controller out of the data path" from a risk into a property: a lost revoke or a partition expires the conduit instead of leaving it up.
6. **Compromised-controller containment unchanged.** The agent re-verifies grants and caps against its **own** trusted keys; a compromised controller cannot exceed agent-enforced policy/TTL/detach ceilings, and cannot *widen* a standing grant.

**Honest tradeoffs (each carries a mitigation that is a MUST in §5)**

- **Loss of the central relay as a single audit/observation vantage.** Mitigation: the controller broker + agent-emitted `SessionEvent`s become the authoritative, *richer* audit point (path class, lease ledger). The relay only ever saw blind bytes anyway.
- **Peers learn each other's reflexive IPs** on a direct conduit. Mitigation: bounded to grant-named, controller-authorized counterparts; a per-node `require_relay` policy bit forces relay-only for sensitive targets.
- **A compromised agent can ignore the cut** — and on a direct path there is no relay chokepoint to backstop it. Mitigation: the **client** also honors revoke/lease-expiry (belt-and-suspenders), and node quarantine stops new brokering. Documented as a bounded residual.

---

## 2. Decisions F1–F5

### F1 — Transport: **B (keep Noise E2E, swap the transport to a session-scoped pion `*ice.Conn`).**
*Justification:* `tunnel.Server`/`tunnel.Client` already take any `net.Conn` and `runSession`/`DialGrant` already hand in a `tls.Conn`; swapping that conn for a pion `*ice.Conn` keeps the audited Noise+grant+SSH+sessionhost stack byte-for-byte unchanged, works with only an outbound UDP socket (no TUN → macOS/Windows clients work day one), and preserves a clean per-operation PEP seam — whereas Fork A (overlay-unify) requires the ephemeral CLI client to be a full WG node (false in `internal/client/` today, cross-platform-blocked) and replaces the unconditional `ClientNoisePub` crypto gate with a config-fragile source-IP binding.

**Mechanism.** New package `internal/conduit/` exposes `Dial` (client, mirrors `DialGrantVia`) and `Accept` (agent, mirrors `runSession`'s relay block). Each builds a **session-scoped** pion `ice.Agent` (its own `UDPMux` on its own ephemeral socket — **not** the overlay's multi-peer `ICEBind`/GSO `conn.Bind`), `CandidateTypes{Host, ServerReflexive, Relay}`, role from a controller-assigned `controlling` bit, bounded gather (pion `FailedTimeout` ~8s, not the overlay's perpetual reannounce), explicit teardown on session end. The selected `*ice.Conn` (already `net.Conn`) is fed **verbatim** into `tunnel.Server`/`tunnel.Client`; everything above (Noise IK authorize, SSH dispatch, sessionhost PTY) is unchanged. The legacy relay-TCP path stays behind a kill-switch as the universal floor.

### F2 — DERP coordination: **reuse the controller disco forwarder pattern, add a first-class `session_id`-keyed signaling path.**
*Justification:* the existing disco broker (`disco.go` `handleAgentDisco` → `findNodeByWGPub`) routes **only between enrolled nodes keyed by WG pubkey**; the ephemeral CLI client has no WG pubkey and only a unary `UserAPI` — so a genuinely new user↔node channel keyed by `session_id` is required and must not overload the wgpub path (overloading it would let any co-member inject candidates for a session).

**Candidate exchange.** The agent (which holds `NodeControl.Stream`) trickles its session ICE candidates + ufrag/pwd up the control stream keyed by `session_id`. The ephemeral client opens a new **server-streaming** `UserAPI.SessionSignal(stream)` RPC immediately after `CreateSession`, mTLS-scoped to exactly the just-signed `session_id`. The controller is a stateless forwarder keyed by `session_id` (a `sessionSignalBroker{session_id → {clientStream, agentNodeID}}`), forwarding client→agent over `NodeControl` and agent→client over the `SessionSignal` stream. **`findNodeByWGPub` is never on the conduit path.**

**DERP fallback guarantee.** Every session ICE agent always gathers the TURN relay (`:7404`) candidate, so under hard/symmetric NAT on both ends pion selects the relayed pair and the conduit **still connects** — the relay forwards opaque Noise-over-UDP, blind. If the client cannot even open `SessionSignal` (egress blocks the gRPC stream), the controller hands back the legacy `relay_addr`/`relay_token` in `CreateSessionResponse` as a hard floor. Degradation order: **direct-UDP → TURN-UDP → legacy relay-TCP.** A session never fails to connect.

### F3 — Realtime PEP: **lease + downgrade-only capability deltas, enforced at the agent AND the session-host, granularity = finest the change implies (cut / per-op restrict / in-flight downgrade), lease MANDATORY and shipped with the transport.**
*Justification:* with the controller off the direct data path, the agent must enforce in-flight; the lease is the only structural backstop against a partition (without it a revoked direct session runs to the 24h `maxAgentSessionTTL`), and the session-host must be authoritative or a detached PTY dodges a read-only downgrade by detach/reattach or worker self-update.

**What the controller pushes** (over the control stream, all signed + monotonic-epoch'd; see §5):
- **Lease refresh** — short signed token (TTL ~120s, refreshed ~30s by `reauthSweep` while authz holds). Governs **liveness only**, never scope.
- **`SessionPolicyDelta`** — `{session_id, epoch, op, target, caps, lease_expiry, reason}`. Downgrade-only: the agent re-verifies the new caps are a **subset** of the standing grant.

**How the agent applies it (granularity):**
- **Whole-session cut:** existing `revokeLive` → `cancel()` tears the conduit; session-host `Kill` reaps a detached PTY. Self-triggered on lease starvation.
- **Per-operation restriction:** `w.live` value changes from `context.CancelFunc` to `*liveSession{cancel, caps atomic.Pointer}`. `serveForward` consults `caps.allowedForwards` at **channel-open AND at splice time**, and **actively closes** the in-flight `spliceForward` goroutines for now-forbidden targets (tracked in a per-session `map[target][]ssh.Channel`). `serveSFTP` gates writes (EPERM) on `caps.allowSFTPWrite`. New channels rejected when `!caps.allowNewChannels`.
- **In-flight shell read-only downgrade:** the **session-host** is authoritative — a new `SessionHost.SetCaps(host_session_id, {readOnly, ...})` RPC flips a per-session caps cell that `handleInput` consults before `w.Write(in.Data)` (`session.go:388`), so a **detached** PTY cannot be written even with no agent bridge in the loop. The agent's `bridgeAttachChannel` input pump is only the fast path. The cap persists on the host across worker restart; `serveAttach` re-reads host caps on reattach and never re-widens from the static grant.

Composes with the existing `reauthSweep` (15s): a tightening that does not fully deny becomes a caps delta instead of an all-or-nothing cut; `SendRevoke` stays the immediate hard kill; the lease is the fail-closed floor.

### F4 — Authority model: **agent stays the SOLE connect-time gate via the UNCHANGED Noise authorize callback; conduit.Accept runs the identical EvaluateOffer + authorize sequence; ICE is availability, not security.**
*Justification:* the relay was only ever an *implicit* rendezvous gate; the real gate has always been the agent's independent grant re-verification (`offer.go` `VerifyGrant` against the agent's own trusted keys + `g2.ID == grant.ID` + `remoteStatic == grant.ClientNoisePub`), which is unconditionally safe regardless of network config and survives the transport swap untouched.

A random/compromised co-member who hole-punches to the agent's ICE socket **cannot complete the Noise handshake** (no `ClientNoisePub` private key) and is dropped before any application byte. Layered binding: (a) per-session ICE ufrag/pwd delivered only to the grant-named principal via the controller; (b) per-session ephemeral TURN creds so a stranger cannot even allocate on the relay; (c) decisive — the Noise+grant gate. **Invariant (MUST, tested):** `conduit.Accept` runs the same `EvaluateOffer` + Noise-authorize sequence as the relay `runSession`; the transport swap changes **only** the `net.Conn` under `tunnel.Server`, never the authorization sequence above it. The agent never gathers/answers ICE for a `session_id` without an accepted, in-window, signed grant.

### F5 — Name: **CONDUITS.**
*Justification:* a conduit is an on-demand, identity-bound, policy-gated per-session E2E L7 path on the same pion substrate as the overlay (which stays the persistent L3 mesh) — the name keeps the overlay/conduit distinction crisp, reads naturally in code/CLI (`internal/conduit/dial.go`, `accept.go`), and avoids the `Service`/`ServiceAdvert` collision of "mesh services" and the overlay overlap of "peer fabric." The relay's role is renamed in code/docs from "session relay" to "overlay/conduit **fallback** relay."

---

## 3. Proto / config / code changes

### Proto — `api/proto/geneza/v1/control.proto` (EXTEND, additive)
- **`DiscoMsg`**: add `string session_id = 7;` (conduit signaling sets `vni=0`, `session_id` set). Routed by `session_id`, **not** `peer_wgpub`.
- **`UserAPI`**: add `rpc SessionSignal(stream ClientSignal) returns (stream ControllerSignal);` — the ephemeral client's session-scoped signaling channel, mTLS-bound to the just-issued `session_id`. `ClientSignal`/`ControllerSignal` carry `IceCreds` + candidate strings (reuse `pion ice.Candidate.Marshal()`).
- **`SessionOffer`**: add `TurnCreds turn = N; bool controlling = N;` so the agent's offer carries its session ICE coordinates.
- **`CreateSessionResponse`**: add `TurnCreds turn = N; bool controlling = N;`. Keep `relay_addr`/`relay_token` as the legacy floor.
- **`ControllerMsg` oneof**: add `SessionPolicyDelta session_policy_delta = N;`. New `message SessionPolicyDelta { string session_id=1; int64 epoch=2; string op=3; string target=4; SessionCaps caps=5; int64 lease_expiry_unix_ms=6; string reason=7; bytes sig=8; }` and `message SessionCaps { bool allow=1; bool allow_pty=2; bool allow_input=3; repeated string forward_targets=4; bool allow_sftp_write=5; bool allow_new_channels=6; }`.
- **`SessionRevoke`**: add `int64 epoch` + `bytes sig` (was unsigned, no epoch).

### Proto — `api/proto/geneza/v1/sessionhost.proto` (EXTEND)
- Add `rpc SetCaps(HostSetCapsRequest) returns (HostEmpty);` with `HostSetCapsRequest { string host_session_id=1; bool read_only=2; bool allow_new_channels=3; bool allow_sftp_write=4; repeated string allowed_forwards=5; }`. Caps persist on the host and survive worker restart.

### Types — `internal/types/grant.go`
- `Validate()` unchanged for the relay path; conduit grants reuse `NetworkVNI`. No source-IP binding (F1=B keeps `ClientNoisePub`).

### Code — EXTEND (not rewrite)
- `internal/agentd/offer.go` `runSession`: replace the relay-TLS block (`tls.DialWithDialer` + `RelayHello`, ~lines 118–141) with `raw, err := conduit.Accept(ctx, grant, turnCreds, controlling)` returning a `net.Conn`, falling back to the existing relay-TLS dial on ICE failure. The `tunnel.Server` authorize callback and everything below are **unchanged**.
- `internal/client/session.go` `DialGrantVia`: branch — if the response carries `TurnCreds`, open `SessionSignal`, call `conduit.Dial(...)` for the `net.Conn`, hand it to `tunnel.Client`; on any failure fall back to the existing relay-TLS path (zero-risk rollout).
- `internal/agentd/worker.go`: change `w.live` from `map[string]context.CancelFunc` to `map[string]*liveSession{cancel, caps}`; add `applyDelta(id, *SessionPolicyDelta)` (verify sig + monotonic epoch + subset, mutate caps, actively close forbidden channels); add the arm/refresh **lease timer** (self-teardown on starvation); add `ControllerMsg_SessionPolicyDelta` and session-keyed disco cases to the stream loop.
- `internal/agentd/session.go`: `serveForward` reads `caps.allowedForwards` at channel-open and re-checks at splice time + closes removed-target splices; `serveSFTP` write-gate; `serveExec`/`serveShell` honor cut; `bridgeAttachChannel`/`serveAttach` apply live read-only via the host caps.
- `internal/sessionhost/`: implement `SetCaps`; `handleInput` (`session.go:388`) drops `w.Write(in.Data)` when `read_only`; caps cell persists across worker restart; reattach re-reads host caps.
- `internal/controller/continuousauthz.go` `reauthSweep`/`reauthorize`: return a capability decision; push `SessionPolicyDelta` (downgrade) on subset-tighten, `SendRevoke` only on full deny; **re-push current authoritative caps+lease per tick** (converge-on-state, not one-shot edges); refresh the lease each tick.
- `internal/controller/broker.go` `createSession`: call `turnCredsFor` to mint **session-scoped, short-TTL** creds; populate the new response/offer fields; register the `sessionSignalBroker` entry.
- `internal/controller/disco.go` `handleAgentDisco`: add a `session_id` branch that forwards via the `sessionSignalBroker` between the agent's `NodeControl` and the client's `SessionSignal` stream. `findNodeByWGPub` stays on the wgpub (overlay) path only.
- `internal/controller/registry.go`: add `SendSessionPolicyDelta` mirroring `SendRevoke`; make enforcement messages (revoke/delta/lease) **never-drop** (priority path, not the best-effort `events` queue that drops at cap 256).
- `internal/relay/turnserver.go`: add `PermissionHandler` (only the grant-named counterpart's candidate addresses) + per-cred/per-IP `QuotaHandler`; drop allocations on session revoke.
- `internal/controller/turncreds.go`: bind the REST username to the **`session_id`**, shorten `defaultTURNCredTTL` from 1h to ≤ grant/session window.

### NEW
- `internal/conduit/{dial.go, accept.go, ice.go}` — session-scoped pion `ice.Agent` wrapper reusing `internal/vpn/icebind.go`'s **patterns** (agent config, gather, Dial/Accept, TURN floor) but its own ephemeral `UDPMux`, returning the selected `*ice.Conn` as `net.Conn`.

### Reused from `internal/vpn` UNCHANGED
The entire overlay `ICEBind`/multi-peer `conn.Bind`, GSO socket, `UniversalUDPMux`, `SyncPeers`/recovery, liveness watchdog, and the disco candidate-exchange **pattern**. Conduits reuse the pattern and the TURN floor (`:7404`), not the multi-peer Bind. The overlay `ICEBind` is **not modified**.

### Config
- `conduit_transport: overlay|relay` per-node (default conduit; auto-fallback to relay-TCP for no-overlay/blocked clients).
- `require_relay` per-node/role policy bit (force relay-only for sensitive targets, preserves IP-hiding + central tap).
- `conduit_direct: true|false` global kill-switch for staged rollout.

---

## 4. Security checklist (every red-team mitigation is a MUST)

1. **MUST** add a first-class `session_id`-keyed signaling path (`UserAPI.SessionSignal` + `DiscoMsg.session_id`); the controller forwards ICE creds/candidates ONLY between the two principals named in the brokered grant. `findNodeByWGPub` MUST NOT be on the conduit path. *(HIGH: ICE-signaling identity gap.)*
2. **MUST** bind TURN creds to the `session_id` with TTL ≤ grant TTL (not 1h, not random opaque id); configure pion/turn with a `PermissionHandler` restricting `CreatePermission` to the grant-named counterpart's candidates and a per-cred/per-IP `QuotaHandler`; drop allocations on revoke. *(HIGH: unauthenticated TURN allocation / relay amplification.)*
3. **MUST** gate session ICE-agent creation (gather/answer) on `EvaluateOffer` success — no socket gathered before an accepted, signed, in-window grant; arm pion `FailedTimeout` so an unanswered gather tears down fast (grant-scoped socket lifetime, not a standing oracle). *(MEDIUM: agent ICE reachability/IP-disclosure oracle.)*
4. **MUST** ship `SessionHost.SetCaps` IN THE SAME CHANGE as the conduit transport, making the session-host the authoritative read-only/quiesce point for attached AND detached PTYs; agent SSH pump is only the fast path; caps persist across worker restart; reattach re-reads host caps, never re-widens from the static grant. *(HIGH: realtime PEP unbuildable + detached-PTY downgrade bypass.)*
5. **MUST** make the fail-closed data-path lease MANDATORY and ship it WITH the direct transport (not follow-up): agent forwards only while a short signed lease is fresh; on partition/lost-revoke the lease expires and the agent self-tears (`revokeLive` + host `Kill` for detached PTY). Add an e2e check: sever the control stream, assert the conduit dies within ~1 lease TTL, not at `maxAgentSessionTTL`. *(CRITICAL: partition = uncuttable session.)*
6. **MUST** sign every lease refresh AND every `SessionPolicyDelta`/`SessionRevoke` with a trusted grant key the agent holds independently, carry a strictly-monotonic per-session epoch (reject non-increase), and verify downgrade-only (subset of the standing grant). Bind to `session_id` + `ClientNoisePub`. *(MEDIUM: lease/delta replay & rollback.)*
7. **MUST NOT** adopt F1=A's source-overlay-IP admission binding; keep `remoteStatic == grant.ClientNoisePub` as the sole connect-time gate; `conduit.Accept` runs the byte-identical `EvaluateOffer` + Noise-authorize sequence as `runSession`, with an invariant test. *(HIGH: spoofable/config-fragile binding.)*
8. **MUST** cap remote candidates per session (small N) + rate-limit `AddRemoteCandidate`; controller sanity-filters forwarded candidates (drop reserved/mismatched-scope); use a dedicated session ICE socket (not the shared overlay GSO socket) so connectivity-check load cannot starve/amplify through the overlay. *(MEDIUM: candidate-flood / connectivity-check DoS.)*
9. **MUST** keep the controller the authoritative audit point off the data path: agent emits `SessionEvent` (established/attached/detached/ended/revoked) including the **selected path class (direct vs relay)** + `session_id`/epoch, plus a lease-expiry teardown event; no code path treats "no relay log" as "no session." *(LOW: lost central audit vantage.)* Offer `require_relay` for high-sensitivity nodes.
10. **MUST** make enforcement messages (revoke/delta/lease) idempotent, re-driven each sweep tick until the agent confirms via `SessionEvent`, and routed on a never-drop priority path (not the best-effort `events` queue that drops at cap 256). On control-stream reconnect the controller re-pushes the full current caps+lease per live session (state, not buffered deltas) so the agent converges deterministically. *(MEDIUM: best-effort revoke silently dropped + boundary race.)*
11. **MUST** actively tear in-flight resources on downgrade (close matching `spliceForward` channels on `revoke_forward`; flip host caps so in-flight stdin stops immediately) — not gate the next op only. *(MEDIUM: in-flight forward/shell not torn.)*
12. **MUST** distinguish lease starvation = "controller unreachable" from "authz denied": both fail closed for the *conduit*, but the agent MUST NOT tear the session-host PTY on mere unreachability (let detached PTYs persist for reattach); lease TTL > worst-case reconnect backoff; a clean reconnect+rehello is an immediate refresh. *(HIGH: lease-starvation DoS.)*
13. **MUST** also push revoke/lease-expiry to the CLIENT so either honest end closes the conduit (belt-and-suspenders against a compromised agent); node quarantine (`Approved=false`) stops new brokering. Documented as a bounded residual. *(HIGH: compromised agent ignores the cut.)*
14. **MUST** re-audit relay-blindness on the TURN fallback (Noise now rides TURN ChannelData, not the TCP splice) — extend the blindness invariant test to the TURN path. *(MEDIUM.)*

---

## 5. Cross-platform support statement

- **Linux:** fully working end-to-end. The conduit transport (pion ICE + Noise + SSH, all userspace, **no TUN, no root, no kernel module**) ships Linux-complete. Agent + session-host are Linux-first.
- **macOS / Windows CLIENTS:** **direct conduits work day one** — this is the decisive advantage of F1=B over the overlay-unify fork. A conduit needs only an outbound UDP socket; pion/ice, flynn/noise, and `x/crypto/ssh` compile and run unprivileged on macOS/Windows today. No utun/wintun dependency. (This is why the dataplane decision picked userspace pion everywhere.) Session apps never touch a TUN.
- **macOS / Windows AGENTS:** the conduit transport is cross-platform, but session-host PTY/exec semantics on Windows agents remain out of scope (unchanged by this design); agents are Linux-first in the lab.
- **Universal floor:** any platform/NAT that cannot hole-punch connects via TURN-relay (`:7404`) or, worst case, the legacy relay-TCP splice — so "it always connects" holds on every OS.
- **Contrast (do not confuse):** the L3 VPN **overlay** client still gates on the unfinished macOS-utun/Windows-wintun work. **Conduits do not** — they are unblocked on non-Linux clients now.

---

## 6. Phased build plan

Each phase is independently lab-e2e-testable. **The legacy relay-TCP path stays the working default until Phase 6**, so the existing battery (CLI exec/ssh, relay-blindness, VPN hole-punch, detach-reattach, signed staged self-update with rollback) stays green at every step. New conduit work lands behind `conduit_direct=false` until proven.

### Phase 0 — Proto + scaffolding (no behavior change)
**Files:** `api/proto/geneza/v1/control.proto`, `sessionhost.proto`, regenerate `internal/pb`; new empty `internal/conduit/{ice.go,dial.go,accept.go}`; config knobs `conduit_transport`/`conduit_direct`/`require_relay`.
**Adds:** `DiscoMsg.session_id`, `UserAPI.SessionSignal`, `SessionPolicyDelta`/`SessionCaps`, `SessionRevoke.epoch`+`sig`, `CreateSessionResponse`/`SessionOffer` turn+controlling, `SessionHost.SetCaps`.
**e2e assertion:** full existing battery still green (proto additive, no path uses the new fields yet); build + `go vet` clean.

### Phase 1 — Session-scoped ICE coordination (the new signaling path)
**Files:** `internal/controller/disco.go` (`session_id` branch + `sessionSignalBroker`), `broker.go` (mint session-scoped TURN creds, register broker entry), `internal/client/session.go` (open `SessionSignal`), `internal/conduit/ice.go` (gather/exchange), `internal/controller/turncreds.go` + `internal/relay/turnserver.go` (session-bound creds, PermissionHandler, QuotaHandler).
**MUSTs landed:** §4.1, §4.2, §4.3, §4.8.
**e2e assertion:** with `conduit_direct=false` (transport still relay-TCP), a client + agent successfully exchange ICE candidates and **select an ICE pair** over the new signaling path on a hole-punchable topology (mirror the overlay's OpenStack-double-NAT proof); assert TURN creds are session-scoped and rejected for a different session. Relay-TCP sessions unaffected; battery green.

### Phase 2 — Direct conduit transport (the swap)
**Files:** `internal/conduit/{dial.go,accept.go}`, `internal/agentd/offer.go` `runSession` (conduit.Accept + relay fallback), `internal/client/session.go` `DialGrantVia` (conduit.Dial + relay fallback).
**MUSTs landed:** §4.7 (invariant test: `conduit.Accept` authorize sequence byte-identical to `runSession`), §4.14 (relay-blindness re-audited on TURN fallback).
**e2e assertion (the headline):** with `conduit_direct=true`, **a session establishes a DIRECT path (selected pair = host/srflx) when hole-punchable, and falls back to the relay (TURN `:7404`) under hard NAT** — both topologies connect; kill the relay process on the direct topology and assert the session still works (no relay in path); force relay-only and assert it still connects AND the relay sees only ciphertext. Legacy relay-TCP still selectable via `conduit_direct=false`. CLI exec/ssh + detach-reattach green over the conduit.

### Phase 3 — Realtime PEP: whole-session cut + mandatory fail-closed lease
**Files:** `internal/agentd/worker.go` (`liveSession{cancel,caps}`, lease timer, self-teardown), `internal/controller/continuousauthz.go` (lease refresh per tick), `registry.go` (signed `SendRevoke` + lease, never-drop path), client-side revoke/lease honoring (§4.13).
**MUSTs landed:** §4.5 (lease mandatory, shipped here with the transport era), §4.6 (sign+epoch), §4.10 (idempotent re-drive), §4.12 (starvation distinguishes unreachable vs denied), §4.13 (client honors too).
**e2e assertion:** open a **direct** conduit, sever the agent↔controller control stream, assert the conduit **fails closed within ~1 lease TTL** (not at `maxAgentSessionTTL`); a detached PTY persists for reattach but the *conduit* dies; a replayed/stale lease does not extend a revoked session.

### Phase 4 — Per-operation restriction + in-flight downgrade (host-authoritative)
**Files:** `internal/sessionhost/` (`SetCaps`, `handleInput` read-only gate, caps persist across restart, reattach re-reads), `internal/agentd/session.go` (`serveForward` live caps + active splice close, `serveSFTP` write-gate, `serveAttach` applies live downgrade), `worker.go` `applyDelta`, `continuousauthz.go` (subset-tighten → delta).
**MUSTs landed:** §4.4 (SetCaps host-authoritative, same change), §4.11 (active in-flight teardown).
**e2e assertion (the second headline):** **a pushed policy/suspension change cuts/restricts a live DIRECT session within a bounded window** — start a direct shell, push read-only, assert keystrokes stop while output continues, and assert it **survives detach→reattach and a worker binary self-update** (host caps authoritative); start a 2-target forward, push `revoke_forward` on one, assert that splice closes immediately while the other survives.

### Phase 5 — Audit + observability off the data path
**Files:** `internal/agentd/worker.go` (`SessionEvent` carries path class + epoch + lease-expiry teardown), controller session ledger, `require_relay` enforcement.
**MUSTs landed:** §4.9.
**e2e assertion:** every conduit (direct and relay) is fully recorded at the controller (lifetime, path class) with the relay process killed; a `require_relay` node forces relay-only and is observable centrally; no code path infers "no session" from "no relay log."

### Phase 6 — Make conduit the default; retire the legacy path
**Files:** flip `conduit_transport` default to `overlay/conduit`; mark relay-TCP `DialGrant` legacy-compat; documentation rename (relay → "conduit fallback relay"); plan deletion of the relay-TCP `:7403` rendezvous once the web-shell proxy + relay-TURN cover all clients.
**e2e assertion:** full battery green with conduit as default; degradation matrix proven (direct → TURN → legacy relay-TCP → web-shell); the no-overlay/no-UDP-egress client still connects via the retained floor. Document that data-path containment of a compromised agent now depends on the client honoring revoke + node quarantine, not the relay.

---

**Key file anchors (verified in this checkout, branch `wip`):** `internal/agentd/offer.go` (`runSession` relay dial ~L118, authorize `ClientNoisePub` L160, `maxAgentSessionTTL` L61); `internal/client/session.go` (`DialGrantVia` L129, relay TLS dial L145–189); `internal/controller/disco.go` (`handleAgentDisco`/`findNodeByWGPub`, wgpub-keyed); `internal/controller/continuousauthz.go` (`reauthSweep` L41, `revokeSession` L113, gated on `registry.Online`); `internal/controller/registry.go` (`SendRevoke` L271 best-effort, `SendDisco` L305); `internal/agentd/worker.go` (`w.live map[string]CancelFunc` L139, `revokeLive` L155, `SessionRevoke` case L536); `internal/agentd/session.go` (`serveForward` L559 reads static grant L577, `spliceForward` L599, `bridgeAttachChannel` L259); `internal/sessionhost/session.go` (`handleInput` L368, `w.Write(in.Data)` L388 — no caps concept); `api/proto/geneza/v1/control.proto` (`DiscoMsg` L79 keyed by `peer_wgpub`, `SessionRevoke` L216 unsigned/no-epoch, `TurnCreds` L180); `api/proto/geneza/v1/sessionhost.proto` (Create/Attach/List/Kill/Health/ApplyPolicy only — no SetCaps). The `scripts/e2e.sh` battery (35 checks per project notes) is not in this checkout and must be extended with the Phase 2–5 assertions above before each phase is declared green.