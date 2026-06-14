# Geneza vs. SRA — Feature, Security & Performance Comparison

> **Baseline:** SRA (Secure Remote Access) — a Rust workspace forked from Narrowlink.
> **Subject:** Geneza — this repository.
> For every capability, the SRA implementation is taken as the reference point and the
> equivalent Geneza capability is compared against it, with explicit security and
> performance notes plus other relevant criteria.

**Date:** 2026-06-14
**SRA revision analysed:** `75ea6fe` (`/root/repos/sra`, ~21k Rust LOC, 7 crates + a Go TUI)
**Geneza revision analysed:** `ac1b5b6` (this repo, ~33k Go LOC, 6 binaries, ~5.85k test LOC)

---

## 0. Methodology & caveats

Both systems are the same *kind* of thing — a relay-based, no-inbound-port remote-access
system where agents dial out and operators reach them through an encrypted tunnel. That
shared shape makes a feature-by-feature comparison meaningful.

Findings below were produced by reading the **actual source** of each codebase and citing
`file:line`, not by trusting the design docs. This matters because **both projects' prose
docs lag their code**:

- SRA's root `CLAUDE.md` still describes a minimal passphrase/JWT PTY fork; the shipped
  code has moved to X.509/Ed25519 certs, a YubiKey CA, RBAC/ACLs, recording, and a TUN VPN.
- Geneza's `ARCHITECTURE.md` names OPA/Rego, `coreos/go-oidc`, and WebAuthn; the code uses
  a hand-rolled YAML policy engine, hand-rolled JWT/JWKS verification, and has no WebAuthn.

Where docs and code disagree, this comparison follows the **code**.

This is an engineering comparison, not a verdict on which project "wins." They target
overlapping but different points: SRA optimises for a *small, auditable, single-domain*
remote-shell tool fronted by Cloudflare; Geneza optimises for a *multi-tenant fleet mesh*
with federated identity and a real overlay data plane.

---

## 1. Executive summary (TL;DR)

| | **SRA (baseline)** | **Geneza** |
|---|---|---|
| Language / runtime | Rust + tokio, `panic=abort`, musl static | Go 1.26, `CGO_ENABLED=0` static |
| Core posture | Outbound-only agents, Cloudflare Tunnel hides the relay | Outbound-only agents *and* operators; payload-blind relay |
| Planes | 2 (gateway/relay merged, data) | 3 (control / blind relay / E2E data) |
| Tunnel crypto | XChaCha20-Poly1305 over WSS, X25519 DH | Noise IK (`flynn/noise`) inside which runs the SSH connection layer |
| **Tunnel crypto correctness** | **Broken: static AEAD nonce reused for every frame** | No findings against tunnel crypto (per internal audit) |
| Machine identity | X.509 + Ed25519, custom OID, YubiKey/offline CA, deferred signing | X.509 ECDSA, `geneza://` SAN URIs, two-tier offline-root CA, join tokens + signed `SessionGrant` |
| Human identity | **Client certs only — no SSO** | OIDC/OAuth2 + PKCE, password-grant, local bcrypt fallback |
| Authorization | Gateway RBAC + live-reload ACLs + tags + lockdown (agent-scoped) | Policy-as-data RBAC/ABAC, **continuous re-authz**, `require_native`, signed-grant enforcement at agent |
| Session persistence | **None** — TCP drop kills the shell | Separate session-host process; survives client crash, roaming, relay failover, worker self-update |
| Self-update | Hash check; **signature only presence-checked, not verified** on agent | TUF-lite ed25519 signing, pinned key, health-gated rollback, anti-rollback floor, canary→stable |
| Audit | SHA3-256 hash-chained JSONL (unsigned), local only | **HMAC-keyed** hash-chained JSONL, off-box http/file sink |
| Data plane | Per-agent point-to-point: TUN VPN, SOCKS5, port-forward, exec, cp | Per-Network **WireGuard mesh** (userspace wg-go) + legacy L3 VPN; ~1.29 Gbit/s measured NAT-traversed |
| NAT traversal | Hand-rolled UDP hole-punch (no STUN/ICE/TURN) | **pion ICE/STUN/TURN**, UDPMux, magicsock-style, relay fallback |
| Multi-tenancy | **None** (single trust domain) | Structural workspace isolation (bbolt sub-buckets, per-tenant overlay/policy) |
| In-network DNS | **None** (OS resolver) | Embedded `miekg/dns`, per-agent policy-aware resolver |
| Operator UX | Rich CLI (~25 cmds) + Go Bubble Tea TUI (shells out to CLI) | Rich CLI (Cobra) + React web console with browser shell |
| Tests | **2 unit test modules, no e2e, build-only CI** | 5.85k test LOC + 40-check lab e2e battery (no CI yet) |

**One-line takeaway:** Geneza is a broader, more defensively-engineered system across nearly
every axis, and crucially does **not** carry SRA's two most serious cryptographic defects
(static-nonce AEAD reuse, unverified update signatures). SRA's advantages are its smaller
surface area, lower operational complexity, and a more battle-scarred production history
(its security fixes landed against real incidents). Geneza's main *relative* weaknesses are
operational maturity (single-node bbolt gateway = SPOF, no CI) rather than design.

---

## 2. Architecture & topology

**SRA (baseline).** Four binaries — `sra-gateway` (relay+control merged), `sra-agent`,
`sra` (operator CLI), `sra-token`. Agents dial **outbound WSS** to the gateway and open
**zero** inbound ports; agent-local services bind `127.0.0.1` only (PTY `:22222`, exec
`:22224`, transfer `:22225`). The gateway binds `127.0.0.1:80` and is exposed **only**
through a **Cloudflare Tunnel** (`cloudflared`), which hides the VPS IP and means no public
listener at all. Clean, minimal attack surface.

**Geneza.** Three strictly-separated planes: **control** (`internal/gateway`), a stateless
**payload-blind relay** (`internal/relay`), and an **E2E data** plane (`internal/tunnel`,
`internal/vpn`). Both agents *and* operators dial out; managed nodes have no inbound ports
(even node-exporter metrics are scraped over the control channel, not a port).

**Assessment.**
- *Surface area:* SRA is genuinely smaller and the Cloudflare-fronted design removes the
  public listener entirely — a real defensive win and an operational simplification.
- *Separation of concerns:* Geneza's three-plane split is stronger in principle — the relay
  is a separate stateless binary that never holds identity or plaintext, whereas SRA folds
  relay+control into one gateway process.
- *Single-point-of-failure:* both have a SPOF gateway. SRA's is inherent (one relay, no HA).
  Geneza's gateway is a single bbolt-backed process (HA Postgres is roadmap-only), so it too
  is a SPOF for *new* sessions — though established E2E/mesh sessions survive its loss.
- *Dependency posture:* SRA leans on Cloudflare as a hard dependency (and inherits its
  constraints — forced HTTP/1.1 ALPN, "Flexible" SSL). Geneza is self-contained (embeds its
  own TURN floor), at the cost of more moving parts.

---

## 3. Transport & cryptography

**SRA (baseline).** WSS over TLS 1.3 (`tokio-rustls`/`rustls`), with an application-layer
E2E AEAD using **XChaCha20-Poly1305** keyed by **X25519 ephemeral DH** (`OsRng`, per
connection → connection-level forward secrecy). A QUIC path (`quinn`) exists for P2P.

> **🔴 Critical defect (verified in code).** `AsyncSocketCrypt` holds a **single
> `nonce: [u8;24]`** (`sra-network/src/lib.rs:90`) and reuses it for **every**
> `encrypt`/`decrypt` call (`lib.rs:118,141,177,198`) with **no per-message increment**.
> The key is fixed per connection, so the same `(key, nonce)` pair encrypts every frame in a
> session. This **voids XChaCha20-Poly1305's confidentiality and integrity** within a
> session: keystream reuse leaks plaintext XOR relationships, and Poly1305 one-time-key
> reuse enables tag forgery. The 192-bit nonce width is irrelevant because it never varies.
> Inherited from upstream Narrowlink and **not fixed** in the fork. Compounding it: a
> `SigningAlgorithm::HmacSha256` is defined and parsed but **never actually computed or
> verified** (`generic.rs`, `p2p.rs:114-118`), so there is no independent MAC, and the KDF
> is a non-standard raw `SHA3-256(DH ‖ nonce)` with no HKDF/domain separation.

**Geneza.** Control channel is gRPC over **mTLS** (TLS 1.3 min, `VerifyClientCertIfGiven`).
The data tunnel handshake is **Noise IK** via `flynn/noise` (Curve25519 / ChaCha20-Poly1305
/ BLAKE2s, `tunnel/noise.go:35`), with a prologue binding the handshake to the session ID
and the signed grant embedded in handshake message 1 — so **an unauthorized peer never
receives a byte of application data**. Inside the completed tunnel runs the **SSH connection
layer** (`x/crypto/ssh`) carrying shell/exec/sftp/forward channels. The native CLI path is
**true E2E**; only the web path terminates at a gateway-resident proxy. The relay parses
exactly one hello frame then copies bytes, logging only metadata. Frames are length-prefixed
with a read cap (~32 KiB) to stop a blind relay forcing huge allocations.

**Assessment.**
- *Crypto correctness:* This is the single most consequential difference in the whole
  comparison. Geneza uses a vetted Noise pattern with a maintained library and per-message
  nonce handling; SRA's hand-rolled AEAD wrapper has a session-fatal nonce-reuse bug. On
  cryptographic soundness, Geneza is decisively ahead.
- *"Don't roll your own":* SRA rolls its own framed AEAD + KDF + (dead) MAC; Geneza adopts
  Noise IK and the SSH connection layer wholesale — the safer engineering choice, and
  consistent with its stated "reuse standard libraries" principle.
- *What the relay sees:* both keep the relay/edge blind to payload in the native path. SRA's
  TLS terminates at Cloudflare (plaintext WS on localhost to the gateway), so its
  confidentiality vs. the *relay* rests entirely on the (broken) XChaCha20 layer. Geneza's
  relay is blind by construction and the E2E layer is sound.

---

## 4. Identity & machine/agent enrollment

**SRA (baseline).** X.509 + **Ed25519** leaf certs with identity in **custom OID extensions**
(`{uid,name,policies}` JSON). Auth to the gateway is by `SRA-CERT` / `SRA-CERT-SIG` /
`SRA-CA-FP` headers (Ed25519 over `SHA3-256(cert ‖ ts)`, ±30 s window). The **CA private key
lives offline** in the operator's **YubiKey (PIV 9c)** with a file fallback; the gateway only
*validates*. Zero-touch **bootstrap**: a cert-less agent generates a keypair, POSTs a CSR,
and polls until an operator approves+signs offline. Revocation is a JSON CRL.

**Geneza.** **Two-tier CA** (ECDSA P-256 root → issuing CA → leaves), with the **root key
moved to a separate offline dir** and only the issuing key loaded at runtime. Identity is a
**`geneza://{node,user,gateway,relay}/<workspace>/<name>` SAN URI** plus a roles/provider
extension. Machine enrollment uses **one-time join tokens** (transactionally consumed in a
bbolt write txn), landing nodes in PENDING unless minted `--auto-approve`. The installer pins
the root fingerprint and stage-1 binary hash before exec. Every session additionally rides an
**ed25519-signed `SessionGrant`** the agent independently verifies (signature, node binding,
agent-Noise-key binding, expiry, scope) — so a compromised gateway cannot grant access the
agent will honour. Revocation is **expiry-as-baseline** (24 h node / 8 h user TTLs) **plus a
serial denylist** checked at every authenticated RPC.

**Assessment.**
- *CA key custody:* comparable and both good — SRA keeps the CA key in hardware/offline;
  Geneza splits the root off-box and runs from a subordinate. Geneza's two-tier model is more
  standard for fleet scale.
- *Revocation:* Geneza is ahead. SRA has a CRL but it is **not auto-reloaded**
  (`ca.rs:103-118` needs a manual call/restart) while its ACLs *are* live-reloaded — an
  inconsistency that lets a revoked-but-connected agent linger. Geneza's short TTLs +
  per-RPC denylist react faster (bounded by reconnect, not by an operator action).
- *Defence-in-depth:* Geneza's signed `SessionGrant`, independently enforced at the agent,
  is a meaningful trust-minimisation property SRA has no equivalent of — SRA's gateway is
  more trusted (it gates the data channel; the agent largely obeys).
- *CSR validation:* SRA does not verify the CSR signature at bootstrap submission; Geneza's
  token consumption is transactional and single-use. Edge to Geneza.

---

## 5. Human / operator authentication

**SRA (baseline).** Operators authenticate with **client certificates** (same header scheme,
YubiKey touch or file CA). There is **no OIDC / SSO / SAML anywhere** — every operator is a
locally-issued cert. This is SRA's single biggest identity gap.

**Geneza.** Federated **OIDC/OAuth2** — but *not* via `coreos/go-oidc` (absent); the gateway
**hand-rolls JWT/JWS verification** (`gateway/oidcverify.go`): OIDC discovery, JWKS
fetch/cache/kid-rotation, RSA/EC only, rejects `none`/HMAC, iss/aud/exp/nbf with skew, JWKS
DoS hardening. Client flows: AuthCode + **PKCE S256** loopback (default), `--manual` headless
paste, and password-grant (ROPC) for CI. **Local login fallback** is bcrypt with a
timing-oracle-hardened dummy-hash path. (No device flow; **WebAuthn/FIDO2 is absent** despite
the design doc.)

**Assessment.**
- *Federation:* Geneza is categorically ahead — it integrates with an external IdP
  (the lab federates to Keycloak), maps IdP groups to roles, and supports SSO. SRA cannot.
- *"Roll your own" caveat:* Geneza hand-rolls the JWT/JWKS verifier, which is a deliberate
  dependency-reduction choice but is exactly the class of code that has produced CVEs
  elsewhere (alg-confusion, kid-injection). It is implemented carefully (rejects `none`/HMAC,
  validates kid) and unit-tested, but it is a larger trusted surface than using a vetted
  library. Worth noting as a residual risk even though it is *more* capable than SRA's
  cert-only model.
- *Hardware-bound human keys:* SRA actually has a concrete edge here — operator auth is
  YubiKey-touch-gated by default. Geneza's login uses a file key store and has no WebAuthn,
  so the *human credential* is software-resident unless the IdP enforces MFA.

---

## 6. Authorization / policy

**SRA (baseline).** Layered, mostly gateway-side, all **live-reloaded**: operator **RBAC**
(`roles.json` → admin/operator/auditor), **ACLs** (`access.json`, per-user rules incl.
`tag:X`, exact name, and **time-bounded** `rule@<rfc3339>`, re-read on every check), **tags**
(admin-merged), **lockdown** (`locked.json` blocks new connections), IP blocking + auth-fail
rate-limiting. Agent-side: an `allowed_users` header and a CIDR/port `Policy` checked before
the agent dials a backend.

**Geneza.** A **policy-as-data** engine — *not* OPA/Rego (no such dep); a hand-rolled YAML
engine with an `Engine` interface as the documented OPA swap-in seam. RBAC **+ ABAC**: roles
bound to users/groups, allow rules over `actions × node-labels × time-windows`, a
`MaxSessionTTL` cap, `AllowDetach`, and **`require_native`** (reserves sensitive targets for
the true-E2E client, **fail-closed**). The gateway decides with the `ClientPath` set by the
*trusted caller* (never client-supplied). **Continuous authorization**: a 15 s sweep re-runs
policy against live sessions and pushes a revoke that tears the tunnel down. `platform-admin`
is reserved break-glass and stripped from any IdP-resolved role set.

**Assessment.**
- *Model richness:* roughly comparable on RBAC + time-windows + tags/labels; Geneza adds
  true ABAC over labels, per-session TTL caps, and the `require_native` web/native
  distinction. Edge to Geneza on expressiveness.
- *Continuous enforcement:* Geneza's 15 s re-authz that actively kills live sessions is a
  capability SRA lacks entirely — SRA's `lockdown` blocks *new* connections but does not
  terminate established ones. Significant edge to Geneza for incident response.
- *Granularity:* SRA's policies are effectively **agent-scoped**, not per-user-within-agent
  (a `policies: Vec<u32>` field exists but is **not enforced**), and the ACL fallback trusts
  the agent's self-reported `allowed_users`. Geneza scopes per identity and re-checks at the
  agent against the signed grant. Edge to Geneza.
- *Both* live-reload policy; both re-check on two sides. This is the axis where SRA is
  closest to parity.

---

## 7. Session model & persistence

**SRA (baseline).** PTY shell via `portable-pty` on `127.0.0.1:22222`, framed
data/resize protocol, idle + max-duration timeouts, `MAX_CONCURRENT_SESSIONS=5`.
**Persistence: none** — a TCP drop terminates the session; there is no session ID,
re-attach, or tmux-style detach (`shell.rs:259-266`). Recording is **asciinema v2**
`.cast`, `0600`, 50 MB cap — but **plaintext at rest**, capturing full keystrokes.

**Geneza.** A **separate `session-host` process** (`Setsid`, not killed on worker shutdown)
owns the PTY and **always drains** it. Two buffer layers (vt10x screen snapshot +
byte-bounded scrollback ring with zeroize), **sequence-numbered I/O** with ack and
delta-or-full replay on reattach, **re-auth on every reattach** (fresh grant, ownership
re-checked). It **survives client crash, roaming, relay failover, and worker self-update**;
it does **not** survive session-host death or **node reboot** (explicit v1 non-goal).
Recordings are asciicast v2 produced at the agent and uploaded to a **write-once** store.

**Assessment.**
- *Persistence:* the starkest functional gap. SRA has none; Geneza's persistent session host
  is one of its headline features and survives the common real-world disruptions (laptop
  sleep, network roam, relay restart, agent self-update). Decisive edge to Geneza.
- *Recording at rest:* both store asciicast; Geneza's gateway store is write-once (O_EXCL)
  and the recording is produced at the agent. SRA's recordings are plaintext `0600` files
  with no write-once guarantee. Slight edge to Geneza; **both** capture secrets typed into
  the shell (neither redacts).
- *Complexity cost:* Geneza pays for this with a whole extra process, an attach protocol, and
  buffer-management guardrails (TOCTOU-safe reservation, dim clamps, lag coalescing) — more
  code, more to get right. SRA's model is trivially simple by comparison.

---

## 8. Self-update & artifact signing

**SRA (baseline).** Hourly/on-connect check: fetch a `.hash` (SHA3-256), download the
binary, **re-verify the hash**, atomic rename, `systemctl restart`. A `.sig` is fetched and
the agent **refuses to update if it is missing** — but it **only checks the signature file
exists; it does not cryptographically verify it** (`update.rs:120-130`). Actual signature
verification only (maybe) happens in the gateway-served installer script, which **proceeds
with a warning if the CA cert is absent**. No staged rollout, no health gate, no rollback,
no version pinning.

**Geneza.** **`geneza-sign`** signs the manifest **offline** with **ed25519** (refuses to
run on the gateway). A **TUF-lite** model: an offline root key signs a set of authorized
signing keys (rotation overlap; no m-of-n threshold). The **bootstrap pins the signing key
independently of gateway TLS** (TLS can even be off), downloads under a size cap, **verifies
hash + size**, atomic-renames, and runs a **health gate** (fresh `worker.health` within 60 s)
with **health-gated rollback** that re-verifies the rolled-back binary. An **anti-rollback
floor** (highest committed timestamp, zero tolerance) blocks downgrades. Updates are
**desired state** the gateway stages **canary → stable**. The session host is never restarted
by an update, so live shells survive.

**Assessment.**
- *Signature enforcement:* Geneza actually verifies the signature against a pinned key on the
  endpoint; SRA only checks the *presence* of a signature file and defers real verification to
  a best-effort installer script. This is a genuine security gap in SRA — a malicious or MITM'd
  binary host could ship an unsigned/forged binary that SRA's agent would accept as long as
  *some* `.sig` file is served. Decisive edge to Geneza.
- *Safety of rollout:* health-gated rollback + anti-rollback floor + canary staging are all
  absent in SRA, which restarts and hopes the process manager copes. Edge to Geneza.
- *Trust anchor independence:* Geneza explicitly decouples update trust from transport trust
  (pinned key, not gateway TLS). SRA conflates them (the installer trusts the CA cert it is
  served, and skips on absence). Edge to Geneza.

---

## 9. Audit & logging

**SRA (baseline).** Gateway audit is **JSON-Lines** with `seq` + **SHA3-256 hash chain** +
RFC3339 timestamps, daily rotation, 30-day retention, queryable with filters. Agent-side:
exec log + session recordings.

**Geneza.** Gateway audit is append-only JSONL with a **keyed HMAC-SHA256** MAC per record
(32-byte key, `0600`) + monotonic seq + prev-hash chain + a sidecar checkpoint, **fail-closed**
("no audit, no action"), fsync per record, constant-time compare, torn-final-line repair.
Off-box sinks: **`file` and `http` (SIEM-over-HTTP)**. Recordings are write-once.

**Assessment.**
- *Tamper-evidence:* both chain records; Geneza's **HMAC key** means an attacker who can edit
  the log cannot recompute a valid chain without the key, whereas SRA's plain SHA3-256 chain
  can be **recomputed wholesale** after a selective edit/truncation (it detects in-place
  corruption only if the attacker can't recompute). Edge to Geneza.
- *Off-box durability:* Geneza can stream to a SIEM/file sink; SRA is **local-file only**
  (no syslog/SIEM drain, no WORM). Edge to Geneza.
- *Fail-closed:* Geneza refuses the action if it can't audit; SRA's audit is a no-op if no
  path is configured (fails open to silence). Edge to Geneza.

---

## 10. Data plane / VPN / mesh

**SRA (baseline).** Richer than its docs suggest, all **operator↔agent point-to-point**:
`sra forward` (TCP/UDP port-forward with profiles), `sra proxy` (**SOCKS5**), `sra tun` (a
real **L3 TUN VPN** via `ipstack`/`tun`/`wintun`, with gateway mode and per-route maps),
`sra connect` (raw tunnel), `sra exec`, `sra cp` (path-traversal-guarded, 500 MB cap,
SHA3-256 verified). **No agent-to-agent mesh** and **no shared overlay address space** —
each agent is an independent endpoint reached from the operator.

**Geneza.** Two overlays. **(A)** The headline **per-Network WireGuard mesh** —
**userspace `wireguard-go` by default** (so it traverses NAT and works on cloud VMs), one
`gnzw<vni>` interface per Network, tag-gated membership pushed by the gateway, per-node X25519
keys, **UDP GSO/GRO batching** (batch 128) for multi-gig. **1.29 Gbit/s** is a *measured*
figure on a 1-vCPU SNAT'd OpenStack VM over a direct NAT-traversed path, CPU-bound, 0% loss.
**(B)** A legacy L3 subnet-route/exit-node VPN pumping raw IP over the Noise tunnel
(`geneza vpn`). Port-forwarding is the SSH `direct-tcpip` channel, policy-gated.

**Assessment.**
- *Topology:* SRA is hub-and-spoke (operator is the hub); Geneza is a true **mesh** where
  enrolled nodes reach *each other* within a Network. Different capability class — edge to
  Geneza for fleet/east-west use cases, but SRA's model is sufficient (and simpler) for pure
  operator-to-server access.
- *Performance:* Geneza has a *measured* multi-gig throughput with GSO batching and an
  endpoint-as-identity design that avoids re-handshake on relay→direct upgrade. SRA's TUN VPN
  has **no published throughput numbers** and routes everything through the operator hop. The
  performance engineering (GSO/GRO, magicsock-style endpoints) is meaningfully more advanced
  in Geneza.
- *Standard components:* Geneza's data plane is built on `wireguard-go` + pion; SRA's TUN is
  built on `ipstack` and a hand-rolled tunnel. Geneza reuses more vetted networking code.
- *Breadth at the edge:* SRA ships SOCKS5 and a cross-platform (Linux/macOS/Windows) TUN
  today; Geneza's mesh/DNS edges are Linux-first (macOS partial, Windows roadmap). For a
  *single-operator, mixed-OS laptop* use case, SRA's client breadth is actually an edge.

---

## 11. NAT traversal

**SRA (baseline).** Hand-rolled **UDP hole-punching** with a NAT-type matrix and port
prediction (`p2p.rs:430-594`), QUIC carrying the direct stream after a punch. **No
STUN/ICE/TURN** — peers rely on a gateway-delivered instruction rather than standard
candidate gathering. Relay (WSS) is the always-available default; direct P2P is opportunistic.

**Geneza.** **pion ICE v4 / STUN v3 / TURN v5** (the earlier hand-rolled magicsock was
deliberately deleted in favour of libraries). A wireguard-go `conn.Bind` backed by an ICE
agent, **UDPMux** sharing one socket for ICE + WG data, **magicsock-style** endpoint-as-peer-
identity, direct-first candidate ordering with relay fallback, and an embedded **pion/turn**
relay floor using stateless HMAC (coturn-REST-style) credentials.

**Assessment.**
- *Standards & robustness:* Geneza uses the de-facto-standard ICE/STUN/TURN stack; SRA hand-
  rolls hole-punching with no STUN discovery, which is more fragile across symmetric/CGNAT
  topologies. Edge to Geneza, and it aligns with the project's "reuse libraries" principle.
- *Both* degrade gracefully to a relay path. Comparable fallback safety.

---

## 12. Multi-tenancy

**SRA (baseline).** **None** — verified absent. One gateway = one trust domain; any
authorized client can list all agents. Single shared CA/secret.

**Geneza.** **Structural** workspace isolation: nested bbolt sub-buckets (`ws/<id>/...`) so
cross-tenant reads return not-found *structurally* rather than via a filter, a per-workspace
policy engine, per-tenant overlay address allocation, and workspace baked into the cert URI
so every broker call is scoped. Proven by `TestCrossWorkspaceIsolation`. (Operator-facing
workspace CRUD RPCs and a console tenant switcher are still design-only; workspaces are
created via config or OpenStack auto-provisioning.)

**Assessment.** Not a contest — Geneza is built for multi-tenant fleets; SRA is explicitly a
single-domain tool. The structural (vs. filter-based) isolation is the security-correct choice
and is test-backed. Decisive edge to Geneza, with the caveat that tenant *administration* UX
is incomplete.

---

## 13. DNS / name resolution

**SRA (baseline).** **None** — OS resolver via `tokio::net::lookup_host`. No service
discovery, no split-horizon.

**Geneza.** Embedded **`miekg/dns`**: a per-agent local resolver at `100.64.0.53` (Linux)
answering purely from gateway-pushed per-Network zones, `SO_BINDTODEVICE=lo` so peers can't
query each other, **policy-aware by construction** (DNS-visible set == WG-peer set; deny →
NXDOMAIN, no enumeration oracle), offline-safe. (The client-side OS resolver *switch* is still
a stub; SRV/service records are design-only.)

**Assessment.** Geneza adds a real, zero-trust-aligned name service SRA has no equivalent of.
Edge to Geneza, tempered by the unwired client resolver switch (so today it's mostly useful
inside the mesh rather than transparently on the operator laptop).

---

## 14. Operator UX

**SRA (baseline).** A **rich CLI** (~25 subcommands via a custom `clap_lex` parser):
list/shell/connect/forward/proxy/tun/exec/cp/sessions, access/cert/operator management,
bootstrap/requests, tags, **decommission** (dead-man self-destruct), audit, crl, lock/unlock,
ip-blocking, status, completions. A gateway-served `curl|bash` installer. A **Go Bubble Tea
TUI** that **shells out to the `sra` CLI** and parses JSON (agents/ACL/certs/audit/requests
tabs, notes/stars). Scheduling is **client-local crontab**.

**Geneza.** A **Cobra CLI** (login/logout/whoami/ls/ssh/attach/sessions/exec/cp/forward/
services/connect/vpn + an `admin` tree) and a **React web console** (xterm.js) with 8 pages
incl. an in-browser remote shell over WebSocket (brokered as `client_path=web` so
`require_native` denies it), embedded Prometheus metrics, policy view, audit chain-OK
indicator, and token admin.

**Assessment.**
- *Self-destruct / decommission:* SRA's `decommission` (NUKE dead-man wipe + CRL revoke +
  bootstrap cleanup) is a concrete capability with no direct Geneza equivalent (Geneza relies
  on revocation + node removal). Edge to SRA here.
- *Web console:* Geneza ships a real browser UI with a working shell and metrics; SRA's "UI"
  is a terminal TUI that wraps the CLI. Edge to Geneza for breadth/accessibility, though SRA's
  shell-out TUI is pragmatic and dependency-light.
- *CLI breadth:* comparable; both are mature. SRA's per-OS client (TUN/SOCKS on
  Win/mac/Linux) is broader at the edge; Geneza's `admin` tree is broader on fleet ops.

---

## 15. Language, runtime & build

**SRA (baseline).** Rust (edition 2021), tokio async. Release profile is hardened:
`opt-level=z`, `lto`, `codegen-units=1`, **`panic=abort`**, `strip`. Only **two `unsafe`
blocks** in the whole tree (a `statvfs` FFI and Windows `wintun::load`), both justified —
excellent memory-safety posture. Cross-compiled to **musl static** Linux + macOS.

**Geneza.** Go 1.26, **`CGO_ENABLED=0`** + `-trimpath` → static, cross-compilable binaries,
no `import "C"` anywhere (even kernel-WG control uses netlink, not cgo). Goroutine-per-
connection with explicit caps/backpressure/deadlines. GC'd.

**Assessment.**
- *Memory safety:* both are memory-safe languages. Rust's near-total absence of `unsafe`
  gives SRA a marginal theoretical edge (no GC pauses, compile-time aliasing guarantees), and
  `panic=abort` avoids unwind-based surprises. Go relies on its runtime/GC but is equally free
  of manual memory bugs in this codebase.
- *Performance ceiling:* Rust + tokio generally has a higher throughput/lower-latency ceiling
  and no GC jitter — relevant for a data plane. **However**, Geneza is the one with *measured*
  multi-gig numbers and GSO batching, while SRA's data plane is unmeasured. So the theoretical
  Rust edge has not been realised as demonstrated performance.
- *Binary/footprint:* both produce static, CGO-free/musl binaries. SRA's size-optimised
  profile yields smaller binaries; Geneza's go.mod is heavy (k8s/cloud transitive deps via
  node_exporter + gophercloud) inflating build size.

---

## 16. Testing, validation & maturity

**SRA (baseline).** **Thin.** Only **two test modules** (X25519 DH unit tests + an ACL test);
**no integration/e2e harness**. CI is **build-only** (4 musl targets, tag-gated release) with
**no `cargo test`, no cargo-audit/SAST, no release artifact signing**; `cargo-deny` exists but
advisories checking is commented out. *But* SRA has a long, real-incident-driven hardening
history: `git log` shows "Fix 13 security vulnerabilities from production audit" and "Fix all
16 audit issues," among ~279 commits.

**Geneza.** **5,850 LOC of Go tests** across packages (security, audit incl. torn-line,
broker, overlay, rollout, policy, sessionhost screen/ring/lag, update health/rollback,
types). A lab **e2e battery** (`/root/labs/geneza1/scripts/e2e.sh`, **40 `check` assertions**)
plus dedicated proofs (TUF, enrollment, data-plane libs, OpenStack, DNS, overlay bench).
A formal **`SECURITY-AUDIT.md`** with 33 findings, of which ~28 are **verified-fixed in code**
with the remainder being explicit seams. **No CI** (`.github/workflows` absent); `make test`
only.

**Assessment.**
- *Automated tests:* Geneza is far ahead — SRA's ~2 test modules and lack of any e2e harness
  is the weakest part of its engineering story. Decisive edge to Geneza.
- *CI:* a wash, both weak. SRA builds but doesn't test in CI; Geneza has no CI at all. Both
  should fix this; SRA at least gates releases on a build.
- *Battle-testing / production scars:* SRA's edge. Its security fixes landed against *real
  production incidents* (the CLAUDE.md "known issues" table documents 14 production-hit
  items), which is a different and valuable kind of maturity. Geneza's audit was an internal
  multi-agent review — rigorous, but not (yet) production-fire-tested at the same level.
- *Supply chain:* neither signs release artifacts in CI (Geneza signs *update* artifacts via
  `geneza-sign`, which is different and good). SRA's `cargo-deny` advisories are disabled.

---

## 17. Security principles scorecard

Rated relative to the baseline. ✅ clearly stronger · ➖ comparable · ⚠️ weaker / gap.

| Principle | SRA | Geneza | Notes |
|---|:---:|:---:|---|
| Minimised attack surface (no inbound ports) | ➖ | ➖ | Both outbound-only; SRA also hides the relay behind Cloudflare |
| Sound, non-custom tunnel crypto | ⚠️ | ✅ | SRA has **static-nonce AEAD reuse**; Geneza uses Noise IK |
| End-to-end confidentiality vs. relay | ⚠️ | ✅ | SRA's E2E depends on the broken AEAD; Geneza's relay is blind + crypto sound |
| Don't-roll-your-own | ⚠️ | ➖ | SRA rolls AEAD framing/KDF/dead-MAC; Geneza rolls JWT verify + YAML policy (carefully) |
| Federated human identity / SSO | ⚠️ | ✅ | SRA cert-only; Geneza OIDC + PKCE |
| Hardware-bound human credential | ✅ | ⚠️ | SRA YubiKey-touch by default; Geneza file keystore, no WebAuthn |
| Least privilege / fine-grained authz | ⚠️ | ✅ | SRA agent-scoped, `policies` unenforced; Geneza per-identity ABAC |
| Continuous re-authorization | ⚠️ | ✅ | SRA blocks new only; Geneza kills live sessions on policy change |
| Trust-minimised gateway | ⚠️ | ✅ | Geneza's signed `SessionGrant` re-verified at agent; SRA agent trusts gateway |
| Timely revocation | ⚠️ | ✅ | SRA CRL not auto-reloaded; Geneza short TTL + per-RPC denylist |
| Verified, safe self-update | ⚠️ | ✅ | SRA presence-checks signature only; Geneza pinned-key verify + health-gated rollback |
| Tamper-evident, durable audit | ⚠️ | ✅ | SRA SHA3 chain (recomputable), local-only; Geneza HMAC-keyed + off-box sink + fail-closed |
| Multi-tenant isolation | ⚠️ | ✅ | SRA none; Geneza structural bbolt isolation |
| Memory safety / unsafe footprint | ✅ | ➖ | Both safe; SRA ~2 unsafe blocks, no GC |
| Secrets not captured in recordings | ⚠️ | ⚠️ | **Both** record raw keystrokes incl. typed secrets |
| Self-destruct / decommission | ✅ | ⚠️ | SRA dead-man NUKE; Geneza relies on revoke + remove |

---

## 18. Performance principles

| Dimension | SRA | Geneza |
|---|---|---|
| Data-plane throughput | Unmeasured; routed through operator hop; TUN on `ipstack` | **Measured ~1.29 Gbit/s** NAT-traversed, CPU-bound, with UDP GSO/GRO batching |
| Latency / jitter | Rust + tokio, no GC pauses (theoretical edge) | Go GC (sub-ms pauses typical); endpoint-as-identity avoids re-handshake on path upgrade |
| NAT-traversal efficiency | Hand-rolled punch, no STUN; relay default | ICE direct-first; UDPMux shares one socket for ICE+WG |
| Connection scaling | tokio tasks | goroutine-per-conn with explicit caps/backpressure |
| Binary size / footprint | Smaller (size-optimised musl) | Larger (heavy transitive cloud deps) |
| Crypto cost | XChaCha20 (fast) but broken; QUIC for P2P | ChaCha20-Poly1305 (Noise); WG ChaCha for data plane |

**Net:** Rust gives SRA a higher *theoretical* performance ceiling and no GC jitter, but
Geneza is the only one with **demonstrated** data-plane performance and the batching/mux
engineering to reach multi-gig. For the operator-shell use case both are more than fast
enough; for a fleet mesh, Geneza's measured numbers matter and SRA has no comparable mesh.

---

## 19. Where SRA is genuinely ahead

To keep this honest, the axes where the baseline beats Geneza:

1. **Attack surface / operational simplicity** — Cloudflare-fronted, no public listener, two
   merged planes, far less code to run and reason about.
2. **Memory-safety margin** — Rust with ~2 justified `unsafe` blocks and `panic=abort`; no GC.
3. **Hardware-bound operator credentials** — YubiKey-touch by default (Geneza has no WebAuthn
   / hardware key in the login path).
4. **Decommission / dead-man self-destruct** — a concrete NUKE-and-wipe capability.
5. **Cross-platform client breadth today** — TUN VPN + SOCKS5 on Linux/macOS/Windows; Geneza's
   mesh/DNS are Linux-first.
6. **Production battle-scars** — its security fixes were forged against real incidents.
7. **Smaller binaries / leaner dependency tree.**

---

## 20. Recommendations

**If picking SRA, fix first (in priority order):**
1. **🔴 The static-nonce AEAD reuse** (`sra-network/src/lib.rs`) — replace with a per-message
   counter/random nonce (or adopt a vetted AEAD construction / Noise). This is session-fatal
   and must be fixed before any production use.
2. **🔴 Real self-update signature verification** on the agent (don't just check the `.sig`
   exists) and remove the installer's "proceed on missing CA" path.
3. **Auto-reload the CRL** to match the live-ACL behaviour.
4. **Add an e2e/integration test harness** and enable `cargo test` + `cargo-deny` advisories
   in CI.
5. Consider OIDC for operators; enforce per-user (not just per-agent) policy.

**Geneza's residual gaps worth closing (informed by what SRA does well):**
1. **CI** — Geneza has none; add `make test` + `go vet` + race detector in GitHub Actions.
2. **HA gateway** — the single bbolt process is a SPOF for new sessions (Postgres is roadmap).
3. **Hardware-bound human auth** — WebAuthn/FIDO2 is in the design doc but absent in code; SRA's
   YubiKey-by-default is a reminder this matters.
4. **Reduce hand-rolled trusted surface** — the JWT/JWKS verifier and YAML policy engine are
   careful but are exactly the code classes that produce CVEs; the `Engine` OPA seam exists —
   consider using it, and keep fuzzing the JWT path.
5. **Secret redaction in recordings** — both systems capture typed secrets; a redaction layer
   would help either.
6. **Finish the wired stubs** — client OS resolver switch, web reattach-by-id, workspace CRUD
   RPCs, CA-rotation overlap.
7. **Decommission UX** — add an SRA-style dead-man wipe for lost/compromised nodes.

---

## 21. Bottom line

Taking SRA as the baseline, **Geneza is the more complete and more defensively-engineered
system on the large majority of axes** — and it avoids SRA's two most serious defects
(broken tunnel AEAD, unverified updates) by leaning on vetted constructions (Noise, ICE,
WireGuard, TUF-lite). It adds whole capability classes SRA lacks: federated identity,
multi-tenancy, a measured multi-gig mesh data plane, session persistence, continuous
authorization, policy-aware DNS, and a web console.

SRA's enduring strengths are **smaller surface area, lower operational complexity, a stronger
memory-safety margin, hardware-bound operator auth, broader same-day cross-platform client
support, and a production-hardened track record.** It is the better fit when the requirement
is a *single-domain, single-operator, minimal-footprint* secure shell with a hidden relay —
provided the nonce-reuse and update-verification bugs are fixed first.

Geneza is the better fit when the requirement is a *multi-tenant fleet* with federated SSO, an
east-west mesh, persistent sessions, and auditable continuous authorization — provided the
operational gaps (CI, HA gateway, hardware human-auth) are addressed.

---

*Compiled from source-level review of both codebases at the revisions noted above. All
claims are traceable to `file:line` citations in the underlying analysis; where a project's
documentation contradicted its code, the code was treated as authoritative.*
