# Architecture

This document describes how Geneza is built and why. It tracks the system as it
actually exists in this repository, not an aspirational design. Where a subsystem
has a deeper spec, it is linked from [`docs/`](docs/README.md).

The one-line version: **agents dial out, relays stay blind, and the node enforces
its own access.** Everything below follows from those three commitments.

---

## 1. The three planes

Geneza separates control, relay, and data into planes that are kept apart on
purpose. The separation is the foundational security property: no single
component sees both the authorization decisions and the plaintext.

- **Control plane** — the controller. It enrolls machines, brokers identity,
  evaluates policy, issues certificates, tracks fleet state, and aggregates
  audit. It brokers sessions but never carries their bytes.
- **Relay plane** — stateless forwarders. They rendezvous two endpoints that
  already share keys and shuttle ciphertext between them. They also carry an
  agent's long-lived control stream to a controller, blindly. A relay holds no
  session state and cannot decrypt anything.
- **Data plane** — end-to-end between client and agent. The session is encrypted
  by keys only the two endpoints hold; the relay in the middle is a dumb pipe.

```
        ┌──────────────────── control plane ────────────────────┐
        │ controller (stateless tier, replicated store, HA)         │
        │  identity broker · policy · CA · registries · audit    │
        └───────────────┬───────────────────────────────────────┘
                        │ mTLS gRPC (everyone dials out to here)
        ┌───────────────┴──────────── relay plane ──────────────┐
        │ stateless, payload-blind forwarders                    │
        │  rendezvous · TURN floor · blind control-stream carry  │
        └───────────────┬───────────────────────────────────────┘
                        │ end-to-end encrypted (Noise / WireGuard)
   ┌─────────┐  direct p2p when reachable   ┌──────────────────────┐
   │ client  │◀───────────────────────────▶ │ agent + session host │
   │ CLI/web │  relay floor otherwise        │ (no inbound ports)   │
   │ /desktop│                               └──────────────────────┘
   └─────────┘
```

---

## 2. Deployment & trust model

Geneza is self-hosted first. Every control-plane component is also built to run
as a managed service later, because the control plane is a stateless app tier
over a replicated store and the relays are stateless and blind — nothing in the
data path assumes who operates it.

Trust boundaries, ranked by how much damage a compromise does:

1. **The offline signing keys** — the CA root and the artifact/trust signing
   keys. These are the crown jewels; whoever holds them owns the fleet. They live
   off every controller, on a secrets host or in an HSM/KMS, and are wielded only by
   `geneza-sign` (release artifacts) and `geneza-trust` (the fleet trust set).
2. **The controller** — issues certs, evaluates policy, holds fleet state. It is an
   availability bottleneck for establishing *new* sessions, but not a
   confidentiality bottleneck: it does not hold the CA root, the signing keys, or
   any session plaintext.
3. **The web session proxy** — only on the browser path. A browser cannot speak
   the tunnel, so the proxy terminates TLS from the browser and re-encrypts into
   the session. It necessarily sees plaintext and is inside the trust boundary;
   native clients are not.
4. **Relays** — see ciphertext and traffic metadata (timing, volume). Safe on
   untrusted infrastructure.

> The single largest risk in the system is the binary-push channel becoming a
> path to fleet-wide compromise. The mitigation — agents verify a signing key
> **pinned offline**, independent of the controller's TLS — is described in §8 and
> is non-negotiable.

---

## 3. Identity & the auth broker

Geneza is not an identity provider. It federates humans to whatever the customer
already runs and brokers everything else.

**Humans** authenticate through OIDC (Okta, Entra, Google, Keycloak, …). The
controller runs the broker: it completes the OIDC flow, maps the verified identity
onto a Geneza principal and its workspace memberships, and hands back an opaque
session token plus a short-TTL, hardware-bound device certificate. MFA is the
IdP's job; an optional per-session WebAuthn presence check is the controller's.

**Machines** enroll with a one-time join token, or — on platforms that publish a
signed instance identity — with that document instead of a token. The OpenStack
instance-identity path is wired end-to-end (see
[`docs/openstack-integration.md`](docs/openstack-integration.md)); cloud-metadata
enrollment for other providers follows the same seam in
`internal/controller/enroll.go`.

**Workspaces** scope everything. A principal, a node, a policy, a session, and an
audit record all belong to a workspace, so one controller and one store can serve
multiple tenants without their fleets or identities bleeding into each other. The
reserved `admin` identity is break-glass only — it exists to bootstrap and
recover a cluster, not to run day-to-day.

Authorization is kept deliberately separate from authentication. A principal can
be **suspended** — authorization revoked — and that suspension is enforced on the
next policy check even while a previously issued token is still cryptographically
valid. Revoking access does not depend on a credential expiring. The auth-broker
and authz/presence models are specified in
[`docs/auth-broker-spec.md`](docs/auth-broker-spec.md) and
[`docs/authz-presence-spec.md`](docs/authz-presence-spec.md).

---

## 4. Certificates & the CA

Credentials are short-TTL X.509, minted per login and per session, with identity
encoded as a URI SAN:

```
geneza://node/<name>     geneza://user/<name>
geneza://controller/<name>  geneza://relay/<name>
```

plus a roles extension. **Expiry is revocation** — there are no CRLs to push.
The CA is two-tier (`internal/ca`): the root key is generated at `ca.Init` and
kept aside, and the controller holds only an intermediate it uses to issue leaf
certs. CA rotation is done with an overlap window — publish the new bundle, have
the fleet trust old and new together, then retire the old — never a hard cutover,
which is the classic way to lock yourself out of your own fleet.

Every controller-issued session grant is a signed envelope (`internal/types`). The
fleet trust set itself — the `ClusterConfig` that names the controllers, relays, and
the keys agents pin — is signed by a separate **offline** trust key via
`geneza-trust`, so a running controller (which holds only its own grant key) cannot
rewrite the trust set it operates under.

---

## 5. Transport

| Layer | Choice | Why |
|---|---|---|
| Control RPC | gRPC over mTLS, streaming | one persistent dial-out channel; strong typing; mature in Go |
| Session handshake | Noise IK (`flynn/noise`) | modern, analyzed mutual auth; the relay can't read it |
| Session protocol | the SSH connection layer (`x/crypto/ssh`) **inside** the tunnel | reuse hardened channel/pty/exec/sftp/forward semantics; identity is already established by Noise + the grant |
| Session p2p | pion ICE/STUN, TURN-UDP floor (`internal/sessionconn`) | direct hole-punched path when reachable, relay floor otherwise |
| Overlay data | userspace WireGuard with UDP GSO/GRO (`internal/vpn`) | high-throughput machine-to-machine mesh, same crypto everywhere |
| Overlay names | embedded resolver on `miekg/dns` (`internal/dns`) | policy-filtered, answered locally on the agent |
| Web transport | WebSocket (WSS) | universal; bridged to the session by the proxy |

A few things are worth drawing out, because they are where Geneza differs from a
textbook design.

**SSH inside the tunnel.** Geneza uses SSH's *channel layer*, not its transport
security. Identity and encryption are handled by Noise plus the signed grant; SSH
gives us exec, interactive shell, `sftp`, and TCP forwarding as channel types
rather than as new protocols we'd have to design and harden ourselves.

**One entrypoint for session transport.** Every client — CLI, desktop, and the
web proxy — selects its transport through a single function (`client.DialSession`)
gated by one server-side predicate (`types.PathSupportsICE`). A native client
gets an ICE offer and hole-punches; the web proxy is structurally unable to
request ICE and always takes the relay floor. This is deliberate: a new client
path that forgets to opt in defaults to the always-correct relay floor, never to
an ICE offer its peer would wait out. (The bug that motivated this — a web shell
stalling ~15s waiting out an ICE gather it could never complete — is exactly the
class of divergence the single entrypoint makes impossible.)

**Relay-homed control.** An agent keeps one long-lived control stream to a
controller. Rather than require a routable path from agent to controller, the agent can
*home* that stream through a relay: it opens a control hello to the relay, which
splices it straight through to the controller's control listener. The agent's mTLS
terminates on the controller, so the relay stays blind, and the agent needs only a
single outbound connection to a relay it does not have to trust. If its relay
dies it re-homes to another, or falls back to dialing a controller directly. See
[`docs/relay-homed-control.md`](docs/relay-homed-control.md).

This is only the *agent→controller* control path: the relay splices an agent's
stream to the one controller that owns it; it does not let any controller push to any
agent. The *client→controller* side is the complement — a client's `CreateSession`
may land on a controller that does not own the target agent's stream and is
redirected to the one that does (a `ControllerRedirect`). Relay-homed agent
control + client redirect-to-owner together are how a session reaches the right
controller; the redirect lives in §9 (HA) and `docs/ha-architecture-spec.md`.

**The overlay is separate from sessions.** A *session* (exec/ssh/sftp/forward) is
a brokered, grant-gated, point-to-point thing carried by `internal/sessionconn`.
The *overlay* (`internal/vpn`) is an opt-in, per-network WireGuard mesh for
machine-to-machine traffic, with its own policy-aware DNS answered locally on each
agent at a fixed in-network resolver address. They share crypto philosophy and
relay infrastructure but are different planes — the overlay is not "sessions for
machines," it's a network.

---

## 6. Access paths: native, web, desktop

|  | Native CLI | Web (browser) | Desktop |
|---|---|---|---|
| Tunnel terminates | on your device — true end-to-end | on the web session proxy — proxy sees plaintext | on your device — true end-to-end |
| Proxy in the trust boundary | no | yes (unavoidable; browsers can't speak the tunnel) | no |
| Install | one binary | nothing | one app |
| Credentials | hardware-bound key on device | server-side custody by the proxy + WebAuthn | hardware-bound key on device |
| Best for | the most sensitive targets | convenience, sharing, zero-install reach | the console UI with native-grade transport |

The web path is a deliberate trade: zero-install reach in exchange for a
privileged proxy. Four things keep that honest — the proxy is minimized and
hardened, the **agent enforces policy regardless** of what the proxy asks for,
recording happens at the agent and not only the proxy, and policy can reserve the
most sensitive targets for the native client (`require_native`). The desktop app
(Wails, `desktop/`) renders the same React console as the browser but drives the
shell through the shared client core in-process, so it gets the console UI *and*
the direct end-to-end tunnel.

---

## 7. Server-side session persistence

Geneza builds mosh/tmux-style resilience into the agent, so every client gets
persistence and roaming with nothing extra installed. The principle is to
**decouple the session from the connection**: the PTY, the shell process, and the
output state live in the agent's session host (`internal/sessionhost`) and keep
running whether or not a client is attached. The connection is transient and
reattachable by session ID.

This adds no new trust party — the buffer lives on the agent, which already has
the plaintext — and keeps native end-to-end intact. The implementation gets the
details that bite a build-it-yourself attempt right:

- **It always drains the PTY**, even when detached, so the shell never blocks on
  write and the "persistent" session never freezes.
- **It keeps two buffer layers**: a headless virtual terminal (`vt10x`) for an
  instant, correct screen repaint on reattach, and a bounded scrollback ring for
  history. Replaying raw bytes would cut mid-escape-sequence and corrupt
  full-screen apps.
- **It sequence-numbers I/O** and replays a delta (or a snapshot) on reattach, so
  a dropped link doesn't double-apply or lose in-flight keystrokes.
- **It re-authorizes on reattach** — certs rotate and ownership must be
  re-checked.
- **It has guardrails**: caps on ring size, detached-session count, and memory;
  TTL/idle reaping; zeroize-on-end (buffers hold plaintext); and a policy knob to
  forbid detached sessions on sensitive targets.

It survives laptop sleep, IP roaming, relay failover, client crash, and CLI↔web
hand-off. It does **not** survive node reboot or agent-process death — that is out
of scope, by design.

---

## 8. Self-updating fleet

The controller distributes the agent binary and CA bundle to the fleet. That is an
RCE channel into every node, so it is engineered defensively.

- **Two-stage agent.** A tiny, rarely-changing bootstrap (`geneza-bootstrap`) is
  the only thing the OS package installs. It verifies signatures, swaps binaries
  atomically, supervises, and rolls back on a failed health check. The larger
  worker is what actually changes.
- **Sign everything, verify offline.** Every worker build is signed, and the
  bootstrap verifies it against a public key **pinned in the bootstrap itself** —
  not against the controller's TLS. A fully compromised controller still cannot push an
  altered binary. The signing key lives offline.
- **The release trust chain** (`internal/releasetrust`) roots in an offline key
  that signs `root-keys.json`, which authorizes per-release signers, which sign a
  release's `SHA256SUMS`. A verified signature transfers trust to every asset
  digest, so the downloader trusts the artifact without trusting GitHub — and a
  leaked signer is rotated out by re-signing with the offline root, no client or
  controller rebuild.
- **Atomic swap + health-gated rollback.** Download → verify signature and hash →
  atomic rename → restart worker → self-test → auto-revert if it doesn't check in
  healthy. The session host is never restarted by an update, so live shells
  survive a binary push.
- **Staged rollout.** The controller treats agent version as desired state and rolls
  canary → stable behind a promotion health gate, halting if check-ins drop.

---

## 9. High availability

The controller is the availability bottleneck for new sessions, so HA is built in,
not bolted on. The model is **leaderless**: several controllers run over one
replicated store (Postgres today), and any controller can authorize, broker, and
redirect for the whole fleet. A client or agent reaches any controller and is
transparently redirected to the one that owns the target node. There is no leader
election and no failover promotion — losing a controller just removes one
interchangeable front door.

- **Controllers** heartbeat their endpoint into the store; the signed cluster map
  carries the set, and clients, agents, and relays re-home across it. Strong
  reads — suspension, node affinity — and the cross-controller doorbell go through
  the store, so a session denied on one controller is denied on all.
- **Relays** self-register with a controller's registrar; with the SQL store the
  controllers record each relay's cert key in the signed map, so a relay joins,
  leaves, or re-homes to another controller without touching any client.
- A black-holed controller is caught by gRPC keepalive and ages out of the signed
  map after its stale-TTL; everyone moves to a survivor.

A single-node deployment runs the same code over an embedded `bbolt` store and
synthesizes the cluster map from its own config — no Postgres, no registrar. The
HA deployment and its failover mechanics — the configuration reference for
running controllers over a shared Postgres — are in [`deploy/ha/`](deploy/ha/README.md);
the broader edge-fleet design is in
[`docs/ha-architecture-spec.md`](docs/ha-architecture-spec.md).

---

## 10. Policy & audit

Policy is data, not code (`internal/policy`): roles bound to users and groups,
and allow rules over actions × node-labels × time windows — RBAC for the common
case, ABAC for the expressive ones ("group X may exec on `prod` nodes 09:00–17:00
with approval"). It is evaluated at the controller when a session is brokered and
**re-checked at the agent** before the session is honored.

Audit is append-only and hash-chained JSONL at the controller, so tampering is
evident. Session recordings (asciicast v2) are produced **at the agent** — the
endpoint that has the plaintext — and uploaded, so the record does not depend on
trusting the web proxy.

---

## 11. Threat model (summary)

| Adversary capability | Mitigation |
|---|---|
| Compromised relay | sees only ciphertext + traffic metadata; cannot decrypt or inject |
| Compromised controller | cannot push unsigned binaries (offline-pinned key); cannot exceed policy at the node (agent re-enforces); holds no CA root or signing key |
| Compromised web proxy | limited to web-path sessions; bounded by agent-side enforcement; recording is at the agent; policy can reserve targets for native |
| Stolen client credential file | hardware-bound keys can't be exfiltrated; short TTL; optional WebAuthn presence |
| Stolen long-lived secret | there are none in the data path — credentials are short-TTL; expiry is revocation |
| Malicious binary push | offline-verified signatures, staged rollout, health-gated auto-rollback |
| Revoked user with a live token | authorization is checked separately from the token; suspension takes effect on the next check |
| Detached-session abuse | TTL/idle reaping, re-auth on reattach, policy to forbid on sensitive targets, audited detach/reattach |

The full security review is in [`docs/SECURITY-AUDIT.md`](docs/SECURITY-AUDIT.md).
To report a vulnerability, see [`SECURITY.md`](SECURITY.md).

---

## 12. Operating principles

- **Fail closed, not open.** Losing the controller keeps existing sessions alive but
  refuses new ones once the node cert expires — an outage is never a security
  hole, and never a fleet-wide outage of live work.
- **Reconcile loops over commands.** Version, CA set, and policy are desired state
  the fleet converges toward, so it survives partitions and missed messages.
- **The bootstrap and session host are sacred** — tiny, audited, versioned almost
  never. All churn lives in the worker.
- **Reuse audited components.** `wireguard-go`, pion, `flynn/noise`,
  `x/crypto/ssh`, `miekg/dns`, `coreos/go-oidc` — Geneza's value is the control
  plane, the policy and push models, and the persistence, not reinvented crypto
  or transport.

---

## Platform support

Linux and macOS are the v1 targets for the agent, client, and relay. A Windows
agent is a planned later phase; the OS-specific seams (`Pty`, `KeyStore`,
`ServiceManager`, `Updater`, the data driver) are defined as interfaces so
Windows is a new backend rather than a rearchitecture.

For the original design draft that seeded this system, and for the in-progress
specs that go deeper than this overview, see [`docs/`](docs/README.md).
