# Geneza

**Identity-aware remote access for server fleets — without opening a single inbound port.**

[![CI](https://github.com/geneza-ai/geneza/actions/workflows/ci.yml/badge.svg)](https://github.com/geneza-ai/geneza/actions/workflows/ci.yml)
[![Binaries](https://github.com/geneza-ai/geneza/actions/workflows/binaries.yml/badge.svg)](https://github.com/geneza-ai/geneza/actions/workflows/binaries.yml)
[![Go](https://img.shields.io/badge/go-1.26-00ADD8?logo=go)](go.mod)
[![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-blue)](LICENSE)

Geneza lets operators reach their nodes over SSH, exec, file transfer, and
port-forwarding the way they always have — but the nodes never listen for
inbound connections. Every agent dials *out* to a control plane. Sessions are
brokered through relays that only ever see ciphertext, tied to a short-lived
identity, recorded, and torn down when the credential expires.

Think of it as the parts of Teleport, Tailscale, and Boundary that matter for
fleet access, built as one small set of static Go binaries you can self-host.

![Geneza architecture: an operator and IdP up top, a self-hosted control plane of
a payload-blind relay and a controller in the middle, and a fleet of agents that dial
out from the bottom — with the end-to-end-encrypted session flowing down through
the blind relay and the agents' control streams dialing up to the controller.](docs/architecture.png)

---

## Why it exists

Most fleet-access tooling makes you choose between *reachable* and *exposed*.
Bastions, VPNs, and open SSH ports all put something on the network that an
attacker can find and knock on. Geneza's premise is that managed nodes should
have **no listening socket at all** — the agent is always the dialer — and that
the thing brokering access should never be able to read the traffic it brokers.

That gives you a few properties that are hard to get otherwise:

- **No inbound attack surface on nodes.** Agents dial out. There is nothing to
  port-scan, nothing to firewall-except, nothing to expose.
- **Relays you can run anywhere.** A relay forwards encrypted frames and parses
  exactly one handshake byte-string before it goes blind. Run them on cheap or
  untrusted infrastructure — a compromised relay sees timing and volume, never
  plaintext.
- **Expiry is revocation.** Credentials are short-lived X.509 certs minted per
  login and per session. There are no CRLs to distribute; you stop trusting a
  principal by not re-issuing.
- **The node has the final say.** Every session carries a controller-signed grant,
  but the agent independently verifies the signature, the scope, the node
  binding, and the peer's handshake key. A compromised controller cannot hand out
  access the agent will honor.
- **Sessions that survive the network.** The PTY and its output live on the
  agent, decoupled from any one connection, so a shell survives laptop sleep,
  Wi-Fi→cellular roaming, relay failover, and CLI↔browser hand-off.

The full design rationale and threat model live in
[`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## What you can do with it

- `geneza ssh node` / `geneza exec node -- cmd` — interactive shells and remote
  exec, with the local terminal in raw mode so it feels exactly like `ssh`.
- `geneza cp`, `geneza forward` — SFTP-backed file transfer and TCP
  port-forwarding, carried as channels inside the same tunnel.
- **A browser console** — an xterm.js terminal, fleet and session dashboards, a
  policy view, and live metrics, served by the controller. Zero install.
- **A desktop app** — the same console in a native window, but the shell runs the
  same direct end-to-end tunnel as the CLI instead of the proxied browser path.
- **Overlay networking** — opt-in per-network WireGuard overlays with a
  policy-aware resolver, so nodes can address each other by name over an
  encrypted mesh.
- **A self-updating fleet** — the controller stages signed binary rollouts to agents
  (canary → stable) with health-gated automatic rollback.

---

## Quickstart

You need Docker with the Compose v2 plugin and a Linux host. This brings up a
controller and one relay, then enrolls a node.

```bash
curl -fsSL https://raw.githubusercontent.com/geneza-ai/geneza/wip/deploy/compose/install.sh \
  | sudo bash         # choose controller+relay; it prints an admin password
```

Point the client at the break-glass admin identity the installer created and mint
an enrollment code:

```bash
export GENEZA_HOME=/opt/geneza/generated
geneza --profile admin node enroll --labels env=lab --ttl 1h
```

On any Linux box you want to manage, run the installer with that token (the agent
dials out — open no ports on it):

```bash
curl -fsSL https://raw.githubusercontent.com/geneza-ai/geneza/wip/deploy/install/install-agent.sh \
  | sudo bash -s -- gzk_XXXX --controller <controller-host>:7401 --labels env=lab

geneza --profile admin node approve <name>
geneza --profile admin ssh <name>
```

The complete tutorial — admin setup, enrolling machines, and **OpenStack
zero-touch VM enrollment** — is in [`INSTALL.md`](INSTALL.md). The installer and
its roles are documented in [`deploy/compose/`](deploy/compose/README.md);
high-availability topologies in [`deploy/ha/`](deploy/ha/README.md).

---

## Building from source

A Go 1.26 toolchain and `protoc` (with the Go plugins) are all you need. The
binaries are static and CGO-free.

```bash
make proto       # regenerate gRPC/protobuf from api/proto
make build       # -> bin/
make test        # go test ./...
```

| Binary | Plane | Role |
|---|---|---|
| `geneza` | client | operator CLI: `login`, `ls`, `ssh`, `exec`, `cp`, `forward`, `sessions`, `admin …` |
| `geneza-controller` | control | CA, enrollment, identity broker, policy, session broker, registry, audit, update endpoints |
| `geneza-relay` | relay | stateless, payload-blind rendezvous + TURN floor; splices two ciphertext streams |
| `geneza-agent` | node | `worker` (control channel, tunnel server, SSH-inside-tunnel) and `session-host` (PTYs, buffers), plus `enroll` |
| `geneza-bootstrap` | node | tiny supervisor/updater: pins the artifact key, health-gated atomic swap + rollback |
| `geneza-sign` | offline | signs release artifacts — runs on the secrets host, never on a controller |
| `geneza-trust` | offline | signs the fleet trust set (`ClusterConfig`) with the offline trust key, kept off every controller |

The browser console (`web/`) and desktop app (`desktop/`) build separately; see
their READMEs.

---

## How it fits together

Three planes, kept strictly apart:

- **Control plane** (`internal/controller`) brokers and authorizes; it never carries
  session bytes. It runs as a stateless tier over a replicated store, so it goes
  HA without leader election — any controller can serve any request and redirects to
  the one that owns a given node.
- **Relay plane** (`internal/relay`) rendezvouses two endpoints that already
  share keys and forwards ciphertext. It also accepts an agent's long-lived
  control stream and forwards it blindly to the controller, so an agent needs only
  one outbound connection through a relay it doesn't have to trust.
- **Data plane** is end-to-end between client and agent. Native clients try a
  direct peer-to-peer path first (ICE/STUN/TURN, `internal/sessionconn`) and fall
  back to a relay floor; the session itself is a Noise IK tunnel
  (`internal/tunnel`) with the SSH connection protocol running *inside* it
  (`internal/agentd`). The optional WireGuard overlay (`internal/vpn`) is a
  separate, userspace, GSO-accelerated data path for machine-to-machine traffic.

Identity, certificates, policy, persistence, and the self-update model are each
covered in [`ARCHITECTURE.md`](ARCHITECTURE.md); the design notes and specs that
back them are indexed in [`docs/`](docs/README.md).

### Repository layout

```
api/proto/geneza/v1/   control + session-host gRPC contracts
internal/pb/           generated gRPC/protobuf
internal/types/        signed envelopes — SessionGrant, ClusterConfig, manifests, keys
internal/wire/         length-prefixed frames + the relay rendezvous protocol
internal/tunnel/       Noise IK encrypted tunnel (a net.Conn)
internal/sessionconn/  per-session p2p (pion ICE) transport, relay floor fallback
internal/icewire/      shared ICE/STUN endpoint helpers
internal/vpn/          userspace WireGuard overlay data plane (UDP GSO/GRO)
internal/dns/          embedded policy-aware resolver for the overlay
internal/ca/           two-tier CA, identity URIs, issuance, peer-identity extraction
internal/policy/       policy-as-data engine (RBAC/ABAC)
internal/controller/      control plane — broker, auth, console, registries, audit
internal/agentd/       agent worker
internal/sessionhost/  PTY/buffer host (session persistence)
internal/attachproto/  session-host attach framing (shared by client + agent)
internal/client/       operator CLI internals
internal/clientcore/   UI-agnostic session engine shared by the CLI and desktop
internal/attachbridge/ desktop ↔ session-host glue
internal/selfupdate/   in-place binary self-update
internal/releasetrust/ offline-rooted release signature chain
internal/update/        agent updater (installer, supervisor, health gate)
cmd/<binary>/          thin mains
deploy/                compose installer, Dockerfiles, host installers, release archives
web/                   React + xterm.js browser console
desktop/               Wails desktop app (own nested module)
docs/                  architecture deep-dives, specs, and design notes
```

---

## Trust boundaries, enforced in code

- The relay reads one hello frame, then copies bytes. It logs metadata — token
  prefix, addresses, byte counts — and never payload.
- The controller holds neither the CA root key (kept aside at `ca.Init`) nor the
  artifact signing key (offline, in `geneza-sign` / `geneza-trust`).
- gRPC interceptors gate every RPC by verified certificate identity and role;
  node RPCs additionally bind to the calling node's own identity.
- Agents verify each session grant's signature, scope, node binding, and the
  peer's Noise key before honoring it — independently of the controller's TLS.

Reporting a vulnerability: see [`SECURITY.md`](SECURITY.md).

---

## Contributing

Build instructions, the proto workflow, coding conventions, and how changes are
reviewed are in [`CONTRIBUTING.md`](CONTRIBUTING.md). Issues and pull requests are
welcome.

## License

Geneza is **source-available** under the
[Business Source License 1.1](LICENSE). In short: read the source, run it
internally in production, and modify it freely — but you may not offer Geneza to
third parties as a hosted or managed service that competes with the licensor's
own offering. On each release's Change Date the license converts to Apache-2.0.
See [`LICENSE`](LICENSE) for the exact terms.
