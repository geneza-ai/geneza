# Geneza

> Relay-based, identity-aware remote access for server fleets.
> Agents dial out; no inbound ports on managed nodes; relays never see plaintext.

This repository is the implementation of [`ARCHITECTURE.md`](../ARCHITECTURE.md)
(kept at the lab root). It is a Go monorepo producing a small set of static,
CGO-free binaries.

## Binaries

| Binary | Plane | Role |
|---|---|---|
| `geneza-gateway` | control | CA, enrollment, identity brokering, policy, session broker, registry, audit, artifact store, HTTP update endpoints |
| `geneza-relay` | relay | stateless, payload-blind rendezvous (splices two ciphertext streams by token) |
| `geneza-agent` | node | `worker` (control channel + tunnel server + SSH-inside-tunnel) and `session-host` (PTYs + buffers) subcommands, plus `enroll` |
| `geneza-bootstrap` | node | tiny two-stage updater: pins the artifact key, supervises session-host + worker, health-gated atomic swap + rollback |
| `geneza` | client | operator CLI: `login` (OIDC/local), `ls`, `ssh`, `attach`, `exec`, `cp`, `forward`, `sessions`, `admin …` |
| `geneza-sign` | offline | artifact signing tool — runs on the secrets host, **never** on the gateway |

Build: `make proto && make build` → `bin/`. Test: `make test`.

## How the pieces correspond to the architecture

- **Three planes (§3).** Control = `internal/gateway`; relay = `internal/relay`
  (blind byte splice); data = E2E `internal/tunnel` between client and agent.
- **Identity & certs (§5).** `internal/ca` issues short-TTL X.509 with
  `geneza://{node,user,gateway,relay}/<name>` identity URIs and a roles
  extension. Human auth federates to an OIDC IdP (`coreos/go-oidc`); machine
  auth is one-time join tokens today, with the **OpenStack instance-identity
  seam** stubbed in `internal/gateway/enroll.go` (see
  [`docs/openstack-integration.md`](docs/openstack-integration.md)).
  **Expiry is revocation**: no CRLs.
- **Transport (§6).** Control channel = gRPC/mTLS (`api/proto`,
  `internal/pb`). Handshake = **Noise IK** (`flynn/noise`,
  `internal/tunnel`). Session protocol = the **SSH connection layer**
  (`x/crypto/ssh`) *inside* the tunnel — channels carry shell/exec/sftp/forward,
  identity already established by Noise + the signed grant.
- **Agent-side enforcement (§5, §12).** Every session rides a gateway-signed
  `SessionGrant` (`internal/types`). The agent independently verifies the
  signature against its trusted grant keys, checks node binding / scope /
  expiry, and requires the tunnel's remote Noise key to equal the grant's —
  so a compromised gateway cannot grant access the agent will honor blindly.
- **Policy (§5).** `internal/policy` — roles bound to users/groups, allow rules
  over actions × node-labels × time windows (RBAC + ABAC), `require_native` to
  reserve sensitive targets for the true-E2E client. Evaluated at the gateway,
  re-checked at the agent.
- **Session persistence (§8).** `internal/sessionhost` is a separate, stable
  process that owns PTYs and **always drains** them; two buffer layers
  (vt10x screen snapshot + scrollback ring), sequence-numbered I/O with
  ack/replay, re-auth on reattach, and guardrails (caps, TTL reaping, zeroize).
  Survives client crash, roaming, and CLI↔web hand-off — not node reboot.
- **Self-update (§9).** `geneza-sign` signs each worker offline; the bootstrap
  verifies against a **pinned** key (not gateway TLS), does atomic swap +
  health-gated rollback, and treats version as **desired state** the gateway
  stages (canary → stable) with a promotion health gate. The session host is
  never restarted by an update, so live shells survive.
- **Audit (§13).** Append-only, hash-chained JSONL at the gateway; recordings
  (asciicast v2) are produced **at the agent** and uploaded.

## Trust boundaries enforced in code

- Relay parses exactly one hello frame, then copies bytes; it logs only
  metadata (token prefix, addrs, volume) — never payload.
- The gateway holds neither the CA root key (kept aside by `ca.Init`) nor the
  artifact signing key (offline, `geneza-sign`).
- gRPC auth interceptors gate every RPC by verified cert identity kind/role;
  node RPCs additionally bind to the calling node's identity.

## Lab deployment

The `geneza1` lab (`/root/labs/geneza1/`) deploys this to three VMs on the
Proxmox host and runs an end-to-end battery. See that lab's `CLAUDE.md`.

## Layout

```
api/proto/geneza/v1/   control.proto, sessionhost.proto (the contracts)
internal/pb/           generated gRPC/protobuf
internal/types/        signed envelopes, SessionGrant, ClusterConfig, Manifest, keys
internal/wire/         length-prefixed frames + relay rendezvous protocol
internal/tunnel/       Noise IK encrypted tunnel (net.Conn)
internal/ca/           two-tier CA, identity URIs, issuance, peer-identity extraction
internal/policy/       policy-as-data engine (RBAC/ABAC)
internal/attachproto/  session-host attach framing (shared by client + agent)
internal/gateway/      control plane
internal/relay/        rendezvous relay
internal/agentd/       agent worker
internal/sessionhost/  PTY/buffer host (persistence)
internal/client/       operator CLI
internal/update/       updater library (installer, supervisor, health gate)
cmd/<binary>/          thin mains
docs/                  OpenStack integration seam
```
