# Policy-aware DNS (the miekg/dns library) — design + phased plan

Status: **design approved (2026-06-12), not yet implemented.** Decisional-agent
output. Goal: resolve **machine names → overlay IPs** inside the VPN (later:
expose services under DNS), policy-aware, per tenant; the VPN client switches its
system resolver to Geneza's tenant DNS.

## Layer decision: run the resolver in the GATEWAY (NOT the relay)
The gateway is the only layer that already holds all four inputs a policy-aware
resolver needs: the authenticated caller (`ca.Identity{Name,Roles,Workspace}`),
the policy engine, the authoritative name records (`NodeRecord`, advertised
`types.Service`), and the overlay IP allocator. **The relay is rejected outright**:
it is provably payload-blind (`relay.go splice()`: "not a single byte is parsed —
only copied"), has no identity/policy/records, and is designed to run on
untrusted infra. Putting a policy-aware resolver there would collapse the
system's central security claim. Agents are also rejected (they only know
themselves; a fleet directory + policy on every agent reintroduces the
confidentiality-SPOF the architecture avoids).

## Embedding: the `github.com/miekg/dns` LIBRARY behind a `Resolver` interface
Geneza uses the **miekg/dns library** (the standard Go wire-format DNS package) —
NOT the CoreDNS project/server. A/AAAA/SRV/PTR over UDP+TCP, CGO-free, lean. The
`Resolver`/`Answer` interface keeps the door open to richer behavior
(`forward`/`cache`/`dot`/`doh`) later without adopting CoreDNS-the-project.
  Mirrors how `policy.Engine` is an interface so OPA/Cedar can replace it.

## Two query paths (both already-authenticated)
The VPN data path is a raw Noise tunnel client↔node, NOT client↔gateway, so:
1. **Direct mTLS `Resolve` RPC (Phase 1, build first).** The client is already
   on an authenticated mTLS gRPC channel to the gateway; add `UserAPI.Resolve`
   (identity via `identityFrom(ctx)` — unambiguous). Works before/independent of
   an active VPN session.
2. **In-overlay resolver IP `100.64.0.53` (Phase 1.5, MagicDNS transparency).**
   Reserve `.53` from the session CGNAT block. Client points its OS resolver at
   it; packets go over the Noise tunnel to the node, which **hairpins**
   `100.64.0.53:53` up its existing mTLS control stream to the gateway resolver
   (attributed to the session grant's User/Roles). Keeps "no inbound ports" +
   relay blindness intact.

## Policy-aware flow (DNS = a projection of policy)
identity → strip per-tenant zone → `Store.FindNode`/advertised services → for
each candidate `engine.Evaluate(policy.Input{User,Roles,NodeID,NodeLabels,
Action,Service,ServiceKind,ServiceLabels,ClientPath:native,Now})` → **deny ⇒
NXDOMAIN** (not NODATA/REFUSED — no enumeration oracle, mirrors `resolveAttach`'s
opaque denial). The set of names a caller can resolve == the set they can connect
to. Share one `visibleNodes(ident)` helper and back-fill the (currently
un-filtered) `ListNodes`/`ListServices` reads.

## Naming + record model
- Zone **`<machine>.<workspace>.geneza`** (tenant TLD swappable via config). The
  workspace label IS the DNS isolation boundary — converges with multitenancy.
- **A/AAAA** → the machine's **stable per-node overlay IP** (NEW IPAM concept:
  today only clients get session overlay IPs; assign each node a stable overlay
  /32 at approval — `NodeRecord.OverlayIP`). **PTR** reverse zone. **Services
  (Phase 2)**: `<service>.<machine>.<workspace>.geneza` SRV (+ convenience A),
  policy-gated by kind/labels; consumed by `geneza connect` so the broker still
  derives the real target server-side. Short TTLs (5–30s).

## Client resolver switch (`geneza vpn`, Linux first)
In `runVPN` (`cmd/geneza/vpn.go`), alongside the TUN/route setup + `cleanups`:
- **systemd-resolved (default):** `resolvectl dns <tun> 100.64.0.53` +
  `resolvectl domain <tun> ~<workspace>.geneza` (split DNS — only tenant names go
  to Geneza). Teardown = `resolvectl revert <tun>`.
- **plain resolv.conf:** atomic backup + rewrite, restore on teardown.
- Add `100.64.0.53/32` route via the TUN; search domain = tenant zone (MagicDNS).
- macOS (`scutil`/`/etc/resolver/`) compile-only this phase; Windows unsupported.

## Phased file-level plan
- **Phase 0 — IPAM:** `NodeRecord.OverlayIP` + stable per-node alloc in
  `overlay.go` (reserve `.53`); assign at approval.
- **Phase 1 — machine-name→IP:** new `internal/dns` (`resolver.go` miekg-based +
  `ServeDNS` seam, `zone.go` name parse); `internal/gateway/dns.go` (wire
  store/registry/policy + `visibleNodes`); `UserAPI.Resolve` RPC; client
  `internal/vpn/resolver_linux.go` + `cmd/geneza/vpn.go`; e2e: `nslookup`
  resolves over VPN, denied machine ⇒ NXDOMAIN, teardown restores resolver.
- **IMPLEMENTED instead (supersedes the old "Phase 1.5 hairpin"):** in-network DNS
  is resolved LOCALLY at each agent — NOT by querying the gateway. The gateway
  PUSHES each node its policy-filtered per-Network zone in `NetworkSpec.dns_records`;
  the agent runs the miekg/dns resolver at `100.64.0.53` answering from pushed data
  (zero per-query gateway dependency, offline-safe). The old per-query
  `UserAPI.ResolveDNS` RPC + `DNSQuery`/`DNSResponse` were REMOVED. See
  `internal/agentd/dnsserver.go` + memory `geneza-roadmap-dns-tenancy`.
- **Phase 2 — services:** SRV + service-A in the resolver; `geneza connect`
  consumes service names.

Tenant-shaped from day one: reserve `policy.Input.Workspace` + the zone label now
so DNS and multitenancy converge without rework. Critical files:
`internal/gateway/broker.go` (the exact policy.Input to mirror), `internal/policy`,
`internal/gateway/overlay.go`+`store.go` (stable overlay IPs), `cmd/geneza/vpn.go`+
`internal/vpn/tun_linux.go` (resolver switch), `internal/agentd/vpn.go` (hairpin).
