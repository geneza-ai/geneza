# Managed domain, trusted certificates, and public funnel

Geneza gives every workspace a real, publicly-trusted DNS name and TLS without
the operator running a CA, a public web server, or a certificate dance. It is
Geneza's answer to Tailscale `ts.net` (trusted certs on overlay-only names) and
Tailscale Funnel (deliberate public exposure of one service).

The design has two distinct exposure profiles. They look similar but have
opposite trust boundaries, and the certificate strategy follows the boundary —
not the name.

## 1. Two profiles

### 1a. Managed domain (VPN-only)

A deployment configures **one or more** operator-owned public base domains (each
bound to a named DNS-01 provider — see §4). A workspace admin **reserves** one or
more subdomain **labels** under any configured base domain — their own choice, if
the label is free — up to **3 reservations per workspace** (tunable). Each
reservation defines a zone:

```
<label>.<base>            # the reserved workspace zone (admin-chosen label)
<machine>.<label>.<base>  # a machine in it
<service>.<label>.<base>  # a service in it
```

If an admin reserves without naming a label, it falls back to a stable derived
default `w-<token>` (see §4). These names resolve **only on the Geneza VPN
resolver** (`100.64.0.53`), to overlay IPs — exactly like the internal `*.geneza`
zone does today. They are not in public DNS. A laptop off the VPN cannot resolve
them.

The certificate is a **wildcard per reservation**: `*.<label>.<base>` (plus the
apex `<label>.<base>`). One cert covers every machine and service under that
label, so issuance scales with the number of reservations, not machines. Because
only the wildcard label is ever submitted to a public CA, the **individual
machine names never appear in Certificate Transparency logs** — a privacy
property that matches the "these names only exist on your VPN" promise.

Reservations are globally unique (first to reserve a `(base, label)` owns it) and
persisted at workspace level; the controller enforces uniqueness and the per-
workspace cap atomically, so two concurrent claims can't both win.

The wildcard **private key is sealed to that workspace's own agents** and never
leaves the tenant. An agent terminates TLS for any `*.w-<token>` name it serves
on the overlay. This is safe: the agents are the tenant's own machines, the key
is the tenant's, and the blast radius of a compromised agent is within the
tenant that already owns the data.

The wildcard key **never goes to a relay.** Relays are shared, public-facing
infrastructure; see §1b.

### 1b. Funnel (public internet)

A workspace admin may additionally expose **one specific service** to the public
internet. Public DNS (the real authoritative nameserver) points the funnel
hostname at a bucket of relays. Each relay terminates public TLS and reverse-
proxies the request into the workspace over the existing overlay tunnel. This is
the one place Geneza's relays stop being payload-blind — by explicit, per-service
opt-in only.

Funnel does **not** use the workspace wildcard. The controller issues a **narrow
leaf certificate for the single funnel hostname**, sealed to the specific relays
serving it, with a short TTL. Rationale: a relay is shared public infrastructure;
if one is compromised, the attacker may impersonate only that one funnel
hostname for as long as the short-lived key is valid — never the whole workspace,
never the VPN-only names, never another tenant. The funnel hostname is meant to
be public, so its presence in CT logs is expected and harmless.

| | Managed domain (VPN-only) | Funnel (public) |
|---|---|---|
| Resolves where | VPN resolver only, to overlay IP | public DNS, to relay pool |
| Certificate | wildcard `*.w-<token>` per workspace | narrow leaf per funnel hostname |
| Private key lives on | the tenant's own agents | the serving relays (sealed, short-TTL) |
| TLS terminated by | the workspace's machine/agent | the relay (payload-visible, opt-in) |
| In CT logs | only the wildcard label | the funnel hostname (expected) |

## 2. Components and where they run

```
                         ┌─────────────────────────────────────┐
                         │             controller                  │
  public DNS provider    │  webpki issuer (lego, DNS-01)        │
  (Cloudflare/R53/...)   │   - mints wildcard per workspace     │
        ▲   ▲            │   - mints narrow leaf per funnel host │
        │   │ _acme-     │  reconcile ticker (renew, leader-only)│
        │   │ challenge  │  cert store (blobStore: fs | s3)     │
        │   │ TXT (brief)│  sealed distribution (per recipient) │
        └───┘            └───────┬───────────────────┬──────────┘
                                 │ agent control      │ relay control (new mTLS RPC)
                                 ▼                     ▼
                   ┌──────────────────┐    ┌────────────────────────┐
                   │  agent (tenant)  │    │  relay (shared/public) │
                   │  holds wildcard  │    │  holds narrow funnel    │
                   │  key, serves TLS │    │  leaf key, terminates   │
                   │  on overlay      │    │  public TLS, proxies in │
                   └──────────────────┘    └────────────────────────┘
```

The only component that talks to the public CA and the public DNS provider is the
**controller**. Agents and relays only ever receive sealed cert material; they never
hold ACME accounts or DNS credentials.

## 3. Technology choices (decisional-panel synthesis)

- **ACME engine: `github.com/go-acme/lego/v4`**, used as a protocol library, not
  a lifecycle daemon. Geneza already owns the lifecycle machinery lego's
  alternatives (certmagic) would duplicate: a leader-elected reconcile ticker
  (`store.TryReconcileLock`), a pluggable `blobStore`, an HA SQL store for
  locking, and signed-map propagation. lego supplies correct DNS-01 wildcard
  issuance, ACME ARI renewal hints, and a large provider catalog; Geneza drives
  the renewal loop.
- **DNS-01 providers: lego's `challenge.Provider` set, imported per provider.**
  Only `providers/dns/cloudflare` is imported day-one so the controller binary does
  not pull aws-sdk-go until Route53 ships. New providers are an import + a config
  case, nothing more. The selector mirrors `StorageConfig`/`newBlobStore`.
- **Cert issuer is pluggable** (Let's Encrypt now, ZeroSSL later): a CA directory
  URL + optional EAB on the lego client. No code change to add a CA.
- **Funnel proxy: standard library only** — a `crypto/tls` `GetCertificate`
  SNI-router selecting the right narrow cert, plus `net/http/httputil.ReverseProxy`
  for HTTP and a raw byte splice for non-HTTP. No Caddy/Traefik embed: that would
  put a second cert/config/lifecycle system inside the relay, whose entire virtue
  is being small and auditable. The relay never issues certs — the controller does —
  so the proxy only needs hot cert swap, which is one `atomic.Pointer`.
- **Cert distribution: a dedicated mTLS RPC, never the broadcast signed map.** The
  cluster map is signed (integrity) but not confidential and is fanned to all
  relays; private keys must be sealed to one recipient and pulled over mTLS.

## 4. Naming, domains, and providers

- **Multiple base domains.** `managed_domain.domains` is a list, each entry a
  `{base, dns_provider}`. The base is an operator-owned public domain (e.g.
  `geneza.app`); `dns_provider` references a provider by name.
- **DNS-01 providers by name.** `managed_domain.dns_providers` is a map keyed by
  name (e.g. `cf-main`), each a `webpki.DNS01Config`. Domains reference providers
  by that name, so different domains can live on different providers (and even
  different DNS accounts) under one ACME account. Only the selected provider's
  lego subpackage is imported.
- **Shared ACME account.** `managed_domain.acme` is one `webpki.Account` (email,
  staging/production, optional EAB) for all domains; the account key is persisted
  once under the data dir.
- **Admin-chosen labels, with a derived default.** A reservation's label is the
  admin's choice (validated as an RFC-1035 label). When omitted it defaults to
  `w-<token>`, derived from the stable workspace id via FNV-1a/base32 (mirrors
  `vniForWorkspace`) — DNS-safe, stable across renames, and it doesn't leak the
  human workspace name into public DNS / CT.
- **Per-workspace cap:** `maxWorkspaceSubdomains` (3 today), enforced atomically.
- Machine/service label under a zone: existing `dnsLabel()` sanitizer.

## 5. Issuance flow (controller)

1. Reconcile ticker (leader-only) computes the desired cert set: one wildcard per
   workspace that has the feature enabled, plus one narrow leaf per active funnel
   binding.
2. For each cert missing or within the renewal window, the issuer runs lego with
   the configured DNS-01 provider:
   a. lego asks the provider to publish `_acme-challenge.<name>` TXT to the
      **real public authoritative nameserver**.
   b. The CA validates; lego tears the TXT down.
   c. The signed cert + key are written to the cert store (`blobStore`).
3. Renewal is driven at ~1/3 of remaining lifetime, honoring ACME ARI when the CA
   provides it, with jitter to avoid fleet-synchronized stampedes.
4. All issuance/renewal is leader-only under `TryReconcileLock`, so two HA
   controllers never double-issue and burn duplicate-cert rate limit.

**Test/CI safety:** the issuer defaults to the Let's Encrypt **staging**
directory; the production directory is opt-in per deployment. The e2e battery
must never touch the production rate-limit bucket.

## 6. Distribution and serving

- **To agents (wildcard):** the workspace wildcard cert+key is sealed to each
  participating agent's node key and delivered over the existing agent control
  channel. The agent stores it under its data dir and serves TLS for `*.w-<token>`
  names. Renewal re-pushes; the agent hot-swaps.
- **To relays (funnel leaf):** a new server-streaming mTLS RPC on the relay
  registry delivers, per relay, only the funnel leaf certs that relay serves,
  each sealed to that relay's node key. The relay holds them in memory, selects
  by SNI via `tls.Config.GetCertificate` reading an `atomic.Pointer`, and
  **fails closed** (503 / no cert) if it cannot refresh before `notAfter`.
- Cert epoch: each cert carries a monotonic epoch + sha256 so a recipient can
  detect a missed update and pull on reconnect.

## 7. Funnel proxy (relay)

- A separate public listener (default `:443`), structurally distinct from the
  payload-blind L4 splice path, so a config bug can never route a blind tunnel
  through the terminating path.
- `tls.Config.GetCertificate` selects the funnel leaf by SNI.
- HTTP services: `httputil.ReverseProxy` to the overlay target (handles
  WebSocket/`101` upgrades). Raw TCP services: SNI-routed byte splice, no proxy.
- Reuses the relay's existing drain/active-count gate: config and cert swaps
  quiesce new connections and drain active ones through the battle-tested path.

### 7b. Funnel data path — agent back-connection (decisional-panel verdict)

The relay terminates public TLS but is NOT an overlay member and holds NO overlay
key — so it reaches the target service via an **agent-initiated back-connection**,
not by joining the overlay:

1. The controller pushes the funnel binding to the **target agent** over the existing
   `NodeControl` stream (hostname H → local target T, + the relay pool to register
   with).
2. The agent **dials out** to the pool relays (preserving no-inbound) and registers
   a persistent funnel connection keyed by H — reusing the relay's control-mux /
   rendezvous framing.
3. On a public TLS connection with SNI=H, the relay terminates TLS and **splices
   the plaintext byte stream over the agent's back-connection** (or signals the
   agent to dial a fresh per-request data conn, reusing the token→splice path).
4. The **agent** — not the relay — proxies that stream to the pinned local target
   T. The relay never learns an overlay address/route/key.

Why (rejected alternatives): a relay joining the overlay (option B) would put a
live WireGuard key into the tenant's private network on a public, multi-tenant
box — popping one relay would expose the *whole* workspace overlay, not just the
funneled service. Option A keeps a popped relay's reach to exactly the one service
the operator chose to publish. **Guardrails:** relay never originates the
agent connection; no overlay primitives on the relay ever; the agent pins T (the
relay supplies only bytes + hostname); the relay→agent leg is mTLS/Noise; and the
controller registers the agent on a relay *before* that relay enters public DNS
(register-then-advertise), tearing the back-connection on drain.

### 7a. Drain, public-DNS reconcile, and relay failover

Funnel's public DNS for a hostname is an A/AAAA record **set** over the *pool* of
relays serving it (the controller owns these records via the same DNS provider used
for DNS-01, but as durable records, not transient TXT). A **funnel-DNS
reconciler** on the controller (leader-only, on the managed-cert controller tick —
`internal/controller/funneldns.go`, IMPLEMENTED) watches the relay presence (which
carries `RelayNode.Draining`, a `FunnelIP`, and is heartbeat-reaped) and keeps
each hostname's public A-record set pointed at only **healthy, non-draining**
relays. It fails the set over on drain/death/staleness, withdraws it on release,
and never blackholes (an empty healthy set leaves the last good record). A-records
are written through a `webpki.RecordManager`: the **`exec`** provider (a script:
`set-a`/`remove-a`) ships and is the testable default; native cloudflare
A-records are a follow (a cloudflare deployment manages funnel A-records
statically until then). Behavior:

- **Drain (rollout wave):** a draining relay is removed from the record set, so
  new public connections resolve to relays **outside** the update batch, while the
  draining relay bleeds its existing connections via the active-count gate, then
  updates. Drain = stop being advertised, not drop traffic.
- **Death (reap):** a relay whose heartbeat lapses is pulled from the map and the
  record set the same way — survivors absorb the traffic. This is the controller
  handling relay failover.
- **Why it's seamless:** the funnel narrow-leaf cert is distributed to the
  **whole pool**, so a relay traffic shifts to already holds the cert and
  terminates TLS identically.
- **Caveat:** public DNS is eventually-consistent, so funnel records use a **low
  TTL** (~30–60s) and drains stay gradual; a single-node controller remains a
  control-plane SPOF (HA controllers are a separate roadmap), but relay data-plane
  failover does not depend on controller HA.

## 8. Security red lines (non-negotiable)

1. A relay **never** holds a workspace wildcard private key — only narrow,
   per-funnel-hostname leaf keys.
2. A private key **never** travels in the broadcast signed map — it is sealed to
   one recipient's node key and pulled over mTLS.
3. Funnel is **per-service, default-deny, controller-authorized** — a relay can
   never self-grant termination; the blind splice runs on a separate listener
   that cannot be handed a key.
4. The DNS-01 credential is **scoped to the delegated managed zone, DNS-edit
   only** — never account-wide. CAA on the zone pins issuance to the expected
   ACME account.
5. No public **leaf** cert is ever issued for a VPN-only internal hostname —
   internal names are covered only by the controller-issued, agent-sealed wildcard,
   keeping individual names out of CT.
6. Funnel keys are **short-TTL and resident only while actively served**.

## 9. Rate limits and scale

Let's Encrypt caps issuance at ~50 new certs per **registered domain** per week,
where "registered domain" is the eTLD+1 as defined by the **Public Suffix List
(PSL)**. The design keeps a deployment under that cap on several axes, in order
of leverage:

1. **Wildcard-per-workspace** is the biggest reduction: one cert covers every
   machine and service in a workspace, so issuance scales with #workspaces, not
   #machines. (Tailscale issues per-node; Geneza does not.) Renewed quarterly,
   one workspace consumes ~0.1 certs/week.
2. **PSL the managed base domain (primary scale mechanism for a managed/SaaS
   deployment).** Adding the base domain (e.g. `geneza.app`) to the Public Suffix
   List makes each workspace zone `w-<token>.geneza.app` its OWN registered
   domain, so every workspace gets an independent 50/week bucket — the exact trick
   `ts.net`, `app.netlify`, `app.vercel`, and `herokuapp` use. With wildcard-per-
   workspace on top, a PSL-listed deployment effectively never hits the limit.
   This is a one-time PR to `publicsuffix/list`; it has propagation lag and means
   the base domain itself can't set cross-subdomain cookies (fine here).
3. **Staging by default** keeps CI/e2e off the production bucket entirely
   (`Config.Production` defaults false → LE staging directory).
4. **ARI-driven renewal at ~1/3 lifetime + jitter** so renewals never stampede,
   and **cached issuance** so a valid cert is never re-minted (which also avoids
   the separate duplicate-certificate limit of 5 per identical name-set per week —
   the one limit the PSL does not relax).

For a **self-hosted** deployment on an operator's own arbitrary domain (not PSL-
listed), the levers are: wildcard-per-workspace (already sufficient for hundreds
of workspaces on one domain), the LE rate-limit-increase request form for large
fleets, sharding workspaces across multiple base domains, or pointing the
pluggable issuer at a different ACME CA. The config and issuer therefore accept a
**list** of base domains so sharding is a config change, not a redesign, and a
controller-side issuance rate governor (token bucket per registered domain) can cap
Geneza below the CA's limit and surface pressure as a metric instead of hitting a
hard CA lockout.

## 10. Build phases

1. **webpki foundation** — config (pluggable issuer + DNS-01 provider, mirroring
   `StorageConfig`), the lego DNS-01 wildcard issuer, cert store, the leader-only
   renewal ticker, staging-by-default. Unit-tested with a mock ACME/DNS-01.
2. **Workspace wildcard distribution** — per-workspace enablement, seal-to-agent
   delivery over the agent control channel, agent-side serve + hot swap.
3. **Funnel** — funnel binding model, public DNS record management, narrow-leaf
   issuance, the new relay mTLS cert RPC, the relay public proxy listener.
4. **Console + CLI** — enable managed domain per workspace, list certs, create a
   funnel exposure, surface state.
5. **e2e** — issuance against the ACME staging endpoint (or pebble), VPN-only
   resolution proof, funnel reachability proof, renewal + hot-swap proof.
</content>
