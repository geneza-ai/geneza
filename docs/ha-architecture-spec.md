# Geneza Global-HA Architecture — Decisional Spec

> **⚠️ SUPERSEDED.** The CockroachDB / regional-cell / per-cell-CA / Raft design in
> this document is replaced by the Postgres-flat architecture in [`ha.md`](ha.md):
> one managed Postgres, a flat leaderless controller pool, `LISTEN/NOTIFY` as the bus,
> and stateless relays. Kept for historical context and for the security-MUST
> catalogue, most of which still applies. Where this doc and `ha.md` disagree,
> `ha.md` wins.

> **Provenance.** Synthesized from a 10-agent decisional design workflow
> (`geneza-ha-global-architecture`, runId `wf_f530415c-5dc`): 3 architects
> (managed-stateless-gw / self-contained-raft / regional-cells-edge) → 3 judges
> (correctness-and-consistency / operability-and-self-hostability /
> zero-trust-and-blast-radius) → 3 red-teamers (split-brain & state consistency /
> multi-controller CA & trust / DERP & control-stream at scale) → 1 synthesizer.
> All agents read the live tree (store.go, registry.go, broker.go, continuousauthz.go,
> disco.go, auth.go, ca.go, grant.go, turncreds.go, turnserver.go, control.proto).

## Decision summary

**Winning base: Design 1 — managed distributed SQL (CockroachDB/Postgres via pgx) +
NATS control-stream bus + Tailscale-style DERP map**, with the two cell-oriented forks
(F5 sharded sweep, F6 regional cells) grafted in from Design 3.

| Design | correctness | operability | zero-trust | verdict |
|---|---|---|---|---|
| 1 · managed SQL + NATS (**chosen base**) | 9 | 7.5 | 9 | |
| 2 · embedded Raft | 7 | 7 | 7 | |
| 3 · regional cells (**F5/F6 grafted**) | 7 | 7.5 | 8 | |

### Best decision per fork (judge consensus)

| Fork | Decision |
|---|---|
| **F1 DERP fleet** | Signed DERP map inside the already-signed `ClusterConfig` + client-side STUN/RTT closest-pick (Tailscale `netcheck`); regionally sharded so relay churn doesn't rev the map per-relay; **no relay-to-relay mesh** (ICE picks a shared relay candidate from both peers' home regions); **per-region** TURN secret with overlap-window rotation; relays heartbeat to a **per-region registrar**, never fanning into the global control plane. |
| **F2 Controller state** | **CockroachDB** (prod) / Postgres-sync-replica (smaller HA) via `pgx`, behind an extracted `Store` interface (`*bboltStore` stays the default). Every existing single-bbolt-txn invariant → one SERIALIZABLE SQL txn. |
| **F3 CA / signing** | Per-controller **intermediate CA** under the one shared **offline root** (root stays the only trust anchor in `CARootsPEM`); per-controller ed25519 **grant key**, all pubkeys in the signed `GrantKeys[]` union. `crypto.Signer` keeps KMS/HSM opt-in. |
| **F4 Control-stream routing** | **NATS** bus: local-registry-handle-first, else publish to the owning agent's subject; session-id-keyed bridge for cross-controller ICE signaling; **epoch-fenced** affinity directory; the strong-store sweep is the backstop so no revoke is silently lost. |
| **F5 Sweep / audit** | **Sharded-by-held-stream** sweep (each controller revokes its own agents with a local push — NOT leader-only); per-controller hash-chained HMAC audit merged off-box. |
| **F6 Topology** | Regional controller **cells** (failure domain = cell) **but** the deny-path records (revocation, suspension, `GrantKeys`/`CARoots` trust set) live in **global strong tables** — closes the cross-cell eventual-revocation hole. Geo-DNS is a bootstrap hint only, behind the signed config. |

## Status & cardinal constraint

**Status:** design-locked spec, build-ready. Supersedes the HA bullets in `docs/ROADMAP.md` (lines 20, 57, 100) by making them concrete and closing the cross-region/cross-controller holes the red-team found in the current single-writer code.

**Cardinal constraint (non-negotiable):** single-node stays the trivial, zero-dependency dev/lab default. `geneza-controller init && geneza-controller serve` is byte-for-byte today's code path. HA is **opt-in, additive** behind three interfaces — `Store`, `streamRouter`, and the existing `crypto.Signer`/`GrantKeys[]` seams. No DB, no bus, no cluster is ever forced on a self-hoster.

---

## 1. The HA model in words

Geneza splits into two independently-scalable tiers plus one global truth store.

### 1.1 The DERP edge fabric (stateless + blind)
Thousands of `pion/turn` relays (today's `internal/relay`, unchanged code) deployed in untrusted PoPs worldwide. Each relay is **payload-blind** (it forwards opaque Noise/WireGuard ciphertext, never sees plaintext or a principal) and **stateless** (it validates coturn-REST HMAC creds against a shared secret with zero stored per-session state). Scaling to thousands is purely a *distribution + selection* problem, not a relay-code problem.

- **Discovery:** a **signed DERP map** rides inside the already-signed `ClusterConfig`. Each entry carries `{RegionID, RelayID, Hostnames/IPs, STUNPort, TURNPort, RelayCertPub}`. Because the map is signed by the trusted `GrantKeys`, a tampered relay list is rejected for the same reason a forged cluster config is — no new trust root.
- **Closest-pick:** every client/agent STUN-probes the nearest relay per region (Tailscale `netcheck` style, using `pion/stun` already in `go.mod`), sorts by RTT, and picks its **home** region locally. The controller never decides closeness; the client measures it. This rides the no-inbound invariant (pure outbound UDP).
- **Cross-home rendezvous:** **no relay-to-relay mesh** (that would break blindness and O(N²) the ops). Two peers on different home regions each offer their home relay as an ICE relay candidate; `pion/ice` converges on a shared candidate. The broker mints **per-region TURN creds for both peers' regions** so either relay validates.
- **Registration without DoS:** relays heartbeat to a **per-region registrar** (hundreds of small heartbeat sets), never fanning into the global per-agent control plane. The signed map is **regionally sharded** so a relay flapping touches only its region sub-entry; the map rebuild is **leader-only + debounced** (one rev per window, not one per relay). Agents pull the map on a schedule, not a per-flap broadcast.

### 1.2 The controller cluster (HA stateful PDPs)
N near-stateless **policy-decision-point** controllers behind a geo-LB, organized into **regional cells**. A cell = N controllers + a regional store replica + a regional control-stream bus + that region's slice of the DERP fabric. Workspaces home to a cell; agents/clients dial out (no inbound) to the nearest cell.

Controllers are *near*-stateless: all durable state lives in the shared store. The in-process `Registry` (`internal/controller/registry.go`) stays per-process as the **local fast path** — an agent's control stream lives on exactly one controller — and a thin **stream router** forwards pushes to the owning controller when the target is remote.

### 1.3 What is strongly consistent vs eventual

| Class | Records | Consistency | Why |
|---|---|---|---|
| **Global deny-path** | `revoked_certs`, `suspensions`, node `Approved` flag | **Globally linearizable** (read-your-writes fleet-wide), **fail-closed** on partition | `IsCertRevoked`/`IsSuspended` run on **every** authenticated RPC (`auth.go`). A revoke must bite at any controller the cert reaches, instantly, everywhere. |
| **Global single-use** | `tokens`, `device_codes`, `user_codes`, `handoff_codes`, `os_enroll`, first-admin check, `node_ws` index | **Globally serializable** (SELECT…FOR UPDATE / CAS) | These are globally-keyed single-spend credentials; today they're atomic only via bbolt's single-writer lock (`membership.go:151`). Two controllers must not both win. |
| **Global trust set** | `ClusterConfig` (`GrantKeys`, `CARootsPEM`, `AgentPolicy`), `ConfigVersion` | **Globally linearizable CAS** on `(version)`, signed by an **offline/threshold** key | Defines fleet-wide trust; a forked config splits the trust anchor. |
| **Workspace-scoped strong** | nodes, networks, subnets, bindings, sessions, source-bindings | **Strong within the owning cell** | A workspace homes to one cell; intra-tenant consistency is cell-local. |
| **Eventual / local** | live session **presence/heartbeat**, metrics (a shared external VictoriaMetrics — every controller forwards to and queries the same store, so series are unified, not per-controller-fragmented), the cross-cell **routing directory** (workspace→cell), per-controller audit chains | **Eventual** (rebuilt on reconnect / merged off-box) | Routes and observability — they *route*, they don't *authorize*. A stale entry causes a redirect, never an over-grant. |

The decisive rule the red-team forces: **the deny set (revocation + suspension + approval) and single-use credentials are GLOBAL-strong, never gossiped.** Gossip is allowed only as a redundant fast-path *on top of* the strong store.

### 1.4 How a session connects across the fleet
1. Agent dials out to its home cell's geo-LB → lands on any controller → `Register`s its `NodeControl` stream; the controller writes an **epoch-fenced** affinity row `node_id → {controller_id, epoch}` and subscribes the bus subject `agent.<ws>.<node_id>`.
2. Client dials out → lands on a (possibly different) controller → `CreateSession`. The broker checks suspension/approval against the **global-strong** store, mints a **scoped** `SessionGrant`, selects a **shared relay candidate** from the intersection of both peers' regions in the signed DERP map, mints per-region TURN creds, and routes the offer to the agent's owning controller (local handle first, else publish to the agent's subject; ack via NATS request-reply correlated by session id).
3. Agent independently re-verifies the grant: signature ∈ trusted `GrantKeys`, **and** the verifying key's declared scope covers `grant.WorkspaceID/NetworkVNI`, **and** `grant.WorkspaceID == its own enrolled workspace`. Default-deny on mismatch.
4. ICE/Noise establishes the E2E tunnel directly (hole-punch) or over the shared blind relay. **The data path never traverses the controller.**

### 1.5 How a session is revoked across the fleet
1. Admin kick or continuous-authz sweep decides to revoke. **The durable deny is written to the global-strong store FIRST** (suspension row and/or `revoked_certs`). This is the source of truth.
2. A live `SendRevoke` is pushed: local handle if the agent is here, else **published to the owning controller** over the bus. The push is a *latency optimization*, not the authority.
3. **The session row is marked revoked + audited ONLY if the deny was durably recorded or the push was accepted by a holder** — never marked-and-audited-as-delivered when the agent is on another controller and the push silently no-op'd (the current bug).
4. Three convergence backstops guarantee no silent loss: (a) every controller's **sharded sweep** re-evaluates its held agents against the global-strong deny set each tick; (b) the agent **pulls** the deny state on each heartbeat; (c) a **per-message re-check** of `checkNotRevoked`/`checkNotSuspended` runs inside the long-lived control-stream loop and tears it down server-side on a hit (today the check fires only once at stream open).

### 1.6 Topology diagram-in-words

```
                          ┌─────────────────────────────────────────────┐
                          │  GLOBAL TRUTH (linearizable, fail-closed)    │
                          │  CockroachDB GLOBAL tables:                  │
                          │   • revoked_certs   • suspensions            │
                          │   • node approval   • single-use creds       │
                          │   • ClusterConfig (CAS on version)           │
                          │  Offline ROOT CA (air-gapped/HSM) + M-of-N    │
                          │  cluster-config signing key                  │
                          └───────────────┬──────────────┬──────────────┘
                                          │              │
              ┌───────────────────────────┴──┐        ┌──┴───────────────────────────┐
              │  CELL: region eu-west         │        │  CELL: region us-east         │
              │  ┌──────────────────────────┐ │        │ ┌──────────────────────────┐  │
              │  │ geo-LB → gw-1 gw-2 gw-3   │ │        │ │ geo-LB → gw-1 gw-2 gw-3   │  │
              │  │  • intermediate CA (eu)   │ │  thin  │ │  • intermediate CA (us)   │  │
              │  │  • grant key (eu, scoped) │ │ x-cell │ │  • grant key (us, scoped) │  │
              │  │  • NATS bus (intra-cell)  │ │ super- │ │  • NATS bus (intra-cell)  │  │
              │  │  • regional store replica │ │ link   │ │  • regional store replica │  │
              │  │  • per-gw audit chain     │ │◄──────►│ │  • per-gw audit chain     │  │
              │  └──────────────────────────┘ │        │ └──────────────────────────┘  │
              └──────────┬────────────────────┘        └────────────────┬──────────────┘
                         │ signed DERP map (closest-pick)                │
          ┌──────────────┴──────────────┐                ┌──────────────┴──────────────┐
          │  DERP edge fabric (eu)       │                │  DERP edge fabric (us)       │
          │  relay … relay … relay (1000s)│  blind/stateless│ relay … relay … relay       │
          │  per-region TURN secret (eu) │                │  per-region TURN secret (us) │
          └──────────────────────────────┘                └──────────────────────────────┘
                 ▲  outbound UDP only                              ▲
                 │                                                 │
        agent ───┘   E2E Noise/WireGuard tunnel  ⇆  client ───────┘
        (dial-out)   (direct hole-punch first; blind relay is the floor)

  Audit: each gw streams its own HMAC hash-chain → off-box sink (S3 Object-Lock/SIEM);
         global order reconstructed at the sink by (controller_id, seq, ts).
```

---

## 2. Decisions F1–F6

Each fork takes the judges' best-per-fork synthesis (Design 1's global-strong consistency model as the spine; Design 3's regional-cell topology, per-region relay registrars, and explicit cross-region detail layered on) and folds in **all** red-team mitigations.

### F1 — DERP relay fleet · *signed DERP map + client RTT probe, regionally sharded, per-region secrets*
**Justification:** the only model that scales to thousands without anycast/BGP a self-hoster can't run, keeps relays blind+stateless, and is tamper-evident via the existing signed `ClusterConfig`.

- **Libs:** `pion/turn` v5 (blind relay), `pion/ice` v4 + `pion/stun` v3 (closest-pick + hole-punch + shared-relay candidate) — all already in `go.mod`. No new relay protocol.
- **Map:** extend `types.ClusterConfig` with `Relays []RelayNode{RegionID, RelayID, Addrs, STUNPort, TURNPort, RelayCertPub}`; **regionally sharded** so churn revs only a region sub-entry. Map rebuild is **leader-only + debounced** (advisory-lock leader, one rev/window).
- **Registration:** relays heartbeat to a **per-region registrar** (a tiny service / cell admin API), never to the per-agent control plane. The registrar health-checks (STUN ping) and UPSERTs its region's slice; the leader assembles the global signed map.
- **Closest-pick:** client/agent STUN-probe per region, pick lowest-RTT home. Grant carries a **signed relay candidate list** (not `relayAddrs[0]`), so ICE picks the lowest-latency *shared* relay and can **fail over** to another if one blackholes.
- **Creds:** **per-region** shared secret (`turn.GenerateLongTermTURNRESTCredentials` + a region-tagged custom `AuthHandler`), **flag-day rotation** (the relay validates against the region's single Current secret — pion hands one integrity key per username, so see §16). The opaque TURN username carries a region tag the relay validates. Cross-region pairs → broker mints **two creds** (one per region). Validation stays stateless; cred carries only `opaqueSessionID`, never a principal.
- **Rogue-relay defense:** client verifies the relay's presented server-cert identity (`geneza://relay/<name>`, chains to root) **against the signed map entry** — not merely chain-to-root. Relay selection is fungible (ICE re-picks on blackhole). Relay blindness limits a rogue relay to traffic analysis + selective drop, never plaintext.

### F2 — Controller state · *CockroachDB (prod) / Postgres (smaller HA) via `pgx`; embedded Raft is the supported self-contained opt-in*
**Justification:** serializable cross-node txns give every existing single-bbolt-txn invariant for free with **no failover gap** and let the deny-path/single-use records be **globally strong** — the only choice that closes the cross-region revocation window both Raft-cell designs leave open. It's the ROADMAP's named mechanism (`pgx` + advisory-lock leader reconcile).

- **Lib:** `jackc/pgx`; CockroachDB (Apache-core, self-hostable) for multi-region, plain Postgres for 2–3 node HA — same driver, same SQL. **No managed-cloud dependency is load-bearing.** `hashicorp/raft`+`raft-boltdb` is offered as a *fully-self-contained single-binary opt-in* for operators who refuse an external DB, behind the **same `Store` interface** — but it must host the global deny-path/single-use records in **one global Raft group**, not per-cell, or it's unsafe (see security checklist).
- **Migration:** extract a `Store` **interface** from the ~60 concrete `*Store` methods (all are `db.Update`/`db.View` closures over JSON). Keep `*bboltStore` verbatim (default); add `*sqlStore`. Per-workspace buckets → `(workspace_id, key) PK, value JSONB`; global buckets → keyed tables. Structural tenant scoping is preserved as a `WHERE workspace_id=` + PK (cross-tenant read is empty-set, not a forgettable filter).
- **Linearizable records** (each existing bbolt txn → one **SERIALIZABLE** SQL txn, no logic change):
  - Single-use / single-spend: `UseToken` (SELECT…FOR UPDATE, `uses<max`), `OSMintOnce`, `RedeemHandoff`, `PollDeviceGrant`, `UpsertFirstAdmin` (→ `INSERT…ON CONFLICT DO NOTHING`), single-active-node-per-uuid, `PutNode` record+`node_ws` index atomic.
  - Deny-path: `RevokeCert`/`IsCertRevoked`, `IsSuspended`, `SetNodeApproval` — **GLOBAL tables**, read-your-writes fleet-wide.
- **Eventual:** live presence/heartbeat (rebuilt on reconnect), metrics (shared external VictoriaMetrics — unified across controllers, not per-controller), cross-cell routing directory.
- **Fail-closed:** a controller that loses global quorum **refuses** security-load-bearing writes/reads rather than serving stale-allow. A region can always write a **local** deny (strict subset of the global deny — can never under-deny) that its own controllers honor instantly, replicated to global on heal; suspend/revoke surfaces a **hard error** to the admin if global quorum is unavailable (never silent success).

### F3 — CA & signing · *shared offline root + per-controller intermediate CAs + per-controller SCOPED grant keys; trust-set signing separated to an offline/threshold key*
**Justification:** N controllers issue concurrently with no shared private key and no hot-path coordination; agents trust any controller's leaf via the one root already in `CARootsPEM`. **But** the central red-team finding makes scope-binding mandatory: a bare grant key is fleet-omnipotent.

- **Model (reused):** `internal/ca/ca.go` already has offline root (`MaxPathLen:1`, moved to `offline-root/`) + online issuing CA behind `crypto.Signer` (HSM/KMS seam present). Give **each controller its own intermediate** under the shared root. `ca.PoolFromPEM(ca-roots.pem)` trusts the root → any controller's leaf verifies fleet-wide.
- **Serials:** keep `newSerial` = **128-bit random, globally unique** (no per-cell counters — a counter is not globally unique across cells and would collide the bare-serial denylist). If a counter is ever used it MUST be namespaced `(issuer-SKI, serial)`.
- **Name constraints:** constrain each intermediate with X.509 **permitted URI subtrees** (`geneza://node/<thisCell'sWorkspaces>/`) so a leaked cell-A intermediate cannot mint a leaf for cell-B's workspace — PKI-tier mirror of grant scoping.
- **Intermediate revocation (must be wired, not aspirational):** the agent verifies the presented chain's intermediate against a **strongly-replicated intermediate-denylist** (standard x509 verification will *not* do this — make it explicit, fail-closed). "Rotate just that controller, denylist its intermediate at the root" becomes a real, tested path. Prefer KMS/HSM-backed intermediates over Raft-replicating an intermediate key to every cell member.
- **Grant keys — SCOPED (the central fix):** `ClusterConfig.GrantKeys` is already a list. Extend each entry to `GrantKey{KeyID, PublicKey, Scope{Workspaces[] | CellID/Regions}}`. Each controller/cell gets its own grant keypair; all pubkeys are published in the signed `ClusterConfig`. **In `EvaluateOffer`, after `VerifyGrant`, REQUIRE:** (1) the verifying key's declared scope covers `grant.WorkspaceID/NetworkVNI`; (2) `grant.WorkspaceID == the agent's own enrolled workspace` (the agent must **durably persist its workspace at enrollment** — today `enroll.go` persists only `NodeID`); (3) `grant.NetworkVNI == vniForWorkspace(self)` and `Routes ⊆ allocated set`. Default-deny on un-scoped key or mismatch. This converts "any trusted key signs anything" into "a cell key signs only for its tenants" — the per-key containment F3 otherwise fails to provide.
- **Revocation store:** `revoked_certs` is in the **global-strong** table (F2), read-your-writes fleet-wide, with a short-TTL cache + an optional `cert.revoked` invalidation publish as a fast-path *on top of* the TTL.

### F4 — Control-stream routing · *NATS bus spine, local-handle-first + publish-to-owner, epoch-fenced affinity, fail-closed revoke*
**Justification:** an agent's stream lives on exactly one controller; NATS request-reply + subject routing is the clean, proven, self-hostable fit. The dropped-revoke bug makes fail-closed routing mandatory.

- **Lib:** `nats.go` (single binary, clusterable; Redis pub/sub as the alternative for existing-Redis shops). Hand-wired gRPC `ControllerMesh` is *not* chosen — it puts retry/back-pressure/observability on the implementer.
- **`streamRouter` interface:** `inproc` (direct `Registry` calls — single-node default, zero deps) vs `nats`. Every `Registry` push API (`SendOffer`/`SendRevoke`/`SendDisco`/`SendModuleConfig`/`SendNetworkConfig`) gets a routed sibling: **try local handle, else publish to `agent.<ws>.<node_id>`**; the owning controller's subscription delivers to its local handle. `SendOffer` ack via **NATS request-reply correlated by session id**.
- **Affinity directory, epoch-fenced:** on `Register`, write `node_id → {controller_id, epoch++}` (last-writer-wins, monotonic epoch) and subscribe the subject. A **partitioned zombie** must not absorb a revoke meant for the live home: the bus subscription is **gated on holding the current epoch** — a stale-epoch controller drops its subscription and refuses delivery.
- **Session-signal bridge (client on A, agent on B):** today `disco.go` resolves the peer via `findNodeByWGPub` then `registry.SendDisco`, which **silently no-ops** (only `slog.Debug`) if the peer is remote — breaking cross-controller ICE. Fix: bridge `SessionSignal ⇄ NodeControl` over `session.<id>.toagent`/`.toclient`. `disco.go`'s stateless forwarder logic is unchanged; it publishes/subscribes when the peer is remote. Because disco is stateless and agents re-announce until connected, a mid-rendezvous failover **re-bridges on reconnect** by rebuilding the `session_id→owner` mapping from the affinity directory.
- **The dropped-revoke fix (critical):** `revokeSession` (today `continuousauthz.go:120`) must NOT mark the row revoked + write `session_revoked` audit when `Online()==false` and the push silently no-op'd. New contract: **durable deny written first → routed push (local-else-publish) → mark+audit only on durable-record-OR-accepted-by-a-holder; otherwise durably queue / retry next tick.** Plus the agent-side pull backstop and the per-message stream re-check.
- **Failover:** agent reconnects via LB → new controller `Register`s (epoch++ fences the dead one) → re-pushes desired state (cluster-config / `NetworkConfig` / `ModuleConfig`, all monotonic-versioned so a stale duplicate is ignored). In-flight E2E tunnels survive (data path never touches the controller). A compromised/failed-over controller cannot exceed policy: the agent re-verifies the **scoped** grant (F3).

### F5 — Sweep & audit · *sharded sweep by held-stream; per-controller HMAC audit chains merged off-box*
**Justification:** sharding by held-stream makes steady-state revoke a **local** push (no cross-controller hop) and scales linearly; a single-leader sweep (Design 2) re-centralizes the deny path and bottlenecks the leader.

- **Sweep:** each controller sweeps **only the sessions whose agents it currently holds**, re-evaluating against the **global-strong** suspension/approval rows (`reauthSweep` changes only its session *selection*, from `ListAllSessions()` to "my held agents"). A suspension written anywhere is enforced by the holding controller within one tick. The admin-kick edge (suspend raised on X for an agent held by Y) is the *only* path that publishes cross-controller. The store-global janitorial deletes (`SweepExpiredAuthSessions`/`DeviceGrants`/`Handoffs`) run on the **one elected leader** (advisory-lock).
- **Suspension instant propagation:** `suspendPrincipal` writes the durable deny to the **global-strong** store FIRST, then fans `authz.suspend.<ws>.<provider>.<subject>` over the bus so every controller tears down matching held tunnels sub-second; the tick is the backstop. Browser auth-sessions move into the **shared store** so `RevokeAuthSessionsForSubject` is not a single-controller local op; `revokeBySubject` **publishes-to-owner** instead of only calling the local registry. If the issuing controller dies between the durable write and the fan-out, every controller's sweep recovers it from the global store.
- **Audit:** keep **per-controller** hash-chained HMAC chains (`audit.go` is inherently serial per writer — a shared global chain is a write SPOF *and* breaks on concurrency: any concurrent append produces a seq-gap/prev-mismatch that fails `ChainOk`). Each controller streams its signed chain to the existing off-box sink (`audit_sink.go` → S3 Object-Lock/SIEM, per ROADMAP). Each segment self-identifies `controller_id + chain-head hash`; the auditor validates **N independent chains** and reads the union ordered by `(controller_id, seq, ts)`. Intra-writer tamper-evidence (what auditors need) is preserved without a global serialization point.

### F6 — Topology & discovery · *regional controller cells; geo-DNS as untrusted bootstrap hint behind the signed ClusterConfig; global deny/trust records in CockroachDB GLOBAL tables*
**Justification:** cells give blast-radius isolation (a region's outage takes down only that region's *new-session brokering*; established E2E tunnels survive everywhere) **without** sacrificing global strong consistency on the deny path — the GLOBAL tables close the cross-cell revocation gap. Rejected: one global mega-cluster (cross-region consensus on every token mint) and hub-spoke (SPOF + latency tax).

- **Cell:** N controllers behind a regional geo-LB + a regional store replica + a regional NATS + a regional DERP slice + its own intermediate CA + its own scoped grant key. A workspace homes to one cell.
- **Discovery:** geo-DNS resolves `gw.<cluster>.geneza` to the nearest healthy cell — **bootstrap hint only**. The agent then pins that it speaks to a `geneza://controller/<name>` mTLS cert chaining to the trusted root, and the authoritative controller+relay endpoint set comes from the **signed `ClusterConfig`** (so a spoofed DNS answer can't point at an out-of-set endpoint — defeats DNS spoofing the same way the signed map defeats relay-list MITM). The real safety net is F3's agent-side scope binding: a mis-route can only fail-and-retry, never over-grant.
- **Failover:** LB drops a dead controller → agent reconnects in-cell → re-syncs. Whole-cell death → geo-DNS fails over to next-nearest cell; **global deny/trust records stay strong** (a suspended/revoked principal stays denied cross-cell). Cross-cell access (rare) routes through the eventually-consistent directory, which **routes, not authorizes** — the owning cell always mints the grant (with its scoped key the client already trusts via the global `GrantKeys` union).
- **Where the store lives:** regional replica per cell for latency-sensitive workspace-scoped reads; the few truly-global records (deny set, single-use creds, trust set) in CockroachDB **GLOBAL** tables (read-local, write-replicated).

---

## 3. The interfaces that keep single-node trivial

HA is selected by config; the default code path is unchanged. All HA backends are **additive nil-able implementations of the same interfaces**, injected at `New()`.

```go
// ── Store: extracted from the existing concrete *Store (~60 methods, no logic change) ──
type Store interface {
    // single-use / single-spend (MUST be globally serializable in HA)
    UseToken(token string, now time.Time) (*TokenRecord, error)
    OSMintOnce(key string, now time.Time, ttl time.Duration, tok *TokenRecord, mk func() (string, error)) (string, bool, error)
    RedeemHandoff(code string, now time.Time) (*HandoffRecord, error)
    PollDeviceGrant(code string) (*DeviceGrant, error)
    UpsertFirstAdmin(...) (bool, error)
    // deny-path (MUST be globally linearizable, read-your-writes, fail-closed)
    RevokeCert(*RevokedCert) error
    IsCertRevoked(serialHex string) bool
    IsSuspended(ws, provider, subject string) bool
    SetNodeApproval(ws, id string, approve bool, by string, now time.Time) (*NodeRecord, error)
    PutNode(ws string, n *NodeRecord) error // record + node_ws index, one txn
    // trust set (CAS on version)
    SetSignedClusterConfig(version int64, signed []byte) error
    ClusterConfigVersion() (int64, error)
    // ... workspaces, networks, sessions, audit-count, settings, artifacts ...
}

// impls:
//   *bboltStore  — today's code verbatim (DEFAULT, zero deps)
//   *sqlStore    — pgx → CockroachDB/Postgres (HA opt-in)
//   *raftStore   — hashicorp/raft FSM over bbolt (self-contained HA opt-in; deny-path/single-use in ONE global group)

// ── streamRouter: forward a push to the agent's owning controller ──
type streamRouter interface {
    // local handle if present, else route to owner; returns Delivered/NotDelivered
    SendRevoke(ctx, nodeID, sessionID, reason string) (delivered bool, err error)
    SendOffer(ctx, nodeID, sessionID string, grant []byte, timeout time.Duration) (accepted bool, reason string, err error)
    SendDisco(ctx, nodeID string, d *DiscoMsg) (delivered bool, err error)
    BridgeSessionSignal(sessionID string) // client⇄agent over the bus
}
// impls:
//   inprocRouter — direct Registry calls (DEFAULT; nil bus; "always local")
//   natsRouter   — local-handle-first, else publish-to-owner; epoch-fenced affinity

// ── signing: the EXISTING crypto.Signer seam, unchanged ──
//   single-node: one self-signed intermediate from ca.Init, one entry in GrantKeys[]
//   HA: per-controller intermediate (root-signed) + per-controller SCOPED grant key; KMS/HSM optional
```

**Config-driven selection (single-node defaults):**

```yaml
store:    bbolt        # bbolt | cockroach | postgres | raft
router:   inproc       # inproc | nats | redis
region:   ""           # "" = no cells, no geo-DNS
relays:   [local]      # the one co-resident relay; no DERP fleet
ca:       self-signed  # one intermediate, one grant key
```

**Single-binary all-in-one mode:** `geneza-controller serve --all-in-one` runs controller + the co-resident relay + bbolt + in-proc registry in one process — exactly today. The e2e battery (`scripts/e2e.sh`) runs unchanged. Enforcement: every HA component is a **nil-able injected dep** — `nil` router ⇒ local-only; `nil` raft/sql ⇒ bbolt; one-element `GrantKeys`/`relays` ⇒ today. HA cannot be accidentally imposed.

---

## 4. Security checklist — every red-team mitigation as a MUST

Numbered to the red-team findings; each is a build-blocking requirement.

1. **MUST — global single-use serialization (double-mint, critical).** `UseToken`/`OSMintOnce`/`RedeemHandoff`/`PollDeviceGrant`/`UpsertFirstAdmin`/`node_ws` index are implemented as `SELECT…FOR UPDATE` in a **SERIALIZABLE** txn (CRDB default) — the second spend aborts with a retry error surfaced as a clean **deny**. In the Raft opt-in, these live in **one global group**, not per-cell. A globally-keyed single-use credential MUST be **hard-rejected** (not redirected) at any non-owning cell.
2. **MUST — globally-strong revocation (revoked-cert authenticates at foreign cell, high).** `revoked_certs` is a **global linearizable** table read by `IsCertRevoked` on every RPC; **never gossiped** as source of truth. **Fail closed** if the global denylist is unreachable. The Noise-handshake grant re-verify (`offer.go`) and control-stream re-attach MUST **also** consult the strong revocation set (today they re-verify the grant but never re-check cert revocation).
3. **MUST — globally-strong suspension (suspended principal keeps live shell, high).** `suspensions` in the **same global-strong** store, keyed on stable `(ws, provider, subject)`. The sharded sweep re-evaluates against the **global** set every tick; instant bus fan-out is the fast path, tick is the backstop, durable write is the authority — **never the bus alone**.
4. **MUST — no silent cross-controller revoke loss (critical, confirmed in code).** `revokeSession` MUST NOT mark a row revoked + write `session_revoked` audit when the agent is remote and the push silently no-op'd. Contract: **durable deny first → routed push (local-else-publish-to-owner) → mark+audit only on durable-record OR accepted-by-a-holder, else durably queue/retry.** Plus: (a) **per-message** `checkNotRevoked`/`checkNotSuspended` inside the `NodeControl`/`UserAPI` stream loop (today it fires only at stream open) with server-side teardown on hit; (b) **agent-side pull** of the deny set on each heartbeat; (c) **sharded-by-held-stream** sweep so steady-state revoke is a local push with a live handle.
5. **MUST — scoped grant keys (cross-tenant grant forgery, CENTRAL/critical).** `GrantKey{KeyID, PublicKey, Scope}` in the signed `ClusterConfig`. `EvaluateOffer` MUST require, after `VerifyGrant`: verifying-key scope covers `grant.WorkspaceID/NetworkVNI` **and** `grant.WorkspaceID == agent's own enrolled workspace` **and** `grant.NetworkVNI/Routes` within the agent's allocation. Agent MUST **durably persist its workspace at enrollment**. **Default-deny** on un-scoped key or mismatch. (Makes the `// agent asserts == its own` comment in `grant.go:35` real code.)
6. **MUST — trust-set anti-split-brain (forked ClusterConfig, high).** `ClusterConfig` write is a **globally-linearizable CAS** on `ConfigVersion` (one writer wins). Agents treat `(version, content-hash)` as identity → two distinct payloads at the same version are detectably forked → agent **fails closed** until it sees a strictly-higher version from the reconciled leader. CA-root changes go behind an explicit **two-version overlap** so a forked config can never strand agents with no common root.
7. **MUST — separate trust-set signing from per-controller grant/issuing authority (failover policy escalation, high).** `ClusterConfig` (the doc defining `GrantKeys`/`CARoots`/`AgentPolicy`) is signed by a **separate higher-tier key kept offline/HSM/M-of-N**, not held by any single running controller. `GrantKeys` additions / `AgentPolicy` relaxations require a **quorum/threshold** signature. Agent treats `AgentPolicy` as **most-restrictive** of a locally-pinned floor and the pushed value (push can tighten, never loosen). Agent independently bounds `NetworkConfig` routes/VNI against its enrolled workspace.
8. **MUST — intermediate CA containment (compromised intermediate, high).** Agent performs an **intermediate-revocation check** against a strongly-replicated intermediate-denylist (fail-closed; standard x509 will NOT do this). Each intermediate carries X.509 **name constraints** (permitted URI subtree per cell). Prefer KMS/HSM-backed intermediates over Raft-replicating the key to every cell member.
9. **MUST — globally-unique 128-bit random serials (serial-space collision, medium).** Keep `newSerial` = 128-bit random, globally unique; **no per-cell counters** (a counter collides the bare-serial denylist). If counters are ever used, key the denylist on `(issuer-SKI, serial)`.
10. **MUST — per-region TURN secrets (global secret forgery, high; confirmed: today one static `RelaySharedSecret`).** Per-region shared secret, overlap-window rotation, region tag in the opaque username validated by the relay; cross-region pairs minted under **both** regions' secrets. Caps a leaked relay secret to one region, not the planet. Validation stays stateless.
11. **MUST — signed DERP map with per-relay identity (rogue relay / fallback-drop, high).** Each relay entry carries `{region, relay-cert-pubkey, addrs}`; client verifies the relay's server-cert identity **against the signed map entry**. Client-side RTT probe (not anycast/geo-DNS as truth). **Fungible** relay selection: ICE re-picks another shared candidate if one blackholes.
12. **MUST — epoch-fenced affinity + epoch-gated subscriptions (zombie split-delivery, high).** Monotonic epoch on each (re)register, LWW on the strong store; **bus subscription gated on holding the current epoch** (stale-epoch controller drops its subscription and refuses delivery). Paired with the agent-side pull backstop (#4).
13. **MUST — cross-controller session-signal bridge (broken/racy ICE, high; confirmed `disco.go` silently no-ops on remote peer).** Bridge `SessionSignal ⇄ NodeControl` over a `session_id`-keyed bus subject; preserve `disco.go` statelessness so re-announce reconverges after failover; rebuild `session_id→owner` from the affinity directory; bus carries opaque candidates only.
14. **MUST — grant relay candidate list, not `relayAddrs[0]` (cross-region rendezvous gap, medium; confirmed `broker.go` pins `relayAddrs[0]`).** Broker selects a shared relay from the **intersection** of both peers' regions in the signed map; grant carries a **signed candidate list**; ICE picks lowest-latency shared relay with fallback; TURN creds minted under both regions for cross-region pairs.
15. **MUST — per-controller audit chains merged off-box (shared chain SPOF/break, medium; confirmed `audit.go` is strictly serial per writer).** Never a single in-band global serial chain (concurrent appends break `ChainOk`). Each controller streams its own HMAC chain to the off-box sink; global order reconstructed at the sink by `(controller_id, seq, ts)`. The suspend event is written to the strong store transactionally with the suspension row so the merge can prove the deny happened even if the issuing controller died.
16. **MUST — TURN-cred rotation is a synchronized flag-day (cross-region cred split, medium).** *Implementation constraint:* pion/turn's `AuthHandler` returns a single integrity key per username, so a relay cannot accept current+previous concurrently without the username naming the secret version. We therefore validate against the region's **Current** secret only; rotating a region's secret is a synchronized flag-day — the controller and every relay in the region swap Current together. A cred minted under the old secret after the relay has rotated is rejected, which degrades the path (availability), never leaks or over-grants. A true overlap window remains a follow-up: extend the minted username to `<expiry>:<region>:<keyver>:<id>` so the relay can try both versions.
17. **MUST — partition fail-closed asymmetry handled (deny-path unavailability, medium).** Deny-path **reads** fail closed on store-unreachable (short-TTL cache for blips). A region can always write a **local** deny (subset of global, never under-denies) honored instantly, replicated on heal. Suspend/revoke **writes** surface a hard error on global-quorum loss (never silent success). Size global-table regions so a single-region partition still has global write quorum; alarm the "cannot issue new global deny" state loudly.
18. **MUST — cache bounded by short TTL, not invalidation-only (stale-allow, high).** Every deny-path cache entry (positive **and** negative) carries a **short TTL** (low single-digit seconds) so a lost/reordered NATS invalidation extends access by at most the TTL. Invalidation publish is additive latency-only. **Required test:** drop all invalidation messages, assert a revoked cert is denied within TTL.
19. **MUST — relay registration cannot DoS the control plane (medium).** Relays heartbeat to **per-region registrars**, never the per-agent control plane. Signed map is regionally sharded; rebuild is **leader-only + debounced**; agents pull on a schedule, not a per-flap broadcast.
20. **MUST — geo-DNS/directory are untrusted hints (mis-route, medium).** Trust decisions live entirely in signed artifacts the agent re-verifies (signed endpoint set in `ClusterConfig`, mTLS `geneza://controller/<name>` pin, scoped grant per #5). A spoofed DNS answer or stale directory can only fail-and-retry, never over-grant.

**Invariants held throughout (audited, unchanged):** no inbound ports (always dial-out, even on failover/re-home); E2E Noise (bus + relays carry only ciphertext/opaque ICE — controllers never see plaintext); independent grant re-verification (a compromised/failed-over/partitioned controller cannot exceed policy); relay blindness; tamper-evident per-controller audit. **The system fails CLOSED on every consensus/quorum/authorization uncertainty — availability of NEW access degrades, security never does.**

---

## 5. Phased rollout

Each phase is independently shippable and lab-testable on the existing `geneza1` lab (vmbr5, VMs 105–107), extended as noted. Single-node remains the default at every phase. The ordering matches the ROADMAP's control-plane chain (Store interface → HA store → off-box audit → relay selection).

### Phase 0 — `Store` interface extraction + scoped-grant security floor *(prerequisite, no behavior change)*
**Build:** extract the `Store` interface from `*Store` (keep `*bboltStore` verbatim). Implement the **scoped grant** check (#5): `GrantKey.Scope`, agent durably persists workspace at enrollment, `EvaluateOffer` enforces `WorkspaceID==self` + key-scope. Add the **per-message** revoke/suspend re-check in the stream loop (#4a) and the agent-side **pull backstop** (#4b). These are safe on single-node and harden it immediately.
**Proves it:** existing `scripts/e2e.sh` (35 checks) passes unchanged. New red-team tests: a grant signed for workspace B is **rejected** by a workspace-A agent; a cert revoked mid-stream is torn down within one heartbeat (not at TTL); `revokeSession` for an offline node does **not** falsely audit `session_revoked` as delivered.

### Phase 1 — HA store (CockroachDB/Postgres `sqlStore`) + leader-only reconcile
**Build:** `*sqlStore` via `pgx`; map every single-use/deny-path invariant to a SERIALIZABLE txn (#1, #2, #3); `ConfigVersion` CAS (#6); advisory-lock leader for reconcile. Single global strong tables for deny/single-use/trust. Still **one controller** — this de-risks the store swap before multi-controller.
**Proves it:** `store=cockroach` runs the full e2e battery identically to bbolt. **Double-mint test:** two concurrent `UseToken` on the same token → exactly one succeeds, one gets a clean deny (run against a 3-node CRDB on the lab). **Fail-closed test:** kill CRDB quorum → new sessions/revokes refuse rather than stale-allow; bbolt default still zero-dependency. Migration test: bbolt → sqlStore bootstrap preserves all buckets.

### Phase 2 — Multi-controller control-stream routing (NATS `natsRouter`)
**Build:** stand up 2–3 controllers behind a geo-LB on the lab, sharing the Phase-1 CRDB + a NATS cluster. Implement `streamRouter` (local-else-publish), epoch-fenced affinity (#12), NATS request-reply offers, the cross-controller **session-signal bridge** (#13), the **fail-closed routed revoke** (#4), sharded-by-held-stream sweep + bus-fanned suspension (#3, F5), and off-box per-controller audit chains (#15).
**Proves it (battle-test):** client on gw-A, agent on gw-B → session establishes; admin kick on gw-A **tears down** the gw-B tunnel sub-second (the headline-hole test). Partition gw-B as a **zombie** while the agent re-homes to gw-C → revoke still lands (epoch fencing + pull backstop); no split-delivery. Drop all NATS invalidations → revoked cert denied within cache TTL (#18). Controller death mid-session → E2E tunnel survives; reconnect re-syncs.

### Phase 3 — DERP relay fleet (signed map + closest-pick + per-region secrets)
**Build:** add VMs as relays across two simulated "regions" on the lab. Signed DERP map in `ClusterConfig` with per-relay identity (#11); client RTT probe + grant **candidate list** (#14); per-region registrars + sharded/debounced map rebuild (#19); per-region TURN secrets with overlap rotation (#10, #16); relay server-cert-vs-map verification; fungible ICE fallback.
**Proves it:** client picks lowest-RTT relay; two peers in different regions rendezvous on a shared relay (two creds). **Rogue-relay test:** a relay not in the signed map (or wrong identity) is rejected; a blackholing relay → ICE fails over to another with no session loss. **Secret-leak test:** rotate one region's secret → that region re-keys alone, other region unaffected; live floors stay up through the overlap window. Relay-churn test: 100s of relays flapping → at most one map rev per debounce window, no agent-fleet broadcast storm.

### Phase 4 — Regional cells + global deny/trust tables + per-cell CA/grant scoping
**Build:** two cells (each its own LB + NATS + store replica + **intermediate CA** + **scoped grant key** + DERP slice), with CRDB **GLOBAL** tables for deny/single-use/trust (#2, #17). Geo-DNS as signed-config-gated bootstrap hint (#20); cross-cell routing directory (eventual, routes-not-authorizes); intermediate name constraints + intermediate-denylist (#8); separated/threshold trust-set signing (#7); partition fail-closed asymmetry + local-deny escape valve (#17).
**Proves it:** workspace homes to cell-A; an agent that geo-DNS-fails-over to cell-B is **denied** if its cert was revoked or principal suspended in cell-A (global table — the cross-region window is **closed**, not gossiped). Whole-cell-A outage → established tunnels everywhere survive; cell-A's new-session brokering pauses; cell-B keeps serving its own. **Compromised-intermediate test:** denylist cell-A's intermediate at the root → its leaves rejected fleet-wide without a root rotation. **Forked-config test:** two writers can't both publish version N+1; agents fail closed on a detected fork until the reconciled leader's strictly-higher version.

**Throughout all phases:** the single-node `--all-in-one` default (bbolt + inproc + one relay + self-signed intermediate) ships unchanged and `scripts/e2e.sh` stays green — HA is purely the additive opt-in, paid for only by operators who flip `store`/`router`/`region`.

---

### Files this spec touches (build map)
- `internal/controller/store.go` → extract `Store` interface; add `sqlStore` (and optional `raftStore`).
- `internal/types/cluster.go` → `GrantKey.Scope`, signed DERP `Relays[]`, `(version,hash)` identity; separate trust-set signer.
- `internal/types/grant.go` + `internal/agentd/offer.go` → enforce scoped + `WorkspaceID==self` + VNI/routes bounds (today aspirational at `grant.go:35`).
- `internal/agentd/enroll.go` → durably persist enrolled workspace.
- `internal/controller/registry.go` → `streamRouter` seam; epoch-fenced affinity; `inproc`/`nats` impls.
- `internal/controller/continuousauthz.go` → fail-closed routed `revokeSession` (fixes the confirmed silent-loss at `:120`); sharded sweep; bus-fanned suspension; per-message stream re-check.
- `internal/controller/disco.go` → bus bridge when peer is remote (today silently no-ops).
- `internal/controller/broker.go` → relay candidate-list selection (replaces `relayAddrs[0]`); two-region cred minting.
- `internal/controller/turncreds.go` → per-region secret + region tag + overlap rotation.
- `internal/ca/ca.go` → per-controller intermediates, name constraints, intermediate-denylist check; keep `crypto.Signer`/128-bit-random serials.
- `internal/controller/audit.go` + `audit_sink.go` → per-controller chains merged off-box (already seamed).

---

## Appendix · Red-team findings (3 critical, 14 high, 11 medium)

Every finding below is a **MUST** the HA build closes structurally. The synthesized
spec above already folds in each mitigation; this appendix is the audit trail.

> ⚠️ **Present-day bug (does NOT need HA to bite): finding C3 — silent revoke loss.**
> `revokeSession` (continuousauthz.go) marks the row `SessionRevoked` and writes the
> `session_revoked` audit record **unconditionally**, while the `SendRevoke` push is
> gated on `registry.Online()` with its error swallowed (`_ =`). If the agent's stream
> is momentarily offline/reconnecting, the audit log says "revoked" while the tunnel
> survives. Worth fixing in the single-node code now, independent of the HA timeline.

### Critical

**1. [critical] DOUBLE-MINT OF SINGLE-USE TOKEN / DEVICE-CODE / OS-ENROLL ACROSS CONTROLLERS UNDER PARTITION. Every single-spend invariant in the code (UseToken store.go:704, OSMi**

- *Precondition:* HA store with anything weaker than SERIALIZABLE on the token/device-code/handoff/firstadmin keys, OR Design-3 cross-cell where a global-keyed single-use credential can be presented at a non-owning cell during a partition/gossip window. Triggered by a leaked/replayed token, or simply two honest concurrent Nova vendordata hits landing on two different controllers.
- *Mitigation (MUST):* STRUCTURAL: these specific records (tokens, device_codes, user_codes, handoff_codes, os_enroll, the members-empty-check for UpsertFirstAdmin, the node->ws index) MUST be GLOBALLY linearizable, not merely intra-cell strong. Design 1 (CockroachDB SERIALIZABLE) is the only fork that gives this for free fleet-wide — implement UseToken/OSMintOnce/RedeemHandoff/PollDeviceGrant/UpsertFirstAdmin as SELECT...FOR UPDATE in a SERIALIZABLE txn (CRDB default) so the second spend aborts on a retry error. For Design 2/3 (per-cell Raft), single-use credentials CANNOT be merely cell-local: either (a) host thei

**2. [critical] SCOPE-BLIND GRANT KEY = full cross-tenant/cross-region grant forgery from one compromised controller (CENTRAL FINDING). The agent's grant acceptance path (internal**

- *Precondition:* Any ONE signing controller is compromised, OR any one per-controller grant private key leaks (filesystem read, backup, or in D3 self-hosted mode the grant key is Raft-replicated to every cell member). Multi-controller HA is enabled so >1 grant key is in the trusted union — this is specifically an HA-introduced blast-radius amplification (N keys, each fleet-omnipotent) over the single-node case.
- *Mitigation (MUST):* Bind AUTHORITY into the signed grant key, not just identity. (1) Add explicit scope to each GrantKey in ClusterConfig: GrantKey{KeyID, PublicKey, Workspaces[] or CellID/Regions}, in the same monotonic signed cluster-config envelope. (2) In EvaluateOffer, after VerifyGrant REQUIRE the verifying key's declared scope COVERS grant.WorkspaceID/NetworkVNI, AND grant.WorkspaceID==the agent's own enrolled workspace — so the agent MUST durably persist its workspace at enrollment and assert grant.WorkspaceID==self, grant.NetworkVNI==vniForWorkspace(self), Routes within its allocated set. (3) Default-den

**3. [critical] SILENT CROSS-CONTROLLER REVOKE LOSS (the headline hole). Today the continuous-authz sweep and admin-kick paths are LOCAL-ONLY by construction. continuousauthz.go:1**

- *Precondition:* HA controllers deployed (>1 controller process); an agent's stream homes to a different controller than the one running the sweep or processing the admin suspend/kick; revoke pushed without a durable/retried bus path or an agent-side pull backstop.
- *Mitigation (MUST):* Routed push (local-handle-else-publish-to-owner) for SendRevoke; sharded-by-held-stream sweep so steady-state revoke is local; revokeSession must treat 'no live handle anywhere' as not-yet-delivered (durably queue / re-try next tick), never mark-revoked-and-audited as if delivered; agent-side pull of the strong revocation/suspension state on heartbeat as the convergence backstop.

### High

**1. [high] REVOKED CERT STILL AUTHENTICATES AT A FOREIGN CONTROLLER/CELL DURING THE PROPAGATION WINDOW. auth.go:179 checkNotRevoked + auth.go:196 checkNotSuspended run IsCert**

- *Precondition:* Multi-region/multi-cell deployment with eventual cross-cell propagation of revoked_certs/suspensions (Design 3 as written, Design 2 with the gap unfilled). Attacker holds a still-cryptographically-valid leaf whose serial was just denylisted, or is a suspended principal, and reaches a non-home controller (via geo-DNS failover or a multi-region workspace) inside the window.
- *Mitigation (MUST):* STRUCTURAL: the deny-path records — revoked_certs (bucketRevokedCerts) and suspensions (bucketSuspensions) — MUST be GLOBALLY strongly consistent (read-your-writes fleet-wide), NOT gossiped. Design 1's global CRDB table is the safe variant. If cells are kept (Design 2/3), carve these two buckets out of the per-cell Raft into a single global strong table/group so IsCertRevoked/IsSuspended on every RPC reads a linearizable global denylist; accept the cross-region read latency (it is a tiny keyset, cacheable). Fail CLOSED on partition: if a controller cannot reach the global denylist, it must DENY (

**2. [high] SPLIT-BRAIN ON THE TRUST SET (GrantKeys / CARootsPEM) VIA THE SINGLE MONOTONIC CLUSTER-CONFIG VERSION. ClusterConfig distribution is gated solely by a monotonic**

- *Precondition:* Two controllers/cells able to write a signed cluster-config concurrently (partitioned leader election, or no global lock on the config writer). The grant/CA trust set must change (controller add/remove, key rotation, CA rotation) during the partition for the divergence to bite.
- *Mitigation (MUST):* STRUCTURAL: the cluster-config WRITE must be a single globally-linearizable compare-and-swap on the version (INSERT ... WHERE version = N, in the global strong store — Design 1's advisory-lock+SERIALIZABLE makes this a CAS that exactly one writer wins; a per-cell Raft is NOT sufficient because the trust set is fleet-global). Make ConfigVersion a global monotonic allocation (one sequence in the global table), and have agents treat the (version,content-hash) pair as the identity so two distinct payloads at the same version are detectably forked and the agent fails closed / refuses to advance unt

**3. [high] HELD CONTROL STREAM SURVIVES REVOCATION/SUSPENSION (NO PER-MESSAGE RE-CHECK) — AMPLIFIED BY HA FAILOVER. checkNotRevoked/checkNotSuspended run in the unary/stre**

- *Precondition:* Long-lived NodeControl/UserAPI stream open across a revoke/suspend event, OR an agent failing over to a new controller around the moment a revoke is issued. Made dangerous by (a) no per-message re-check on the held stream and (b) eventual cross-controller visibility of the deny record.
- *Mitigation (MUST):* STRUCTURAL: (1) add a per-message (or short-interval, e.g. each heartbeat) re-check of checkNotRevoked+checkNotSuspended INSIDE the NodeControl/UserAPI stream loop, reading the GLOBALLY-strong denylist, and tear the stream down server-side on a hit — do not rely on asking the agent to self-revoke. (2) Revoke MUST be a durable write to the strong store FIRST (revokeSession continuousauthz.go:116 already updates the session record, but the authoritative deny is the revoked_certs/suspension row) and the live SendRevoke push is only a latency optimization; on failover the new controller re-derives th

**4. [high] EVENTUALLY-CONSISTENT LEAF REVOCATION = a revoked/stolen cert keeps authenticating fleet-wide during the propagation window. IsCertRevoked is checked on EVERY a**

- *Precondition:* A cert is revoked (compromise response) AND HA is multi-cell with eventual cross-cell propagation (D3 default, D2 as-written), OR D1 with a cache that does not bound staleness independently of NATS. Attacker holds a still-cryptographically-valid stolen leaf and chooses which controller/cell to reconnect to (always possible: dial-out + geo-DNS/LB).
- *Mitigation (MUST):* Make the leaf-revocation denylist STRONGLY consistent fleet-wide, not eventual (D1's global strong table, NOT D3 gossip). (1) The per-RPC revoked-serial check reads a globally-strong store with read-your-writes and FAILS CLOSED on partition (cannot reach the strong store => deny). (2) Any hot-path cache TTL must bound staleness INDEPENDENTLY of pub/sub invalidation — short TTL is the floor, NATS invalidation is only an optimization, never the sole mechanism. (3) The Noise-handshake grant re-verify (offer.go) and control-stream re-attach must ALSO consult the strong revocation set — today they 

**5. [high] SUSPENSION (sticky authZ deny) enforced only at the broker hot path and only for user certs, with no agent-side enforcement on LIVE sessions and eventual cross-**

- *Precondition:* Multi-cell HA with eventual cross-cell suspension (D3 default; D2 unspecified). A principal with an active session whose agent stream is held by a cell other than where the suspension was raised (normal for a multi-region tenant or after a failover that re-homed the agent).
- *Mitigation (MUST):* Put suspension rows in the SAME globally-strong store as revocation, read fail-closed. (1) The per-held-stream sharded sweep re-evaluates against the GLOBAL strong suspension set every tick, so the controller holding the agent enforces a suspension written anywhere within one tick regardless of cell. (2) Fan the suspension as an instant revoke-by-subject over the bus to the OWNING controller (sub-second), tick as backstop — durable deny is the strong store, never the bus alone. (3) Suspension keys on stable (workspace,provider,subject) (auth.go:201), already cell-agnostic; make every cell's sweep au

**6. [high] GLOBAL TURN SHARED SECRET = one compromised relay/controller forges fleet-wide, region-blind relay creds; rotation is all-or-nothing. TURN creds are GenerateLongTe**

- *Precondition:* HA relay fleet (thousands of edge relays) with a single global shared secret (current code). Compromise of any one relay host, or any one controller disk/backup, leaks it. No multi-region tenant required.
- *Mitigation (MUST):* PER-REGION TURN secrets with overlap-window rotation. (1) Each region has its own secret; a relay holds only its own region's secret, so a leaked relay secret forges only within ONE region and that region rotates alone. (2) The opaque TURN username carries a region/realm tag the relay validates, so a cred minted for region X is rejected at region Y. (3) For a cross-region session (peers whose nearest relays differ) the controller mints creds under BOTH peers' region secrets (D3's two-cred minting) rather than falling back to one global secret. (4) Overlap-window rotation (two valid secrets during

**7. [high] FAILED-OVER CONTROLLER RE-PUSHES DESIRED STATE THE AGENT DOES NOT CEILING-CHECK — trust-set / policy escalation across the failover seam. On failover the agent dia**

- *Precondition:* Multi-controller HA where >1 controller can sign cluster-config, or the cluster-config signing key is shared/Raft-replicated (D3 mode). One such controller is compromised; the agent applies the next monotonic ClusterConfig (on failover or routine push).
- *Mitigation (MUST):* Separate the CLUSTER-CONFIG/TRUST-SET signing authority from per-controller grant/issuing authority, and require more than one online controller to change trust. (1) Sign ClusterConfig (the document defining GrantKeys/CARoots/AgentPolicy) with a SEPARATE higher-tier key kept OFFLINE/HSM/M-of-N, not held by any single running controller — so a compromised controller mints grants within its scope (finding 1) but cannot expand the fleet trust set. (2) Make GrantKeys additions / AgentPolicy relaxations require a quorum/threshold signature. (3) Agent treats AgentPolicy as most-restrictive of a local pinned flo

**8. [high] COMPROMISED INTERMEDIATE CA = unlimited fleet-trusted node/user leaf minting, effectively un-revocable short of a root rotation. Every agent trusts ca-roots.pem**

- *Precondition:* One controller's/cell's intermediate CA private key is compromised (disk read; or D3 self-hosted mode Raft-replicates the intermediate key to every cell member, so any cell-member compromise leaks it). HA multi-controller with per-controller intermediates (F3, all designs).
- *Mitigation (MUST):* (1) Add an INTERMEDIATE-revocation check the agent actually performs: verify the presented chain's intermediate is not on a strongly-replicated intermediate-denylist (standard x509 verification will NOT do this; make it explicit, fail-closed against the global strong store). (2) Constrain each intermediate with X.509 NAME CONSTRAINTS (permitted URI subtree geneza://node/<thisCell'sWorkspaceSet>/) so a leaked cell-A intermediate cannot mint a leaf for cell-B's workspace — PKI-tier mirror of finding 1. (3) Prefer the MANAGED/HSM crypto.Signer mode (ca.go:74 seam exists) for intermediates over D3

**9. [high] EVENTUALLY-CONSISTENT DENYLIST = CROSS-REGION OVER-AUTHENTICATION WINDOW (Design 3, and Design 2 by omission). auth.go:184 calls `s.store.IsCertRevoked(serialHe**

- *Precondition:* Multi-cell/region topology with per-cell Raft and gossiped (or unspecified) cross-cell revocation/suspension; a revoked or suspended principal presents at a non-home cell within the propagation window (notably a stolen cert that geo-DNS-fails-over).
- *Mitigation (MUST):* Put revoked_certs + suspensions + node-approval in a GLOBALLY-STRONG store read by the IsCertRevoked/IsSuspended per-RPC path; bound staleness with a short TTL cache (never trust bus-invalidation alone); fail CLOSED on the deny-path read when the global store is unreachable from a cell.

**10. [high] CACHE-INVALIDATION STALE-ALLOW ON THE REVOKE PATH (Design 1's residual risk made concrete). Design 1 routes the per-RPC IsCertRevoked/IsSuspended (auth.go:184/2**

- *Precondition:* Design-1 SQL-backed denylist with an in-process cache whose freshness depends on a NATS/Redis invalidation publish; that invalidation message is lost/reordered/dropped (bus restart, partition, consumer lag).
- *Mitigation (MUST):* Short-TTL bound on every cache entry (positive AND negative) so a lost invalidation extends access by at most the TTL; invalidation publish is additive latency-only; explicit lost-invalidation test asserting deny-within-TTL.

**11. [high] ROGUE / IMPERSONATED RELAY IN THE DERP MAP (relay-list MITM + fallback-drop). Today the relay set reaches agents two ways and NEITHER authenticates an individua**

- *Precondition:* Thousands of relays; the relay list/DERP map is distributed without per-relay identity binding (only chain-to-root) and grants pin a single relay address; an attacker can inject a map entry, spoof a bootstrap hint, or stand up a relay with the fleet secret.
- *Mitigation (MUST):* Signed DERP map with per-relay {region, identity pubkey, addrs}; client verifies the relay's server-cert identity == the signed map entry; client-side latency probe (not anycast/geo-DNS as source of truth); fungible relay selection so ICE re-picks another shared relay if the chosen one blackholes.

**12. [high] ONE GLOBAL TURN SECRET = FLEET-WIDE RELAY-CRED FORGERY + UNBOUNDED LEAK BLAST RADIUS. turncreds.go:43 mints creds with `GenerateLongTermTURNRESTCredentials(s.cf**

- *Precondition:* Fleet shares one static RelaySharedSecret (current code); any single edge relay is compromised or the secret leaks; no per-region scoping or rotation.
- *Mitigation (MUST):* Per-region TURN shared secret; controller mints creds under the chosen relay's region; cross-region sessions mint under both peers' region secrets; validation stays stateless. *Implemented:* the per-region scoping and two-cred cross-region minting ship; rotation is a synchronized flag-day rather than overlap-windowed (pion single-key AuthHandler — see §16), which preserves the leak-confinement property; only zero-downtime rotation is deferred.

**13. [high] CROSS-CONTROLLER SESSION-SIGNAL FORWARDING IS BROKEN/RACY (client on A, agent on B). disco.go is a stateless forwarder that resolves the peer via `s.findNodeByWGPu**

- *Precondition:* HA controllers; a client and the target agent hold their control streams on different controller processes/regions; ICE/disco signaling routed only through the local in-process registry (current disco.go) with no cross-controller bus bridge.
- *Mitigation (MUST):* session_id-keyed bus bridge between the client's SessionSignal stream and the agent's NodeControl stream; preserve disco.go statelessness so re-announce reconverges after failover; rebuild the session_id->owner mapping from the affinity directory on reconnect; bus carries opaque candidates only.

**14. [high] STREAM-AFFINITY DIRECTORY STALENESS / SPLIT-DELIVERY ON FAILOVER (no epoch fencing today). The codebase has ZERO multi-controller ownership concept (no epoch/lease**

- *Precondition:* HA controllers with a stream-affinity directory; an agent's owning controller is partitioned (not cleanly dead) while the agent reconnects elsewhere; ownership writes lack epoch fencing and bus subscriptions are not epoch-gated.
- *Mitigation (MUST):* Monotonic epoch/lease on each (re)register, last-writer-wins on the strong store; bus subscription gated on current epoch (stale-epoch controller drops its subscription and refuses delivery); agent-side pull backstop for convergence.

### Medium

**1. [medium] TWO CONTROLLERS BOTH ISSUE A LEAF CERT WITH THE SAME-SCOPE IDENTITY / SERIAL-SPACE OR APPROVAL RACE. Per-controller/per-cell intermediate CAs (Design 1/2/3 F3) let N **

- *Precondition:* Concurrent enroll/approve/revoke-approval of the same node (same machine re-enrolling, or admin action racing an auto-approve) across two controllers with independent or eventually-consistent node/approval state. Requires the node record + approval flag to live in a non-globally-serialized store.
- *Mitigation (MUST):* STRUCTURAL: node admission state (the Approved flag, the node->ws index, the active-node-per-uuid binding) is a security gate (broker.go:207 refuses sessions to !Approved) and MUST be strongly consistent for the OWNING workspace — Design 1's global SERIALIZABLE table or Design 3's owning-cell Raft (workspace homes to one cell, so node approval is naturally cell-local and strong THERE). The hard rule: a node's identity/approval has exactly ONE authoritative store (its workspace's owning cell), and enrollment/approval at any other controller must route to or be rejected by that authority, never wri

**2. [medium] TURN-CRED / RELAY-SECRET SPLIT DURING PER-REGION SECRET ROTATION BREAKS CROSS-REGION RENDEZVOUS (BLINDNESS-PRESERVING BUT AVAILABILITY/DENY HAZARD). TURN creds **

- *Precondition:* Multi-region relay fleet with per-region secrets; a session/overlay flow whose two endpoints' selected relay candidates live in different regions, or a flow spanning a secret-rotation overlap window. Current turnCredsFor mints under exactly one secret for one relay addr.
- *Mitigation (MUST):* STRUCTURAL: when the two peers may land on relays in different regions, the controller must mint TWO creds (one under each relevant region's CURRENT secret) and hand each peer the cred for the relay IT will use, OR mint creds valid against a shared/global relay candidate both can reach — exactly Design 3's explicit 'mint under both peers' region secrets.' Implement turnCredsFor to take the set of candidate relay regions and return per-region creds. *Implemented:* `selectRelayCandidates` mints under each peer's region's Current secret; rotation is a synchronized flag-day, not relay-side overlap, because the pion AuthHandler validates one key per username (§16) — leak-confinement holds, zero-downtime rotation deferred to a key-versioned username. The original over-spec'd clause (relay accepts both previous and current) read

**3. [medium] AUDIT CHAIN FORK + SUSPENSION-DRIVEN BROWSER-SESSION REVOKE LOST ON FAILOVER. The audit log is a per-writer HMAC hash-chain (audit.go:18, Seq+Prev+Hash) — inher**

- *Precondition:* Suspend/kick issued at controller A for a principal whose live tunnels (agents) and/or browser auth-sessions live on controllers B/C; OR controller A crashes mid-suspend after the durable write but before the fan-out completes.
- *Mitigation (MUST):* STRUCTURAL: make the durable deny (SuspendPrincipal row + revoked_certs) the ONLY thing that must be atomic; everything else is best-effort fan-out backstopped by the strong store. (1) Put browser auth-sessions in the shared strong store (or key them so any controller's sweep can drop them) so RevokeAuthSessionsForSubject is not a single-controller local op. (2) Route the live-tunnel kill to the OWNING controller of each session's agent via the bus/affinity directory (Design 1 NATS / Design 3 cell bus) — revokeBySubject must publish-to-owner, not only call the local registry. (3) Guarantee every gatewa

**4. [medium] GEO-DNS / CROSS-CELL DIRECTORY steering: a network attacker (or a stale directory) routes an agent/client to the wrong cell, and the agent's MISSING scope check**

- *Precondition:* On-path attacker who can spoof geo-DNS/anycast/the eventual directory, OR a compromised in-rotation controller, in a multi-cell topology. Benign on its own (a redirect, not an over-grant); becomes impactful only in combination with finding 1's missing agent-side scope check.
- *Mitigation (MUST):* Keep geo-DNS/anycast/directory as UNTRUSTED routing hints; put the trust decision entirely in signed artifacts the agent re-verifies. (1) Authoritative controller/relay endpoint set comes from the signed ClusterConfig (RelayAddrs already there, cluster.go:37; add the controller endpoint set the same way) so a spoofed DNS answer cannot point at an endpoint outside the signed set. (2) Agent pins that it speaks to a geneza://controller/<name> cert chaining to the trusted root (mTLS), so a random host cannot impersonate a controller under DNS poisoning. (3) The real fix is finding 1's agent-side scope binding

**5. [medium] PARTITION / FAIL-CLOSED ASYMMETRY on the global deny path: a region that loses quorum on the global strong store can no longer ISSUE new revocations/suspensions**

- *Precondition:* HA with globally-strong revocation/suspension tables (D1's safe choice). A partition isolates the responder's region from global write quorum — inducible by an attacker with network position, or coincident with the incident being responded to.
- *Mitigation (MUST):* Keep fail-closed-on-new-access, but add a LOCAL immediately-effective deny that needs no global quorum: (1) a region can always write a LOCAL suspension/revocation its own controllers honor instantly (region-local strong write), replicated to the global table on heal — a strict subset of the global deny, so it can never under-deny. (2) Size global-table regions so a single-region partition still has global write quorum among surviving regions. (3) Alarm the 'cannot issue new global deny' state loudly so operators fail the responder over to a quorum-side region. Invariant: losing quorum may block 

**6. [medium] THOUSANDS OF RELAYS FANNING INTO ONE CONTROL PLANE = REGISTRATION DoS + MAP-CHURN AMPLIFICATION. There is no relay-registration path in the code today (relays a**

- *Precondition:* Thousands of edge relays added with a registration/heartbeat path that fans into the global controller control plane and/or revs+broadcasts the signed ClusterConfig per relay event.
- *Mitigation (MUST):* Per-region registrar/UPSERT for relay heartbeats; regionally-sharded signed DERP map (relay churn touches only its region sub-entry); leader-only debounced map rebuild; agents pull the map on a schedule, not a per-flap broadcast.

**7. [medium] PER-CONTROLLER INTERMEDIATE CA: SERIAL COLLISION + UNCOORDINATED REVOCATION KEY-SPACE. F3 gives each controller its own intermediate under the shared root. ca.go issu**

- *Precondition:* Per-controller/per-cell intermediate CAs issuing concurrently; a serial scheme that is a per-cell counter (Design 3) rather than globally-unique random, OR a future shortening of the serial; revocation keyed on bare serial.
- *Mitigation (MUST):* 128-bit random globally-unique serials (no per-cell counters) so the bare-serial denylist stays sound; if counters are used, key the denylist on (issuer-SKI, serial); explicit tested per-intermediate revoke-at-root + single-controller rotation path.

**8. [medium] AUDIT HASH-CHAIN IS PER-PROCESS SERIAL — A SHARED CHAIN ACROSS CONTROLLERS IS A WRITE SPOF AND BREAKS ON CONCURRENCY. audit.go builds a strictly-serial HMAC chain:**

- *Precondition:* HA controllers configured to write a single shared audit chain (one file/stream) instead of per-controller chains; concurrent Appends from >1 controller.
- *Mitigation (MUST):* Per-controller independent HMAC chains (each tamper-evident standalone) merged off-box at the audit_sink seam; global order reconstructed at the sink by (controller_id, seq, ts); never a single in-band global serial chain.

**9. [medium] GLOBAL-STRONG WRITE UNAVAILABILITY UNDER PARTITION (Design 1's inverse blast-radius cost, must be a DELIBERATE choice not a surprise). Putting revoked_certs + s**

- *Precondition:* Design-1 global-strong tables for revocation/suspension; a region loses global quorum (cross-region partition) while an admin issues a suspend/revoke or while per-RPC deny reads are in flight.
- *Mitigation (MUST):* Deny-path reads fail CLOSED on store-unreachable (short-TTL cache for blips); suspend/revoke writes surface a hard error on quorum loss (never silent success); document/size global-table latency+availability; keep single-node bbolt the zero-dependency default.

**10. [medium] LEADER-ONLY FLEET SWEEP RE-CENTRALIZES THE REVOKE PATH (Design 2's F5, the inferior choice). A single elected leader sweeping the whole fleet must push revokes **

- *Precondition:* HA design adopts a single-leader fleet-wide continuous-authz sweep that must push revokes to agents held by other controllers.
- *Mitigation (MUST):* Shard the sweep by held-stream (each controller revokes its own agents locally against the strong suspension/approval rows); bus-fan suspension instantly with the per-controller tick as backstop; reserve cross-controller publish for the admin-kick edge only.

**11. [medium] GRANT PINS ONE RELAY + ONE WORKSPACE-VNI WITH NO REGION AWARENESS — CROSS-REGION RENDEZVOUS GAP. broker.go:294 hard-pins `RelayAddr: b.relayAddrs[0]` (literally**

- *Precondition:* Global relay fleet with regional homing; broker pins a single relayAddrs[0] into the grant (current code) with no region intersection or candidate list; client and agent are nearest to relays in different regions.
- *Mitigation (MUST):* Broker selects a shared relay candidate from the intersection of both peers' regions in the signed DERP map; grant carries a signed relay CANDIDATE LIST; mint TURN creds under both peers' region secrets for cross-region pairs; ICE picks lowest-latency shared relay with fallback.

