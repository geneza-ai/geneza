<!-- SUPERSEDED: the CockroachDB / regional-cell / per-cell-CA build steps below are
     replaced by the Postgres-flat plan in docs/ha.md (de-CRDB, signed controller
     discovery, pgrouter LISTEN/NOTIFY, delete the leader, redirect, relay
     register-and-watch, delete NATS). Kept for history. ha.md is authoritative. -->
<!-- Provenance: synthesized from the geneza-ha-build-plan decisional workflow
     (4 per-phase detail agents grounded in the live tree + 3 critics + synthesis),
     derived from docs/ha-architecture-spec.md. Companion to that spec: the spec is
     the WHAT/WHY (locked design + §4 security checklist); this file is the HOW
     (file-by-file build order). HA build NOT started. -->

# Geneza Global-HA — Build-Ready Implementation Plan

> **Sole resume artifact for the multi-week HA build.** Pick up here. Read the spec first (`docs/ha-architecture-spec.md`), then this file is the concrete, file-by-file build order. Every claim below was re-grounded against the live tree at HEAD `adb41a9`; where the source plans or spec text were factually wrong about the code, this document carries the **corrected** signature/line and flags the correction inline.

---

## 1. Preamble / how to resume

### Where things live
- **Spec (locked, design-ready):** `docs/ha-architecture-spec.md` — the decisional synthesis (3 architects → 3 judges → 3 red-teamers → synthesizer), the chosen base, the F1–F6 fork decisions, and the **20-item security checklist (§4)** every phase must land. The §-numbers in this plan refer to that checklist.
- **Monorepo:** `/root/geneza`, module `geneza.io`. Controller code in `internal/controller`, agent in `internal/agentd`, relay in `internal/relay`, shared wire/crypto types in `internal/types` + `internal/ca`, proto in `api/proto/geneza/v1`.
- **Lab:** `/root/labs/geneza1` (bridge `vmbr5`, `10.70.70.0/24`; VM 105 `geneza-core` = controller+relay, VMs 106/107 = agents). Deploy via `deploy/*.sh`, validate via `scripts/e2e.sh`. **Grounded count: the live `scripts/e2e.sh` has 47–48 `check` invocations** (spec text says "35", memory "55" — both stale; treat the live count as truth and assert all green at every phase).

### The chosen base (from the spec's Decision summary)
Managed distributed SQL (**CockroachDB / Postgres via `pgx`**) for global state + **NATS** control-stream bus + **Tailscale-style signed DERP map** (client RTT closest-pick) + **regional cells**. The deny-path records (revocation, suspension, node-approval, the `GrantKeys`/`CARootsPEM` trust set, single-use credentials) are **globally linearizable and fail-closed**, never gossiped.

### Cardinal constraint (non-negotiable, enforced every phase)
**Single-node `bbolt` stays the trivial, zero-dependency default.** `geneza-controller init && geneza-controller serve --all-in-one` (bbolt + in-proc registry + one co-resident relay + one self-signed intermediate + one grant key) is **byte-for-byte today's code path**. HA is opt-in, additive, and lives behind exactly three seams:

| Seam | Default impl | HA impl |
|---|---|---|
| `Store` (interface, P0) | `*bboltStore` (today's code verbatim) | `*sqlStore` (pgx → CRDB/Postgres, P1) |
| `streamRouter` (interface, P2) | `inprocRouter` (direct `Registry` calls) | `natsRouter` (publish-to-owner) |
| `crypto.Signer` + `GrantKeys[]`/`TrustKeys[]` (existing + P0 scope, P4 split) | one self-signed intermediate + one all-workspaces key filling both roles | per-cell intermediate + per-cell scoped grant key + offline/threshold trust-set signer |

Every HA component is a **nil-able injected dependency chosen at `New()`**; `nil` router ⇒ local-only, `bbolt` ⇒ no SQL, one-element `GrantKeys`/`Relays` ⇒ today. HA cannot be accidentally imposed — `validateForServe` hard-fails at startup if `router=nats`/`region!=""` without a shared store.

### One-glance status
- **HA build: NOT STARTED.** Nothing below `P0` exists yet.
- **C3 silent-revoke-loss: ALREADY FIXED** in commit `33d9fd0` (confirmation-based teardown). `revokeSession` marks `RevokeDelivered=false`; delivery is confirmed **only** by the agent's `"revoked"` `SessionEvent` ack via `confirmRevokeDelivered` (`continuousauthz.go:164`); owed revokes are re-pushed every sweep tick while online (`reauthSweep` `continuousauthz.go:79`) and on reattach (`redeliverPendingRevokes` `continuousauthz.go:187`). **Every phase builds ON this model and must not re-fix it.**
- **Session-p2p Phase 1: LANDED** (`adb41a9`). `SessionOffer.Turn` **is populated** (`registry.go:251`); the broker mints per-session agent TURN creds and passes them through `SendOffer(... agentTurn ...)` (`broker.go:366`). **Task #18 (delete relay-TCP floor) is PENDING** and touches the same offer/turncreds/ice files — every phase that touches those must coordinate (see the cross-cutting note in §2).

### Critical correction vs. the source phase plans (read before coding)
The source plans contained four load-bearing factual errors about the live code. They are corrected throughout this document and called out where they bite:
1. **`streamRouter.SendOffer` must carry `turn *genezav1.TurnCreds`** — the live `AgentDirectory.SendOffer`/`Registry.SendOffer` already do (`broker.go:26`, `registry.go:238`). Dropping it regresses session-p2p on single-node. (P2-S1)
2. **`SessionOffer.turn` is NOT free** — it is populated at `registry.go:251`; P3 must keep it as `candidates[0]`, not overwrite it. (P3-S8)
3. **`vniForWorkspace` lives in `internal/controller/server.go:397`** and is unreachable from `internal/agentd` — it MUST be moved to a shared package before any agent-side VNI check. (P0-S0)
4. **There are two TURN minters** — `turnCredsFor` (`turncreds.go:30`, overlay/Network flows) and `sessionTurnCreds` (`turncreds.go:91`, session-p2p, username `"sess-"+sessionID`). P3 must migrate **both**. (P3-S2)

---

## 2. Dependency graph

```
P0  Store-interface extraction + scoped-grant security floor          ── single-node hardening, ships ALONE
 │   (no behavior change; bbolt stays default)
 ▼
P1  HA store: *sqlStore via pgx                                        ── ★ MISSING from the source plans; authored here as §P1
 │   SERIALIZABLE single-use/deny-path · ConfigVersion CAS ·               (HARD prereq for P2/P3/P4 multi-node halves)
 │   advisory-lock LEADER election (owned here, consumed by P2-S7 & P3-S6)
 ▼
P2  Multi-controller control-stream routing (NATS streamRouter)          ── needs P1 shared store for affinity + routed-revoke-ack
 │   epoch-fenced affinity · session-signal bridge · fail-closed
 │   routed revoke · sharded sweep · off-box audit
 ▼
P3  DERP relay fleet (signed map + closest-pick + per-region secrets) ── needs P1 ConfigVersion CAS + P1 leader for map rebuild
 │
 ▼
P4  Regional cells + GLOBAL deny/trust tables + per-cell CA/grant     ── needs P0+P1+P2+P3 all landed
     name constraints · intermediate-denylist · threshold trust-set
```

### What each phase unblocks
- **P0** unblocks everything: it creates the `Store` seam P1's `sqlStore` plugs into, and the scoped-grant floor (`GrantKey.Scope`, durable agent workspace, `EvaluateOffer` enforcement) that P2/P3/P4 all reuse for cross-controller/cross-cell containment.
- **P1** is the **strong-consistency floor** every later phase rests on. *(The three source critics independently flagged that P1 was absent from the source plan set while P2/P3/P4 all declare it a hard prerequisite — this is the single biggest gap, fixed here.)* It owns: `*sqlStore`, the SERIALIZABLE mapping of all single-use/deny invariants, `ConfigVersion` CAS, and **advisory-lock leader election** (consumed by P2-S7 janitorial sweeps and P3-S6 map rebuild — built exactly once, here).
- **P2** unblocks horizontal controller scale; the affinity directory + session-signal bridge it adds are reused by P4's cross-cell routing.
- **P3** unblocks the relay fleet; its per-region TURN secrets and signed `Relays[]` map are reused by P4's per-cell DERP slices.
- **P4** is terminal: cells + global tables + PKI hardening.

### Independently shippable
- **Every phase's single-node deliverable ships independently** — single-node `bbolt`+`inproc` remains green at every phase and is the regression gate.
- **The HA (multi-node) half of P2/P3/P4 is BLOCKED on P1.** Concretely unbuildable without P1: P2-S2 affinity directory cross-controller safety, P2-S6 routed-revoke-ack settlement (`confirmRevokeDelivered` does `s.store.UpdateSession` on the *local* store — on two bbolt controllers the ack settles a row gw-A never sees), P3-S6 leader-only debounced map rebuild (unsafe on a bbolt plain-`Put`), P4-S1 GLOBAL tables. **Enforcement contract:** `validateForServe` MUST hard-fail when `router=nats` or `region!=""` while `store=bbolt`. This is the documented runtime gate, not buried in prose.

### Cross-cutting ordering hazards (apply across phases)
1. **P0 deploy order:** land + deploy the controller side (`GrantKey.Scope` S5, `AllWorkspaces=true` stamp S10, VNI move S0) **before** the agent enforcement (S7). If S7 ships first, every grant is rejected and the lab goes dark. Belt-and-braces: gate S7 behind "verifying key carries an explicit `Scope`" so a scope-less legacy key is treated as all-workspaces (fail-open **only** for the legacy single-node key, never for an explicitly-scoped HA key).
2. **`SendOffer` signature is locked ONCE** carrying `turn` and shared by P2 and P3. Whichever lands first defines it; the other references it. Do not double-rewrite the offer path.
3. **Session-p2p task #18 collision:** P2-S5 (bridge), P3-S2 (turncreds), P3-S5 (relay-cert check) all touch the offer path / `p2p/ice.go` / `turncreds.go` that task #18 rewrites. Land additive type/seam changes first (no behavior change), coordinate the cutover.
4. **Trust-set before multi-key:** P4-S5 (separate `TrustKeys` signer) lands **strictly before** P4-S6 (per-cell scoped grant-key union) — the moment >1 grant key is in the union, a single controller re-signing `ClusterConfig` with its grant key is the §7 failover-policy-escalation hole.

---

## 3. The seams (extract these first; everything layers on them)

### 3.1 `Store` (P0 — internal/controller/store_iface.go, NEW)

The complete method set is the **union of every method called via `.store.` across the entire `internal/controller` package** — *not* only the six store-impl files. **Grounded:** the call-site files are `access.go adminapi.go auth.go broker.go console*.go continuousauthz.go disco.go dns.go enroll.go httpapi.go membership.go monitoring.go networkpush.go nodecontrol.go server.go session.go userapi.go vendordata.go` (+ tests). The completeness gate is **`go build ./...`** (the `var _ Store = (*bboltStore)(nil)` assert only proves `bboltStore` is a *superset*, not that the interface covers all callers).

Grounded surface (81 method definitions on the concrete type; the load-bearing-first set with exact source lines):

```go
type Store interface {
    // ── single-use / single-spend (P1 makes these SERIALIZABLE) ──
    UseToken(token string, now time.Time) (*TokenRecord, error)                                  // store.go
    OSMintOnce(key string, now time.Time, dedupeTTL time.Duration, tok *TokenRecord,
               newToken func() (string, error)) (string, bool, error)
    RedeemHandoff(code, cookie string, now int64) (sessionInput, error)
    PollDeviceGrant(deviceCode string, now int64,
               issue func(g *DeviceGrant) ([]byte, error)) ([]byte, error)                       // ← S2 leak resolved: backend-agnostic closure, NOT *bbolt.Tx
    UpsertFirstAdmin(ws string, rec *MemberRecord) (bool, error)                                 // membership.go:153
    PutNode(ws string, n *NodeRecord) error                                                      // store.go:496 — record + node_ws index, one txn
    // ── deny-path (P1 → GLOBAL strong; P4 fail-closed) ──
    RevokeCert(*RevokedCert) error                                                               // store.go:850
    IsCertRevoked(serialHex string) bool                                                         // store.go (bare bool today; P4 adds error twin)
    IsSuspended(ws, provider, subject string) bool                                               // authzstate.go (bare bool today; P4 adds error twin)
    SetNodeApproval(ws, id string, approve bool, by string, now time.Time) (*NodeRecord, error)  // store.go:590
    // ── trust set (P1 CAS on version) ──
    SetSignedClusterConfig(version int64, signed []byte) error                                   // store.go:1037
    ClusterConfigVersion() (int64, error)                                                        // store.go:1026
    SignedClusterConfig() ([]byte, error)                                                        // store.go:1047
    // ── full remainder (the other ~67 methods, verbatim) ──
    PutWorkspace; GetWorkspace; ListWorkspaces
    PutNetwork; ListNetworks; PutSubnet; ListSubnets
    PutBinding; GetBinding; ListBindings
    GetNode; WorkspaceForNode; GetNodeModules; SetNodeModules; DeleteNode; FindNode; ListNodes; ListAllNodes
    PutToken
    PutSourceBinding; GetSourceBinding; ListSourceBindings; DeleteSourceBinding
    PutSession; GetSession; UpdateSession; ListSessions; ListAllSessions
    SetSetting; GetSetting
    StableVersion; CanaryVersion; SetStableVersion; SetCanaryVersion; CanaryNodes; SetCanaryNodes
    PutManifest; GetManifest
    PutMember; GetMember; ListMembers; DeleteMember; ListMemberWorkspaces
    PutDeviceGrant; GetDeviceGrantByUserCode; ApproveDeviceGrant; DenyDeviceGrant; SweepExpiredDeviceGrants
    PutHandoff; SweepExpiredHandoffs
    MintWSTicket; RedeemWSTicket
    PutAuthSession; GetAuthSession; DeleteAuthSession; ListAuthSessions
    RevokeAuthSessionsForUser; RevokeAuthSessionsForSubject; SweepExpiredAuthSessions
    SuspendPrincipal; LiftSuspension; ListSuspensions; ListRevokedCerts
    Close
}
```

Exclude unexported helpers (`getStringSetting`, `getDeviceGrantTx`, `countDeviceGrants`, `suspendedSet`) — they stay methods on `*bboltStore` only.

**The one porous seam (resolved):** `PollDeviceGrant`'s issuance callback currently leaks `*bbolt.Tx` (`device.go:163,185`) because the cert is minted **inside** the redeem txn (RT-F3: a cert must never be persisted, so it is minted-and-marked-redeemed atomically). **Decision (corrected from the source S2 marker-downcast, which a critic correctly flagged as re-introducing the coupling and risking a runtime panic on `sqlStore`):** the interface method takes a backend-agnostic closure `issue func(g *DeviceGrant) ([]byte, error)`; `*bboltStore` runs it inside its own `db.Update`, `*sqlStore` (P1) inside its own `SERIALIZABLE` txn. Atomicity is preserved by the impl wrapping the closure; no concrete txn type ever crosses the interface. This is the documented decision.

### 3.2 `streamRouter` (P2 — internal/controller/streamrouter.go, NEW)

**The signature carries `turn` — corrected from the source plan.** It also reconciles with the existing `AgentDirectory` (the broker calls `SendOffer`/`Online`/`Services` through `b.agents`, `broker.go:24-27`): `inprocRouter` and `natsRouter` **implement `AgentDirectory`**, and the broker's `b.agents` is swapped to the router. `Online()` and `Services()` become routing-aware (a remote agent is `Online` via the affinity directory; `Services` is resolved cross-controller — see P2-S2a).

```go
type streamRouter interface {
    // session offer — MUST carry turn (matches Registry.SendOffer at registry.go:238)
    SendOffer(ctx context.Context, nodeID, sessionID string, signedGrant []byte,
              turn *genezav1.TurnCreds, timeout time.Duration) (accepted bool, reason string, err error)
    SendRevoke(nodeID, sessionID, reason string) (delivered bool, err error)
    SendDisco(nodeID string, d *genezav1.DiscoMsg) (delivered bool, err error)
    SendModuleConfig(nodeID string, cfg *genezav1.ModuleConfig) (delivered bool, err error)
    SendNetworkConfig(nodeID string, cfg *genezav1.NetworkConfig) (delivered bool, err error)
    // cross-controller session-signal bridge (ICE candidates, opaque)
    BridgeToAgent(nodeID, sessionID string, d *genezav1.DiscoMsg) (delivered bool, err error)
    BridgeToClient(sessionID string, sig *genezav1.ControllerSignal) (delivered bool, err error)
    // AgentDirectory members, routing-aware:
    Online(nodeID string) bool
    Services(nodeID string) ([]types.Service, bool)
}
// inprocRouter{reg *Registry, sig *sessionSignalBroker} — DEFAULT, zero deps; wraps the EXISTING Registry methods
//   (registry.go:238/271/285/296/305) translating their plain `error` into delivered/accepted; Online/Services local.
// natsRouter{nc *nats.Conn, reg *Registry, store Store, controllerID string} — local-handle-first, else affinity lookup +
//   publish-to-owner; SendOffer via nc.RequestWithContext correlated by session id; epoch-gated delivery.
```

The current `Registry` methods (`SendRevoke`/`SendDisco`/`SendModuleConfig`/`SendNetworkConfig` at `registry.go:271/285/296/305`) return plain `error`. The router wrappers translate `"node not connected"` → `delivered=false` (owed), **not** an error that aborts the caller — a sloppy translation drops owed revokes or spams errors. `SendOffer` already returns `(accepted, reason, err)`.

### 3.3 The CA / `crypto.Signer` / trust-set seam (P0 scope, P4 split)

The existing `crypto.Signer` seam (`ca.CA.Signer`, `ca.go:74`) keeps KMS/HSM opt-in and is untouched in shape. Two extractions layer on it:
- **P0:** `GrantKey.Scope` rides inside the already-signed `ClusterConfig`, so a tampered scope is rejected exactly like a forged config (`VerifyClusterConfig` `cluster.go:54` unchanged on the wire). `func (k *GrantKey) CoversWorkspace(ws string) bool`.
- **P4:** a **separate** trust-set signer — `ClusterConfig.TrustKeys[]` (distinct from `GrantKeys[]`); `VerifyClusterConfig` verifies the config envelope against `TrustKeys`, `VerifyGrant` against `GrantKeys`. Single-node fills both roles from the one key (`TrustKeys == GrantKeys`, one entry). The offline root signs each cell intermediate **out of band** (`cmd/geneza-ca`); the M-of-N trust-set key signs `ClusterConfig` out of band (`cmd/geneza-trust`).

---

## 4. Per-phase build sections

---

## P0 — `Store` interface extraction + scoped-grant security floor

**Goal.** Extract the `Store` interface from the concrete `*Store` (rename it `*bboltStore`, zero behavior change) **and** land the scoped-grant floor that hardens single-node immediately: `GrantKey.Scope` in the signed `ClusterConfig`; durable agent-side workspace persistence at enrollment; `EvaluateOffer` enforcing `grant.WorkspaceID==self` + verifying-key-scope-covers-workspace/VNI + `Routes ⊆ allocated`; and the cross-controller-revoke convergence backstops that are safe today. No DB, no bus, no cluster. `scripts/e2e.sh` stays green; HA seams are nil-able/additive.

**Prerequisites.** None (this is the floor). C3 is already landed (`33d9fd0`) — build ON it. Broker already stamps `grant.WorkspaceID=ident.Workspace` and `grant.NetworkVNI=vniForWorkspace(ident.Workspace)` (`broker.go:299,308`) and signs via the grant key (`broker.go`); P0 makes the **agent enforce** it. Agent already re-derives identity from its node cert (`ca.PeerIdentity`, `ca.go:365`).

### Ordered build steps

**S0 — (NEW, from critic) Move `vniForWorkspace` to a shared package BEFORE any agent-side VNI check.**
`vniForWorkspace` is at `internal/controller/server.go:397` (FNV-1a, 24-bit, `"default"→1`) and is **unreachable from `internal/agentd`**. Move it to `internal/types` (or `internal/defaults`) as `types.VNIForWorkspace(id string) uint32`, keep a thin controller alias so `server.go:384`, `broker.go:299,308`, `networkpush.go:61`, and the existing `networkpush_test.go` callers are byte-identical. Add a unit test asserting `types.VNIForWorkspace(ws)` equals the broker's stamped value for the lab workspaces. **This is the VNI-half linchpin, on par with S10's `AllWorkspaces` stamp for the scope half** — without it S7 either fails to compile or the agent computes a forked VNI and default-denies every legitimate session.
- Files: `internal/types/vni.go` (NEW), `internal/controller/server.go`, `internal/controller/broker.go`, `internal/controller/networkpush.go`.

**S1 — Enumerate and freeze the `Store` surface** (see §3.1). Enumerate by grepping every `.store.` call across the whole `internal/controller` package (not just the six impl files). Completeness gate = `go build ./...`.
- Files: `internal/controller/{store,membership,session,device,handoff,authzstate}.go` (impl methods) + the call-site files for the union.

**S2 — Resolve the `PollDeviceGrant` `*bbolt.Tx` leak with a backend-agnostic closure** (see §3.1 decision). Change the interface method to `PollDeviceGrant(deviceCode string, now int64, issue func(g *DeviceGrant) ([]byte, error)) ([]byte, error)`; `*bboltStore` runs `issue` inside its own `db.Update`. Document this as the one intentionally-porous place, justified by RT-F3.
- Files: `internal/controller/device.go`.

**S3 — Define `Store` + alias the concrete type.** New file `internal/controller/store_iface.go` declares `type Store interface { ... }`. Rename `type Store struct{ db *bbolt.DB }` (`store.go:25`) → `type bboltStore struct{ db *bbolt.DB }` and every `func (s *Store)` receiver across the six impl files → `func (s *bboltStore)` (**~81 method definitions, grounded; ZERO call sites change** — callers use interface-dispatched `s.store.X`). Add `var _ Store = (*bboltStore)(nil)`. Rename `OpenStore(path string)` (`store.go:242`) to return the interface: `func OpenStore(path string) (Store, error)`. Record/value structs (`WorkspaceRecord`, `NodeRecord`, `TokenRecord`, `SessionRecord`, `MemberRecord`, `RevokedCert`, `SuspensionRecord`, `DeviceGrant`, `HandoffRecord`, `AuthSession`, `WSTicket`, `sessionInput`, errors) stay package-level, shared by all impls.
- Files: `internal/controller/store_iface.go` (NEW) + the six impl files.

**S4 — Switch holders to the interface type.** `Server.store` `*Store` → `Store` (`server.go`; `New()` calls `OpenStore` at `server.go:118` and now receives the interface). **`NewBroker` takes `store *Store` (grounded `broker.go:88`) — change to `store Store`**; the call site is `server.go:194`. Grep `*Store`/`*controller.Store` repo-wide and convert every holder. `New()` is the single nil-able injection point (today always `bboltStore`; a future `sqlStore` drops in with no caller change).
- Files: `internal/controller/server.go`, `internal/controller/broker.go`.

**S5 — Add `GrantKey.Scope` to the signed `ClusterConfig` trust set.** Extend `GrantKey` (`cluster.go:9-13`) to `{KeyID, PublicKey, Scope GrantKeyScope}` and add `type GrantKeyScope struct{ Workspaces []string` ` `json:"workspaces,omitempty"` `; AllWorkspaces bool` ` `json:"all_workspaces,omitempty"` ` }`. Add `func (k *GrantKey) CoversWorkspace(ws string) bool` (`AllWorkspaces || ws ∈ Workspaces`). `Scope` rides inside the already-signed envelope, so `VerifyClusterConfig`/`TrustedKeys` (`cluster.go:41,54`) are unchanged on the wire and a tampered scope is rejected like a forged config (`omitempty` ⇒ old agents that don't know `Scope` still verify).
- Files: `internal/types/cluster.go`.

**S6 — Durably persist the agent's enrolled workspace.** Add `Workspace string` to agent `State` (`state.go:40`) and a `fileWorkspace = "workspace"` const (`state.go:30` block). At `Enroll` (`enroll.go:189` `writes[]`), append `{fileWorkspace, []byte(ws+"\n"), 0o600}` where `ws` is derived from the **issued node cert** (`resp.NodeCertPem` → x509 → `ca.PeerIdentity` → `.Workspace`) — the cert is the authority, never client-asserted. `LoadState` (`state.go:104`) reads `fileWorkspace`; for already-enrolled agents with no file, **lazily backfill** from `State.LeafCert()` (`state.go:219`) → `ca.PeerIdentity().Workspace` and write the file. Add `func (s *State) EnrolledWorkspace() string`. Zero proto change (`EnrollResponse` already carries the node cert encoding the workspace in its URI SAN).
- **Legacy-cert hazard (from critic):** `ca.PeerIdentity` resolves a legacy 2-segment cert (`geneza://node/<name>`) to workspace `"default"` (`ca.go:380`). A pre-P0 single-tenant node whose controller homes it to a non-`"default"` workspace would backfill `"default"` and S7 would default-deny every grant. **Mitigation:** record a `cert had explicit workspace segment` flag on backfill; in S7, **skip the `WorkspaceID==self` assertion when the agent's only workspace source is a legacy-defaulted cert**, until the node re-enrolls or `RenewCert` (`nodecontrol.go:256`) reissues a 3-segment cert. Lab-check a legacy node.
- Files: `internal/agentd/state.go`, `internal/agentd/enroll.go`.

**S7 — Enforce scoped-grant in `EvaluateOffer` (the central security floor, §5).** `EvaluateOffer` (`offer.go:31`) today does `DecodeSigned → VerifyGrant(trusted,...) → grant.Validate(...)`. **Grounded:** `VerifyGrant(trusted map[string]ed25519.PublicKey, s *Signed)` (`grant.go:106`) returns only the grant, discarding *which* key verified; `handleSessionOffer` (`offer.go:81`) has only `w.trustedKeys()` (the map). Changes:
- (a) Thread the verifying `keyID` out: change `VerifyGrant` to return `(grant, keyID, error)` (or add `VerifyGrantWithKey`).
- (b) **Add an agent-side accessor `w.scopedTrustedKeys() []types.GrantKey`** that parses the held `ClusterConfig` from `w.st.ClusterRaw` — there is no path today that hands `EvaluateOffer` the scoped `[]GrantKey`; this is the named seam the source plan omitted. Wire it into `handleSessionOffer` and the in-handshake re-verify.
- (c) Add params `selfWorkspace string, selfVNI uint32` to `EvaluateOffer` and take `[]types.GrantKey`. After `VerifyGrant`, **REQUIRE** (default-deny on any mismatch): `grant.WorkspaceID != "" && grant.WorkspaceID == selfWorkspace`; the verifying `GrantKey.CoversWorkspace(grant.WorkspaceID)`; `grant.NetworkVNI == types.VNIForWorkspace(selfWorkspace)` (special-case legacy `0==0`); **and `grant.Routes ⊆ the agent's allocated set`** *(the Routes-subset half of §5 / §4.3 — flagged uncovered by a critic, landed here)*.
- (d) Call sites: `handleSessionOffer` (`offer.go:81`) passes `w.EnrolledWorkspace()` + the agent-derived VNI; the **in-handshake re-verify in `runSession`** (`offer.go:163`, the Noise `authorize` callback — grounded: today checks only `g2.ID != grant.ID` and the noise key) **ALSO re-runs the workspace==self + key-scope + VNI assertions**. Plumb `w.scopedTrustedKeys()` + `selfWorkspace`/`selfVNI` into that closure — list `internal/agentd/worker.go` (`trustedKeys()`) as a touched site for the scoped accessor.
- Keep `EvaluateOffer` pure for unit tests.
- Files: `internal/agentd/offer.go`, `internal/types/grant.go`, `internal/agentd/worker.go`.

**S8 — Per-message revoke/suspend re-check inside the long-lived stream loops (§4a).** Today `checkNotRevoked`/`checkNotSuspended` (`auth.go:179,196`) fire **once** at stream open (`streamAuthInterceptor`, `auth.go:230`). Add a per-iteration (or bounded-ticker) re-check inside the recv loop of `nodeControlService.Stream` (`nodecontrol.go:110` `for { stream.Recv() ... }`): call `checkNotRevoked`/`checkNotSuspended` against `stream.Context()`; on a hit, audit + return `PermissionDenied` to tear the stream down server-side (the agent reconnects, re-hits the open-time interceptor, denied — fail-closed). **Also add the same re-check to the UserAPI/SessionSignal long-lived stream** (`userapi.go` `SessionSignal` recv loop) — the spec §4a says "NodeControl/**UserAPI** stream loop"; the source plan covered only NodeControl. Re-use `identityFrom(stream.Context())`. Keep it cheap (one `Get`; gate frequency so a chatty stream doesn't hot-loop the store — matters more once P1 makes it a network read).
- Preserve the existing exemptions: `checkNotSuspended` returns nil (allow) for operational certs with no Subject (break-glass/node, `auth.go:194` comment). The re-check must NOT flip those to deny.
- Files: `internal/controller/nodecontrol.go`, `internal/controller/userapi.go`, `internal/controller/sessionsignal.go`, `internal/controller/auth.go`.

**S9 — Convergence backstop on heartbeat — and an HONEST scope statement (§4b).** **Correction (all three critics):** the no-proto "controller re-evaluates the node's sessions on each `Heartbeat` receipt and pushes `SessionRevoke`" is still a **server PUSH**, not the agent-driven **pull** §4b mandates (whose whole value is surviving a controller that withholds the push). Two options:
- **(a) DECISION — implement the true pull:** add `AgentMsg DenySetRequest` + `ControllerMsg DenySetResponse` (carrying this node's relevant revoked-serials/suspension-keys) to `control.proto` + regen, and have the agent self-tear-down on its own timer independent of any push. This genuinely satisfies §4b. **Recommended**, per the user's "battle-test / decisional-when-unsure" mandates — spawn a decisional agent if the proto-in-P0 vs defer fork is contested.
- **(b) If deferred:** implement the server-evaluated-on-heartbeat push as a **#4a reinforcement only**, and **explicitly record that §4b is NOT yet satisfied** and is owned by P2. Do not claim the pull property from a heartbeat push.

This plan adopts **(a)**: build the `DenySetRequest`/`DenySetResponse` round-trip in P0 so #4a (S8) and #4b (S9) are both genuinely landed.
- Files: `internal/controller/nodecontrol.go`, `internal/agentd/worker.go`, `api/proto/geneza/v1/control.proto`.

**S10 — Single-node init stamps the all-workspaces scope (the linchpin).** **Patch inside `buildClusterConfig` itself, not the call sites** (corrected from critic): `buildClusterConfig` (`server.go:415`) is the single function that constructs `GrantKeys[]{{KeyID,PublicKey}}`, and it is called by BOTH `init.go` (v1) AND `reconcileClusterConfig` (`server.go:459`, v0, which re-signs/CASes on a config-file change). Set `GrantKey.Scope.AllWorkspaces=true` there so the one self-signed key covers every workspace and S7's assertions always pass on single-node — and so a runtime reconcile/version-bump never emits a scope-less key. Test that **both** the v1 init config and a reconcile-produced config carry `AllWorkspaces=true`.
- Files: `internal/controller/server.go` (`buildClusterConfig`), `internal/controller/init.go`, `internal/types/cluster.go`.

### New interfaces / types
- `type Store interface { ... }` + `type bboltStore struct{...}` + `OpenStore(path) (Store, error)` (store_iface.go).
- `type GrantKeyScope struct{ Workspaces []string; AllWorkspaces bool }` + `GrantKey.Scope` + `CoversWorkspace`.
- `types.VNIForWorkspace(id string) uint32` (shared, S0).
- `VerifyGrant → (grant, keyID, error)` (or `VerifyGrantWithKey`).
- `EvaluateOffer(... selfWorkspace string, selfVNI uint32, keys []types.GrantKey ...)`.
- `State.Workspace` + `fileWorkspace` + `State.EnrolledWorkspace()`.
- `w.scopedTrustedKeys() []types.GrantKey` (agent accessor over `w.st.ClusterRaw`).
- `control.proto`: `AgentMsg.DenySetRequest` + `ControllerMsg.DenySetResponse`.

### Libs
**NONE new.** Existing tree only: `go.etcd.io/bbolt`, `crypto/ed25519`+`crypto/x509`, the existing protobuf/grpc stack. No pgx/NATS/raft (those are P1+, behind the seams P0 only extracts).

### Data model (no on-disk SHAPE changes)
- `GrantKeyScope` rides inside the already-signed `ClusterConfig` JSON (`omitempty` `workspaces`/`all_workspaces`).
- Agent state dir gains one plaintext file `workspace` (0600), lazily backfilled from the node cert for already-enrolled agents (no re-enroll forced).
- bbolt bucket names UNTOUCHED (`ws`, `workspaces`, `node_ws`, `tokens`, `settings`, `artifacts`, `src_bindings`, `os_enroll`, `revoked_certs`, `sessions_auth`, `device_codes`, `user_codes`, `handoff_codes`, `ws_tickets`, `suspensions`). The extraction is a pure type/receiver rename over identical `db.Update`/`db.View` closures — an existing `state.db` opens identically. `SessionRecord.RevokeDelivered`/`RevokeReason` (from C3) reused, not re-added.

### Invariants preserved
Single-node trivial default (bbolt + inproc + one all-workspaces key + one relay = byte-for-byte today); no behavior change for e2e (interface is pure extraction; scoped-grant is a no-op when the sole key covers all workspaces); no inbound ports; the agent's independent in-handshake re-verify is **strengthened** (S7) never weakened; C3 confirmation model intact (S8/S9 trigger pushes the agent's "revoked" ack settles, they do not mark-as-delivered); reserved-role/break-glass separation untouched; structural tenant scoping preserved verbatim.

### Security MUSTs landed
§5 (scoped grant keys, **the central fix** — incl. the `Routes ⊆ allocated` half), §4a (per-message re-check on NodeControl **and** UserAPI), §4b (agent-side pull via `DenySetRequest`/`Response`). Re-confirms C3 (§4 durable-deny-first) under P0 code.

### Test / proof strategy + lab setup
- **Unit:** `var _ Store = (*bboltStore)(nil)` compiles + `go build ./...` (callers); existing store tests run unchanged. `EvaluateOffer` (pure): grant for ws B **rejected** when `selfWorkspace=A` (the headline red-team #5 test); grant by a key whose `Scope` doesn't cover the grant's workspace rejected even when the signature verifies; single-node all-workspaces key + matching workspace **accepts**; legacy zero-VNI table-test; **`Routes`-superset grant rejected**. `types.VNIForWorkspace(ws) == broker stamp`. Freshly-init'd AND reconcile-produced config both carry `AllWorkspaces=true`. `State` round-trips `Workspace`; `LoadState` backfills from a cert-only state dir; legacy 2-segment cert path does not false-deny.
- **Lab (geneza1, as-is — single-node-safe, no topology change):** full `scripts/e2e.sh` (≈47–48 checks) green unchanged. **New red-team checks:** (a) revoke a node/user cert mid-NodeControl-stream → torn down within one heartbeat, not at TTL (S8); (b) suspend a principal with a live session → torn down within one heartbeat (S9 pull); (c) `revokeSession` for an OFFLINE node does NOT audit `session_revoked` as delivered (`RevokeDelivered` stays false; re-confirms C3); (d) a legacy single-tenant node still establishes (S6 backfill). **Battle-test:** forge a cross-workspace grant at the offer path under reconnect churn; confirm fail-closed at re-open, no race where a torn stream re-attaches with a revoked cert.

### Exit criteria
`go build ./...` + `go test ./...` green; `var _ Store` present; `Server.store` and `NewBroker` hold the **interface**; grep shows no remaining `*controller.Store` holder outside the bbolt impl/tests; `scripts/e2e.sh` green unchanged; cross-workspace + uncovered-key grants rejected, all-workspaces still accepts; agent durably persists workspace (+ legacy backfill); mid-stream revoke/suspend torn down within one heartbeat; §4b is a true agent pull; no new dependency in `go.mod`.

### Risks
Receiver-rename blast radius (~81 defs, mechanical, compile catches misses); `PollDeviceGrant` closure must preserve the double-redeem/RT-F3 atomicity (highest-correctness risk); S0 VNI drift if the helper isn't shared; S10 ordering hazard (controller scope-stamp before agent enforcement — see §2); per-message recheck cost (bound frequency before P1 makes it a network read); legacy-cert workspace defaulting (S6 mitigation); S9 proto-edit scope (decisional check if contested).

---

## P1 — HA store (`*sqlStore` via pgx) + SERIALIZABLE invariants + ConfigVersion CAS + advisory-lock leader  *(★ authored here — absent from the source plan set)*

**Goal.** Implement `*sqlStore` behind the P0 `Store` interface (CockroachDB for multi-region, plain Postgres for 2–3-node HA — same `pgx` driver, same SQL). Map **every** existing single-bbolt-txn single-use/deny invariant to **one SERIALIZABLE SQL txn** (no logic change). Make `ConfigVersion` a globally-linearizable **CAS**. Add **advisory-lock leader election** (the primitive P2-S7 janitorial sweeps and P3-S6 map rebuild both consume — built exactly once, here). **Still one controller** — this de-risks the store swap before multi-controller routing. Single-node bbolt stays default.

**Prerequisites.** P0 complete (the `Store` interface + record structs `sqlStore` implements; `buildClusterConfig` is the single CAS write site).

### Ordered build steps
1. **`internal/controller/sqlstore.go` (NEW) + `sqlschema.sql` (NEW).** `type sqlStore struct{ pool *pgxpool.Pool }` implementing `Store`. Per-workspace buckets → `(workspace_id, key) PK, value JSONB`; global buckets → keyed tables. Structural tenant scoping preserved as `WHERE workspace_id=$1 AND key=$2` (cross-tenant read = empty set, not a forgettable filter). `var _ Store = (*sqlStore)(nil)`.
2. **SERIALIZABLE single-use/single-spend (§1).** Each existing `db.Update` closure → one `SERIALIZABLE` txn: `UseToken` (`SELECT … FOR UPDATE`, `uses<max`), `OSMintOnce`, `RedeemHandoff`, `PollDeviceGrant` (the cert minted inside the SERIALIZABLE txn via the P0-S2 closure), `UpsertFirstAdmin` (`INSERT … ON CONFLICT DO NOTHING`), `PutNode` (record + `node_ws` index, one txn), single-active-node-per-uuid. The second concurrent spend aborts with a retry error surfaced as a **clean deny**.
3. **Deny-path tables (§2/§3).** `revoked_certs`, `suspensions`, node `Approved` flag — keyed tables read by `IsCertRevoked`/`IsSuspended`/`SetNodeApproval`. (P4 marks these CRDB GLOBAL + fail-closed; P1 keeps them strong-within-store.)
4. **`ConfigVersion` CAS (§6).** `SetSignedClusterConfig` becomes `INSERT … WHERE version = $expected` (one writer wins). `ClusterConfigVersion` is a global monotonic allocation. **Agent-side fork detection (§6, the actual mitigation — flagged uncovered by critics):** extend the agent's `parseAndCheckClusterConfig` (`state.go:189`) + `worker.go` config-apply to treat `(version, content-hash)` as the config identity and **fail closed** when two distinct payloads appear at the same version, until a strictly-higher reconciled version arrives. `VerifyClusterConfig` today enforces only monotonic version (`cluster.go:54`).
5. **Advisory-lock leader election (NEW primitive, owned here).** A `pg_advisory_lock`-backed `leader()` bool the controller holds for reconcile + the global janitorial sweeps (`SweepExpiredAuthSessions`/`DeviceGrants`/`Handoffs`). Exposed as a small `internal/controller/leader.go` seam; on single-node bbolt there is exactly one process = always leader.
6. **`config.go`:** `Store string` (`bbolt|cockroach|postgres`), `DSN string`. `New()` chooses the impl (bbolt default). `validateForServe`: `store!=bbolt` requires a reachable DSN.
7. **bbolt → sqlStore bootstrap migration** tool/test: every bucket round-trips into the SQL schema.

### New interfaces / libs / data model
- `*sqlStore` (impl), `leader() bool`. **Libs (NEW):** `github.com/jackc/pgx` (+ `pgxpool`); CockroachDB (Apache-core) for the lab's 3-node cluster. Kept behind `sqlstore.go` so the default build doesn't compile it on the bbolt path. **Data model:** the §1.3 strong/eventual classification realized in SQL; deny/single-use/trust strong, presence/metrics eventual.

### Security MUSTs landed
§1 (global single-use serialization), §2/§3 (deny-path strong store), §6 (ConfigVersion CAS **and** agent-side (version,content-hash) fork-detect + fail-closed).

### Test / proof + lab + exit
- **Double-mint test:** two concurrent `UseToken` on the same token against a **3-node CRDB on the lab** → exactly one succeeds, one clean deny. **Fail-closed test:** kill CRDB quorum → new sessions/revokes refuse rather than stale-allow. **Migration test:** bbolt → sqlStore preserves all buckets. `store=cockroach` runs the full e2e battery identically to bbolt; bbolt default still zero-dependency.
- **Lab:** stand up 3-node CockroachDB on geneza1 (reused by P2/P4). Single controller still on VM 105.
- **Exit:** `store=cockroach` passes the full e2e battery; double-mint and fail-closed proven; CAS single-writer proven; bbolt byte-for-byte unchanged; `validateForServe` gates SQL on a reachable DSN.

### Risks
Cross-region SERIALIZABLE write latency on every token mint / CAS (size regions so a single-region partition keeps write quorum); the `PollDeviceGrant` closure atomicity must hold under SERIALIZABLE retry; the agent fork-detection must not false-trip on a legitimate re-sign at the same content.

---

## P2 — Multi-controller control-stream routing (NATS `natsRouter`)

**Goal.** Make the controller tier horizontally scalable: 2–3 controllers behind an LB sharing the P1 CRDB + a NATS cluster, with every control-plane push that assumes "the agent's stream is on THIS process" working when the agent (or session peer) homes elsewhere. Extract `streamRouter` over the in-proc `Registry` (local-handle-else-publish-to-owner), maintain an **epoch-fenced** `agent_id→controller` affinity directory in the shared store, route `SendOffer` over NATS request-reply (ack by session id), bridge session-p2p ICE signaling across controllers, make `revokeSession` fail-closed when the agent is remote (build ON C3), shard the continuous-authz sweep by held stream + fan suspensions over the bus, and stream per-controller audit chains off-box. **Single-node default (inproc router, nil bus, bbolt) stays byte-for-byte today.**

**Prerequisites.** **P1 COMPLETE** (shared strongly-consistent store — the affinity directory and routed-revoke durable-deny-first contract require it; `confirmRevokeDelivered`'s `s.store.UpdateSession` must hit a row both controllers see). **P0 COMPLETE** (scoped grant + per-message re-check S8 + agent pull S9 = the convergence floor under a partitioned/zombie controller). C3 done. **`validateForServe` HARD-FAILS if `router=nats` without `store!=bbolt`.** Lab extended: a 2nd controller VM, an LB (nginx L4 stream / haproxy on the hypervisor), a NATS cluster (≥3 `nats-server` core pub/sub + request-reply; 1 degrades but proves the path), the P1 CRDB reachable from both controllers. `go.mod` gains `github.com/nats-io/nats.go`.

### Ordered build steps
1. **Extract `streamRouter`, reconcile with `AgentDirectory`, default `inprocRouter`.** New `internal/controller/streamrouter.go` (§3.2). **`SendOffer` keeps the `turn *genezav1.TurnCreds` param** (grounded `registry.go:238`, `broker.go:26,366`) — dropping it regresses session-p2p on single-node. `inprocRouter` and `natsRouter` **implement `AgentDirectory`** (`Online`/`Services`/`SendOffer`); the broker's `b.agents` (`broker.go:24`) is swapped to the router so cross-controller offers actually route (don't leave both fields). Add `router streamRouter` to `Server` and default `&inprocRouter{reg: s.registry, sig: s.sessionSignals}` when no bus is configured. Registry method signatures UNCHANGED — the router is a layer ABOVE them.
2. **Epoch-fenced affinity directory in the `Store` interface + both impls.** Add `ClaimAgentAffinity(nodeID, controllerID string, now time.Time) (epoch int64, err error)` (monotonic epoch++, LWW owner); `AgentAffinity(nodeID string) (controllerID string, epoch int64, ok bool)`; `ReleaseAgentAffinity(nodeID, controllerID string, epoch int64) error` (**compare-and-delete** on owner+epoch so a zombie's stale release can't evict the live home). bbolt: global bucket `agent_affinity`, value JSON `{ControllerID, Epoch, UpdatedUnix}`, claim = `db.Update` RMW (single-writer lock makes epoch++ atomic on one node). sql: `agent_affinity(node_id PK, controller_id, epoch BIGINT, updated)`, claim = `INSERT … ON CONFLICT DO UPDATE SET epoch=agent_affinity.epoch+1 … RETURNING epoch` in a SERIALIZABLE txn. **Same `Store` method, identical semantics** on both impls. The epoch is the §12 fence token.
   - **2a. (NEW, from critic) Cross-controller `Services()`.** `Services(nodeID)` feeds `resolveService` (`broker.go:56`) and gates a grant for **named** services BEFORE minting. For an agent on gw-B, a `CreateSession` on gw-A must resolve its advertised services. Persist the agent's advertised services in the shared store at `Register`/hello time and read them there (or a routed request-reply). Without this, named-service access fails cross-controller even though the agent is healthy.
3. **Wire claim/release into the NodeControl lifecycle.** Right after `h := s.registry.Register(...)` (`nodecontrol.go:61`) call `ClaimAgentAffinity`, stash `affinityEpoch` on `agentHandle` (`registry.go:33`). In the deferred cleanup next to `registry.Unregister` (`nodecontrol.go:71`) call `ReleaseAgentAffinity` (compare-and-delete). The natsRouter per-agent subscription is created/torn-down in lockstep and gated on holding the current epoch.
4. **Build the `natsRouter`** (`internal/controller/natsrouter.go`, NEW). Subjects `agent.<ws>.<nodeID>.{offer,revoke,disco,modcfg,netcfg}` and `session.<sid>.{toagent,toclient}`. Each push: (a) `reg.Online(nodeID)` → local Registry method (fast path); (b) else `AgentAffinity` → no owner ⇒ `delivered=false` (owed); owner==self-but-not-online ⇒ owed; else publish to the owner's subject. **`SendOffer` via `nc.RequestWithContext`** correlated by session id, marshaling the **`turn` creds into the request payload** so the owning controller delivers them to its local handle. Propagate the existing `offerTimeout` (`broker.go:56`, 5s) into `RequestWithContext` so a remote no-ack degrades to the same "agent rejected/offline" deny the local path returns. Reconnect + short publish timeout so a NATS blip → `delivered=false` (owed, retried next tick), never blocks the broker.
   - **4a. (NEW, from critic) Epoch-gated DELIVERY re-read.** Every push handler, BEFORE invoking the local Registry method, MUST `AgentAffinity(nodeID)` and compare to the handle's `affinityEpoch`; **drop on mismatch**. This is a per-delivery store read (cached with the same short TTL as the P4 deny cache to bound cost). Re-read at DELIVERY time, not subscribe time, or a just-migrated agent gets a push on the old controller. This is the zombie split-delivery defense (§12) and is a numbered build step, not just a risk.
5. **Cross-controller session-signal bridge (§13).** Today `disco.go:48`/`sessionsignal.go` assume client-stream and agent-stream are co-resident; a remote peer's `SendDisco` returns "node not connected" and is silently swallowed (`slog.Debug`). Route `forwardClientSignalToAgent` (`sessionsignal.go`) through `router.BridgeToAgent` (local if here, else publish `session.<sid>.toagent`), and `forwardAgentSignalToClient` through `router.BridgeToClient` (local `sessionSignals.deliverToClient`, else publish `session.<sid>.toclient`). **A first-class durable `session_owner` directory row** `session_id → {clientControllerID, agentNodeID}` (Store method on both impls, **eventual / routes-not-authorizes**) — **the agent side resolves via the node affinity directory; the CLIENT side resolves via this `session_owner` row** (a client is not an agent and has no NodeControl affinity). Written at `CreateSession` on the client's controller; `sigEntry` (`sessionsignal.go`) gains `clientControllerID` set from `s.cfg.ControllerID`. Rebuilt on reconnect (disco is stateless, agents re-announce — a stale row only triggers a re-bridge retry). Bus carries opaque ICE candidates only (relay stays blind).
6. **Fail-closed routed `revokeSession` (build ON C3, do not re-fix).** **Grounded:** `revokeSession` (`continuousauthz.go:134`) does `pushed := s.registry.SendRevoke(...) == nil` (`:138`) then marks `RevokeDelivered=false` (`:143`). The ONLY change: replace the local-only `s.registry.SendRevoke` with `delivered, _ := s.router.SendRevoke(rec.NodeID, rec.ID, reason)` (local-else-publish). The durable deny already happens first (suspend path / the session-row write); the C3 invariant (`RevokeDelivered=false`, settled only by the agent's `"revoked"` ack via `confirmRevokeDelivered`, re-pushed on sweep + reattach) is UNCHANGED and now carries cross-controller because `rePushRevoke` (`:181`) and `redeliverPendingRevokes` (`:187`) also go through `s.router`. The audit `pushed` field becomes `routed ∈ {local, published, owed}`.
   - **Spec-reconciliation note (from critic):** the spec §4 says "MUST NOT mark+audit when remote and the push silently no-op'd." The C3 model **always** writes the durable session-row + audits `RevokeDelivered=false` honestly; it never claims *delivered*. Adopt this as the project's faithful rendering of §4: the durable session-row IS the durable record; the audit's `routed=owed` + `RevokeDelivered=false` is the honest no-op record; an owed (no-owner) revoke is re-pushed next sweep tick. Assert exactly this in test.
   - **TOCTOU note:** `SendRevoke`'s `delivered` is the SEND result only (C3 already treats it as unconfirmed); the router must NEVER upgrade a local send to "confirmed" — only the agent ack confirms.
7. **Shard the continuous-authz sweep by held stream + fan suspensions; split the three sweep lifetimes (§3, F5).** Today `reauthSweep` (`continuousauthz.go:41`) sweeps `ListAllSessions()` (`:61`) on every controller. **Split into three (corrected from critic — they're tangled in one function):**
   - (1) **per-process in-memory reaping** (`sessionSignals.sweepExpired`, `:60`) — runs on **EVERY** controller always (it's local in-memory state; must NOT be leader-gated).
   - (2) **global janitorial store deletes** (`SweepExpiredAuthSessions`/`DeviceGrants`/`Handoffs`, `:45/:50/:55`) — **leader-only** via the P1 advisory lock (else N controllers race the same global deletes).
   - (3) **sharded session re-eval** — each controller sweeps ONLY sessions whose `NodeID` it currently holds (`s.registry.Online(rec.NodeID)`), re-evaluating against the global-strong `IsSuspended`/`node.Approved`. Steady-state revoke is then a LOCAL push with a live handle. The **owed-revoke re-push branch** (`reauthSweep:79`) is sharded identically (only the holding controller re-pushes); `redeliverPendingRevokes(nodeID)` on the new owner's `Register` (`nodecontrol.go:107`) is the cross-controller convergence for a re-homed agent. The admin-kick edge (suspend on gw-A for an agent held by gw-B): `suspendPrincipal` (`:212`) publishes `authz.suspend.<ws>.<provider>.<subject>` so the holding controller tears down sub-second; the sharded tick is the backstop. `revokeBySubject`/`revokeUser` keep `ListAllSessions` (they target a principal fleet-wide, correct) but their `revokeSession` calls are now routed.
8. **Off-box per-controller audit chains keyed by `controller_id` (§15).** Keep per-controller chains (a shared global chain breaks `ChainOk` on concurrent append). Stamp `controller_id` (from `cfg.ControllerID`) into each off-box record; the off-box sink (`audit_sink.go`, already seamed) is unchanged — every controller points at the same destination, the auditor reconstructs global order by `(controller_id, seq, ts)`. Write the `principal_suspended` audit transactionally with the `SuspendPrincipal` row so the merge proves the deny even if the issuing controller dies between write and fan-out.
9. **Config + lab wiring.** `config.go`: `ControllerID` (default hostname), `Region` (P2 leaves `""`), `Router string` (`inproc|nats`, default `inproc`), `NATSURL`. `validateForServe`: `Router==nats` requires `NATSURL` non-empty AND `store!=bbolt` (fail closed at startup). `New()`: connect nats + `natsRouter` when `Router==nats`, else `inprocRouter`. Lab: `deploy/deploy-core.sh` templates `router/nats/controller_id`; add `deploy/deploy-gw-b.sh`, an LB nginx L4 fragment round-robining the two gRPC ports, a `geneza-nats.service` unit + `nats.conf`. Single-node deploy unchanged.
10. **Extend `scripts/e2e.sh` with HA-profile battle-tests** (gated on `GENEZA_HA=1`, single-node checks stay green): (a) client on gw-A + agent on gw-B → session establishes (cross-controller `SendOffer` + signal bridge), **incl. a NAMED service** (proves 2a); (b) admin kick on gw-A tears down the gw-B tunnel sub-second (headline hole); (c) partition gw-B as a zombie while the agent re-homes to a 3rd controller → revoke lands via epoch fencing + agent pull, no split-delivery; (d) drop all NATS invalidations → revoked cert denied within deny-cache TTL (§18); (e) kill a controller mid-session → E2E tunnel SURVIVES (data path never touched the controller), agent reconnects + re-syncs; (f) double-mint guard across 2 controllers (P1 SERIALIZABLE, assert here too).

### New interfaces / libs / data model
- `streamRouter` (§3.2); `inprocRouter`/`natsRouter` implementing it + `AgentDirectory`. Store: `ClaimAgentAffinity`/`AgentAffinity`/`ReleaseAgentAffinity` + the `session_owner` directory methods + the advertised-services read. NATS subjects as above. Config: `ControllerID`/`Region`/`Router`/`NATSURL`.
- **Lib (NEW):** `github.com/nats-io/nats.go` (kept behind `natsrouter.go` so the default build doesn't compile it). pgx (P1 prereq).
- **Data model:** `agent_affinity` (epoch fence token, compare-and-delete release); `session_owner` (eventual, routes-not-authorizes); existing `SessionRecord` reused (cross-controller revoke flips `RevokeDelivered` via the SHARED row when the ack lands on the owning controller). NATS messages are EPHEMERAL transport (opaque proto bytes + `authz.suspend` fan-out), never system-of-record.

### Security MUSTs landed
§4 (no silent cross-controller revoke loss, routed fail-closed), §12 (epoch-fenced affinity + epoch-gated delivery), §13 (session-signal bridge), §3 (global-strong suspension + sharded sweep + bus fan-out), §15 (per-controller audit off-box), §18 (deny within cache TTL).

### Test / proof + lab + exit
Unit: inprocRouter delegates identically (incl. `turn` pass-through); affinity Claim bumps epoch monotonically; Release is a no-op when a newer epoch owns the row; natsRouter (in-memory nats-server harness) `SendOffer` round-trips `accepted/reason` **with turn**; epoch-gated delivery DROPS on mismatch; routed `revokeSession` keeps `RevokeDelivered=false` until `confirmRevokeDelivered` on the shared row; owed (no-owner) revoke re-pushed next tick; sharded sweep selects ONLY held agents; `suspendPrincipal` publishes `authz.suspend` once. Lab: the 6 HA-profile checks above. Race/load: single-node battery under `-race` (no behavior change); 50 concurrent cross-controller sessions + a burst of admin kicks (battle-test, no silent loss, no split-delivery under A→B→A churn).
- **Exit:** single-node `scripts/e2e.sh` byte-for-byte unchanged (`-race` green, no new dep on the default path); cross-controller session (incl. named service) establishes; admin kick on gw-A tears down gw-B sub-second with `RevokeDelivered` flipping only after the ack; zombie test (stale epoch drops its subscription, no split-delivery); drop-all-NATS denies within TTL; controller-death-mid-session tunnel survives + re-claims affinity (epoch++ fences the dead one); double-mint across controllers exactly-one-wins; off-box N-chain merge validates.

### Risks
NATS request-reply on the broker critical path (mitigated by propagating `offerTimeout`); affinity epoch flap races (delivery-time re-read, step 4a); sharding could leave an agent un-swept for one tick under a brief affinity error — the P0 agent pull is the floor, **verify it fires under this exact condition** (don't assume); Registry methods return plain `error` — translate "node not connected" → `delivered=false` (owed) carefully; `nats.go` transitive deps must not break the minimal build (kept behind `natsrouter.go`); cross-controller ack travel (the ack lands on the owning controller which `confirmRevokeDelivered`s the shared row; idempotent confirm + `RevokeDelivered` read guards double-push).

---

## P3 — DERP relay fleet (signed map + closest-pick + per-region secrets)

**Goal.** Turn the single co-resident relay + one global TURN secret + `relayAddrs[0]`-pinned grant into a signed, regionally-sharded DERP fleet: a per-relay-identity `Relays[]` map inside the already-signed `ClusterConfig` (tampered map rejected like a forged config); client/agent STUN-RTT closest-pick; a signed relay CANDIDATE LIST from the intersection of both peers' regions replacing the `relayAddrs[0]` pin; per-region TURN secrets with overlap-window rotation + a region tag in the opaque coturn-REST username the relay validates; per-region relay registrars (heartbeat → UPSERT) feeding a leader-only debounced map rebuild; agent verification of the relay's presented server-cert identity against the signed map entry; fungible ICE re-pick on blackhole. Closes §10, §11, §14, §16, §19. **Single-node (one local relay, one secret, one region) stays byte-for-byte today.**

**Prerequisites.** **P1** `ConfigVersion` CAS (the map rebuild is a globally-linearizable CAS — on bbolt it degrades to the existing `Put`) **and P1 advisory-lock leader** (the debounced rebuild is leader-only; correction: leader is a **P1** deliverable, not P2). **P0** scoped-grant floor (the candidate list rides the signed grant; the agent ICE-picks within it). **Decision before coding:** region assignment is a **static signed-config/operator input** in `relay.yaml`/`controller.yaml`, NOT geo-IP (geo is a hint, the signature is the truth). Spawn a decisional agent if contested.

### Ordered build steps (additive types FIRST — see §2)
1. **Data model: `RelayNode` + `RegionID` in the signed `ClusterConfig` (the trust spine).** `internal/types/cluster.go`: `type RelayNode struct{ RegionID, RelayID string; Addrs []string; STUNPort, TURNPort int; RelayCertPub []byte }`; extend `ClusterConfig` (today `ConfigVersion/CARootsPEM/GrantKeys/AgentPolicy/RelayAddrs`, `cluster.go:32`) with `Relays []RelayNode` ` `json:"relays,omitempty"` `. Keep `RelayAddrs` for the legacy relay-TCP floor. Add `RelaysByRegion()` and `RelayByID()`. `VerifyClusterConfig` UNCHANGED — `Relays[]` rides the same signed envelope, so a tampered relay list fails ed25519 verify like a forged config (§11, no new trust root). **Land this step + step 8's `types.RelayCandidate` FIRST as additive no-behavior-change.**
2. **Per-region TURN secrets + region tag + overlap rotation — migrate BOTH minters.** **Grounded:** `turnCredsFor` (`turncreds.go:30`, overlay/Network flows) mints under the single `RelaySharedSecret` (`:44`); **`sessionTurnCreds` (`turncreds.go:91`, session-p2p — the path that actually reaches relays today via `SessionOffer.Turn`) mints with user `"sess-"+sessionID`**. The source plan migrated only `turnCredsFor`; **both** must move or the session path keeps the global secret and the new AuthHandler rejects every session-p2p cred. Changes:
   - Config gains `RelaySecrets map[string]RegionSecret{Current, Previous string; RotatedAt time.Time}` keyed by RegionID (keep `RelaySharedSecret` as the **default region** for single-node back-compat).
   - **Username region tag — corrected encoding (from critic).** `turn.GenerateLongTermTURNRESTCredentials(secret, user, ttl)` **already prepends the timestamp** (`username = <expiry>:<user>`). So pass the region in the **user arg only**: `user = <region>:<opaqueRand>` (and `sessionTurnCreds` → `user = <region>:sess-<sessionID>`), yielding `<expiry>:<region>:<rand>`. Do NOT reshape `opaqueSessionID` to include the expiry (that double-stamps). Centralize username construction in one helper so both producers tag identically.
   - **Empty-region canonical form:** single-node uses region tag `"default"` (NOT `""`) to avoid empty-segment parse ambiguity in the `<expiry>:<region>:<rand>` split. Add the single-node relay-auth round-trip to the regression e2e (cardinal-constraint gate).
   - The relay AuthHandler (`turnserver.go:37`, today `turn.LongTermTURNRESTAuthHandler(sharedSecret, log)` — note it `strconv.Atoi`s the whole username, so a custom handler is mandatory the moment any `:` tag is added) is replaced by a custom closure: parse the region tag, look up THAT region's `{Current, Previous}` (relay holds only its OWN region's secret — a leaked relay secret forges only its region, §10), accept under current OR previous (overlap, §16), reject a foreign-region tag. Stateless recompute-and-verify. Cred validity window ≤ overlap window (config-validate rule, §16).
   - Rewrite `turnCredsFor` → `turnCredsFor(selfID, peerID string, regions []string) (creds map[string]TurnCred, controlling bool, err error)` (one cred per region in the candidate set — §14/§16 two-cred cross-region minting).
3. **Broker: relay CANDIDATE LIST from region intersection, replacing `relayAddrs[0]`.** Grounded pins: `broker.go:308` `RelayAddr: b.relayAddrs[0]`, `broker.go:392` returns `grant.RelayAddr`. Add to `SessionGrant` (`grant.go`, after `RelayAddr`) `RelayCandidates []RelayCandidate{RegionID, RelayID, TurnURL, TurnUser, TurnPass, Realm}` — the SIGNED candidate list (inside the grant, re-verified by the agent like the rest). Keep `RelayAddr/RelayToken` as the legacy floor until task #18. Broker selector `selectRelayCandidates(clientRegion, agentRegion string) []RelayNode` = relays whose RegionID ∈ `{clientRegion} ∪ {agentRegion}`, sourced from the in-memory signed `ClusterConfig` (`s.setClusterConfig`). For each chosen region, call the new `turnCredsFor(...regions)`. **Mixed-upgrade safety (from critic):** an unset node Region and an unset relay RegionID both canonicalize to the **default** region; selection falls back to the signed **default-region slice** (NOT `relayAddrs[0]`) when a peer's region is unknown — fail-OPEN to the single default region only, never across explicit regions. The agent's home region comes from `NodeRecord.Region` (persisted at enroll/hello, step 6d); the client's from the user-cert/identity. Wire `NewBroker` to take the cluster-config accessor + region resolver. Single-node: length-1 candidate list, behaviorally identical.
4. **Client/agent STUN-RTT closest-pick + fungible ICE fallback.** `p2p/ice.go`: `Config` gains `Candidates []RelayCandidate`; add `probeRTT(ctx, candidates) []RelayCandidate` (a single `pion/stun` Binding request + RTT timing — netcheck-lite, no new protocol) returning candidates sorted by RTT; feed the full sorted set into the pion `ice.Agent` URL list (pion picks the lowest-latency working pair internally). Explicit re-pick guard: on `Connect()` failure with >1 candidate, re-run excluding the blackholed `RelayID` (§11). Mirror the `Candidates` wiring into `internal/vpn/icebind.go` and `internal/agentd/wg_userspace.go`. Single-node: length-1, probe is a no-op.
5. **Relay server-cert-vs-map identity verification (the rogue-relay gate, §11).** **Corrected anchor (from critic):** the source plan pinned this to the TCP floor at `offer.go:118-120`, but **the live TCP dial is `offer.go:131`** (`tls.DialWithDialer(... grant.RelayAddr, &tls.Config{RootCAs: w.rootPool()})`, no identity pin) **and task #18 is slated to DELETE the relay-TCP floor.** So: enforce `VerifyPeerCertificate` (assert the relay leaf's `geneza://relay/<name>` URI == the signed map entry) on the TCP floor **while it exists** (bonus), but make the **load-bearing §11 control the surviving TURN/UDP path**: signed-map `RelayCertPub` + region-secret containment (§10) + the agent's signature re-verification of the `RelayCandidate` list inside the already-signed grant. Document that per-packet relay-identity on UDP-TURN is a STUN/TURN protocol limit; the defense-in-depth is region-secret containment + map-signed addrs + E2E Noise blindness (a rogue relay sees only ciphertext). Coordinate ordering with task #18. The `geneza://relay/<name>` URI is already on the relay leaf (`ca.go` `KindRelay` issue) — no CA change, just the agent-side check.
6. **Per-region relay registrar (heartbeat → UPSERT) + leader-only debounced map rebuild (§19).** No relay-registration path exists today. Add: (a) a registrar endpoint (mTLS with the relay's `geneza://relay/<name>` cert) where a relay heartbeats `{RegionID, RelayID, Addrs, STUNPort, TURNPort, RelayCertPub, healthy}`; the registrar health-checks via a STUN ping before accepting. (b) Store: `bucketRelays = "relays"` (global, keyed `(RegionID,RelayID)→{RelayNode,lastSeen}`); `UpsertRelay`/`ListRelays(region)`/`ExpireStaleRelays(ttl)` (eventual presence data, NOT deny-path). (c) **Leader-only debounced rebuild** (one rev per window, e.g. 10s): the leader coalesces relay-bucket changes, rebuilds `Relays[]`, bumps `ConfigVersion` via the **P1 CAS**, re-signs (`buildClusterConfig` + `signClusterConfig`), `SetSignedClusterConfig`. Agents PULL on their existing schedule — NOT a per-flap broadcast. (d) Persist `NodeRecord.Region` at enroll/hello (`AgentHello` gains region). **(e) Single-node relay injection — corrected site (from critic):** populate `Relays[]` **inside `buildClusterConfig` (`server.go:415`)** from `cfg.RelayAddrs` with `RegionID="default"`, so BOTH `init.go` AND `reconcileClusterConfig` (`server.go:459`) emit the same `Relays[]` — patching only `init.go` would let a restart-reconcile drop the relay map. No registrar runs on single-node; no debounce.
7. **`turnserver.go` PermissionHandler + QuotaHandler (relay-side abuse caps).** Add a PermissionHandler scoping which peer addresses an allocation may permission (the relay is blind but must not be an open proxy — scope to the fleet's overlay/relay address space + advertised routes, NOT a hardcoded allowlist, or it breaks VPN route targets) and a QuotaHandler bounding per-allocation bandwidth/count. Both nil-able; single-node default permissive (matches today). pion/turn v5 `ServerConfig` exposes these seams.
8. **Proto + wiring: carry the candidate list to client and agent.** `control.proto` already has `TurnCreds` (`turn_url/username/password/realm/controlling`) on `WGPeer.turn`, `SessionOffer.turn` (**populated, `registry.go:251` — corrected**), `CreateSessionResponse.turn`. Add `repeated TurnCreds candidates` (or a `RelayCandidate` message with `region_id+relay_id+TurnCreds`) to `SessionOffer`, `CreateSessionResponse`, `WGPeer`; regen. Populate: `broker.go` `SendOffer` carries the agent's candidate list; `CreateSessionResponse` carries the client's; `networkpush.go` `WGPeer` for the VPN path. **Always populate the scalar `turn` with `candidates[0]`** for back-compat with un-upgraded agents (never strand old agents on a length mismatch).

### New interfaces / libs / data model
- `types.RelayNode`, `ClusterConfig.Relays[]`, `RelaysByRegion`/`RelayByID`, `types.RelayCandidate`, `SessionGrant.RelayCandidates`. `turnCredsFor(... regions []string) (map[string]TurnCred, ...)` + `sessionTurnCreds` migrated. `RegionSecret` + `Config.RelaySecrets`; `relay.Config.RegionID`+`Secrets`. Store `UpsertRelay`/`ListRelays`/`ExpireStaleRelays` + `bucketRelays`. `registrar.go` + `leaderMapRebuilder`. `p2p.Config.Candidates` + `probeRTT` + re-pick loop. Custom relay AuthHandler + PermissionHandler + QuotaHandler. `NodeRecord.Region` + `AgentHello` region. proto candidates field.
- **Libs:** all EXISTING — `pion/turn v5`, `pion/ice v4`, `pion/stun v3`, `crypto/ed25519` (map signed by the existing GrantKeys, no new signing lib). pgx (P1) only relevant in HA mode for the CAS/UPSERT.
- **Data model:** signed map (trust spine, inside the signed `ClusterConfig`, CAS on rebuild); `bucketRelays` (eventual presence, rebuilt from heartbeats — NOT deny-path); per-region TURN secrets (controller mints, relay holds only its own region's `{Current,Previous}`); region-tagged stateless coturn-REST username; `SessionGrant.RelayCandidates` (signed); `NodeRecord.Region`.

### Security MUSTs landed
§11 (signed map + per-relay identity, UDP-path caveat documented), §14 (grant candidate list, not `relayAddrs[0]`; two-cred cross-region), §10 (per-region secrets, leaked secret caps to one region), §16 (per-region secret validation — see correction below), §19 (per-region registrar + leader-debounced rebuild, no map-churn broadcast storm).

> **Implementation correction (§16 rotation).** The build steps above (and the §16 spec, since amended) called for relay-side overlap rotation — the relay accepting current+previous secret during a window. This is **infeasible** with `pion/turn`: its `AuthHandler` returns a single integrity key per username, so a relay cannot try two secrets for one credential. The shipped design validates against the region's **Current** secret only; rotating a region's secret is a **synchronized flag-day** (controller + every relay in the region swap Current together). `RegionSecret.Previous` was removed. Leak-confinement (a leaked secret forges only its own region) is unchanged; only zero-downtime rotation is deferred, and would require widening the username to `<expiry>:<region>:<keyver>:<id>` so the relay can select the key version. The unit/lab "previous-secret cred validates in the overlap window" check below is replaced by the synchronized-rotation check.

### Test / proof + lab + exit
Unit: signed `Relays[]` round-trips Sign/Verify; one flipped byte fails Verify; candidate list inside a grant survives Sign/Verify, mutation rejected; a cred minted under region eu validates at the eu relay and is REJECTED at a us relay (region tag, §10); a previous-secret cred validates in the overlap window, rejected after (§16); **`sessionTurnCreds` output validates at the matching-region relay** (the migration test the source plan would have missed); `selectRelayCandidates` same-region → one region, cross-region → union, unknown region → default-region fallback (NOT `relayAddrs[0]`); `probeRTT` sorts lowest-first; `Connect()` re-picks past a blackhole. Lab (2 simulated regions: VM 106=eu, VM 107=us, `tc netem` RTT deltas): closest-pick selects eu; cross-region rendezvous on a shared relay (two creds); rogue-relay reject (broken map signature / cert!=map entry / not-in-map); blackhole → ICE failover no session loss; secret-leak/rotation (one region rotates alone, other unaffected, live floors survive the overlap window); relay-churn (100s of flapping heartbeats → ≤1 ConfigVersion rev per debounce window, no agent broadcast storm); **mixed-upgrade check** (unset region nodes still rendezvous via default region); **single-node relay-auth round-trip** (the cardinal regression gate). Relay-side: PermissionHandler denies off-fleet addr; QuotaHandler caps a runaway allocation.
- **Exit:** single-node `scripts/e2e.sh` green (one relay, one secret, default region, byte-for-byte); closest-pick proven; cross-region rendezvous; rogue-relay rejected; blackhole failover; secret rotation isolated; relay-churn debounced; `broker.go` no longer references `relayAddrs[0]` for new sessions (signed candidate list); both TURN minters region-tagged; relay validates per-region secret + region tag + runs Permission/Quota handlers.

### Risks
Session-p2p cutover collision with task #17/#18 (land additive types first); UDP-TURN has no per-packet relay-identity (documented limit, not a code gap — region-secret containment is the real control on UDP); ConfigVersion CAS hard-dependency on P1 (don't build the rebuild on a bbolt plain-Put); region-assignment policy fork (static config, decisional if contested); overlap-window mis-sizing (config-validate cred-TTL ≤ window); back-compat scalar `candidates[0]`; PermissionHandler over-restriction breaking VPN route targets (scope to overlay + advertised routes); the §11 cert check pinned to a task-#18-doomed TCP path (anchor to the surviving UDP path's containment, correct the cited line to `offer.go:131`).

---

## P4 — Regional cells + global deny/trust tables + per-cell CA/grant scoping

**Goal.** Stand up two regional controller CELLS (each its own LB + NATS + store replica + intermediate CA + scoped grant key + DERP slice); back the deny-path/single-use/trust set with CRDB **GLOBAL** tables read fail-closed on every authenticated RPC; harden cross-cell trust: per-cell X.509 intermediate CAs under the one offline root with URI name constraints + a strongly-replicated intermediate-denylist the agent checks; a **separated/threshold** `ClusterConfig` trust-set signing key distinct from per-controller grant keys; geo-DNS as a signed-config-gated bootstrap hint; an eventual cross-cell routing directory that routes-not-authorizes; partition fail-closed asymmetry with a local-deny escape valve. **Single-node `bbolt` + inproc + one self-signed intermediate + one grant key stays the byte-for-byte default; every P4 mechanism is additive, nil-gated behind the seams, and `region:""`.**

**Prerequisites.** **P0 + P1 + P2 + P3 ALL landed** (P4 reimplements none of them — it marks tables GLOBAL and adds the PKI/trust-set/directory/geo-DNS/local-deny layers). Specifically depends on: P0 scoped grant + durable workspace + `EvaluateOffer`; P1 `sqlStore` + SERIALIZABLE + `ConfigVersion` CAS + advisory-lock leader; P2 NATS router + affinity + routed revoke + off-box audit; P3 signed `Relays[]` map + per-region TURN secrets. C3 done (P4 only extends the deny READ to GLOBAL + fail-closed; does not re-touch the confirmation model).

### Ordered build steps
**S1 — Promote deny-path + single-use + trust-set to CRDB GLOBAL tables.** In the P1 `sqlStore`, `ALTER TABLE … SET LOCALITY GLOBAL` for `revoked_certs`, `suspensions`, **node `Approved` flag** (see S1-note), `tokens`/`device_codes`/`user_codes`/`handoff_codes`/`os_enroll`/first-admin, `node_ws` index, `cluster_config`. Workspace-scoped tables (nodes/networks/subnets/bindings/sessions) stay `REGIONAL BY ROW` homed to the owning cell. Pure schema/locality change behind the `Store` interface — no method-signature change, bbolt default untouched.
   - **S1-note (NEW, from critic — resolve the contradiction):** the source plan listed the `Approved` flag GLOBAL in prose but left the `nodes` table REGIONAL (`SetNodeApproval` `store.go:590` writes `Approved` on the `NodeRecord`). `Approved` is a deny gate read on the admission/reauth hot path (`broker.go:232`, `continuousauthz.go`); a stale regional replica could admit a just-quarantined node (§ medium-1). **Decision:** make the `Approved` flag a GLOBAL row keyed `(ws, nodeID)` (split it off the REGIONAL `NodeRecord`), so node admission/approval is read-your-writes fleet-wide on the hot path.
- Files: `internal/controller/sqlstore.go`, `internal/controller/sqlschema.sql`, `internal/controller/store.go`.

**S2 — Fail-closed deny-path reads with short-TTL cache (§2/§4/§9/§10/§17/§18).** **Grounded:** `IsCertRevoked`/`IsSuspended` return bare `bool` with NO error path; on a bbolt View error `IsCertRevoked` silently returns false (allow). Add error-returning twins `IsCertRevokedE`/`IsSuspendedE` on `sqlStore`; a new `denyCache` (`internal/controller/denycache.go`) wraps the deny reads with a short TTL (low single-digit seconds, positive AND negative entries) so a lost NATS invalidation extends access by at most the TTL; on store-unreachable the cache fails to **deny** once the entry lapses. `checkNotRevoked`/`checkNotSuspended` (`auth.go:179,196`) route through it.
   - **S2-note (NEW, from critic — preserve exemptions + single-node fail-open):** `checkNotRevoked`/`checkNotSuspended` today return nil (ALLOW) when `identityFrom` fails or the cert has no Subject (operational/break-glass/node certs, `auth.go:194` deliberately exempt). The fail-closed path applies **after** the exemption gate — never flip those to deny on a store blip. **Scope fail-closed to the `sqlStore`/global path only**; keep `bboltStore`'s `IsCertRevoked` **fail-open-on-local-read-error** (a local bbolt error is not a partition), preserving the single-node byte-for-byte claim. Test: break-glass/node cert still authenticates during a simulated store-read error; a user cert is denied (global path).
   - Also consult the strong revocation set in the **agent-side in-handshake re-verify** (`offer.go:163` callback — today checks only `g2.ID` + noise key, never cert revocation): add a revocation consultation there via the P0 heartbeat pull hook (§2/§4 explicitly flag this site).
- Files: `internal/controller/auth.go`, `internal/controller/denycache.go` (NEW), `internal/controller/sqlstore.go`, `internal/agentd/offer.go`, `internal/agentd/worker.go`.

**S3 — Per-cell intermediate CA under the offline root, with X.509 URI name constraints (§8, defense-in-depth).** `ca.IssueIntermediate(rootSigner crypto.Signer, rootCert *x509.Certificate, cellID string, permittedWorkspaces []string) (*ca.CA, error)`: a new intermediate with `NameConstraints` (OID 2.5.29.30, `uniformResourceIdentifier` subtrees `geneza://node/<ws>/`, `geneza://user/<ws>/`). Keep `newSerial` = 128-bit random (`ca.go:85`) UNCHANGED — no per-cell counters (§9). Each cell loads its own `intermediate-ca.key` behind the existing `crypto.Signer` seam. The offline root signs each cell intermediate **out of band** (`cmd/geneza-ca`), never online.
   - **S3-note (from critic — DEMOTE the name constraint to defense-in-depth):** Go's `crypto/x509` enforces `PermittedURIDomains` as **HOST-based**, NOT path-prefix — `geneza://node/<ws>/` path-subtree is **NOT enforced** by standard `Verify`. **Add a unit test against Go's actual `x509.Certificate.Verify`** documenting the real (non-)enforcement. The **load-bearing containment for §8 is the strongly-replicated intermediate-denylist (S4) + the P0 agent-side `WorkspaceID==self` scope check** — the name constraint is defense-in-depth only (or implement an agent-side custom verify that the leaf URI workspace ⊆ the intermediate's permitted set, if the constraint is to be real).
- Files: `internal/ca/ca.go`, `internal/ca/intermediate.go` (NEW), `cmd/geneza-ca/main.go`.

**S4 — Agent-side intermediate-denylist check (fail-closed; standard x509 will NOT do this — §8).** Add `IntermediateDenylist []string` (intermediate SKI hex / serial) to the signed `ClusterConfig` (rides the same signature trust). On every NodeControl re-attach AND inside `EvaluateOffer`, after the leaf chain verifies to root, compute the intermediate's SKI/serial and DENY if present. Controller side: `RevokeIntermediate(ski, *RevokedIntermediate)` + `IsIntermediateRevoked(ski)` writing a new global intermediate-denylist table + bumping `ClusterConfig`. Name-constraint (S3) blocks cross-cell mint; denylist (S4) kills a compromised in-cell intermediate fleet-wide without a root rotation.
- Files: `internal/types/cluster.go`, `internal/agentd/offer.go`, `internal/agentd/worker.go`, `internal/controller/store.go`, `internal/controller/sqlstore.go`.

**S5 — Separate trust-set (`ClusterConfig`) signing key from per-controller grant keys; threshold/offline (§6/§7).** **Grounded:** today `signClusterConfig` (`server.go:425`) signs `ClusterConfig` with the SAME grant key that `broker.go` signs grants with, so any single running controller can rewrite the fleet trust set. Add `TrustKeys []TrustKey{KeyID, PublicKey}` to `ClusterConfig` (separate from `GrantKeys`); `VerifyClusterConfig` (`cluster.go:54`) verifies the config envelope against `TrustKeys`, `VerifyGrant` against `GrantKeys`. A running controller holds only its grant key + cell intermediate; it CANNOT mint a new `ClusterConfig` alone. Reconcile becomes: the controller proposes a candidate, the offline/M-of-N `geneza-trust` tool signs it, the controller CASes it in. Single-node: the one key fills BOTH roles (`TrustKeys == GrantKeys`, one entry) so today's path is byte-for-byte. Agent treats `AgentPolicy` as most-restrictive of a locally-pinned floor and the pushed value (S5-note).
   - **S5-note (NEW, from critics — the agent-side pivot is the load-bearing, omitted part):** the agent's `parseAndCheckClusterConfig` (`state.go:189`) + `worker.go` config-apply today derive the verify map from the config's OWN `GrantKeys` (`TrustedKeys()`, `cluster.go:41`). For `TrustKeys` to be a real trust root the agent MUST verify each incoming config against the `TrustKeys` it ALREADY holds (pinned, like CARoots), NOT the incoming config's keys — else a config could rotate its own trust root. Add `types.ClusterConfig.TrustedConfigKeys()` and wire `state.go`/`worker.go` to it. **Two-version overlap** for `TrustKeys` rotation (mirrors the §6/§7 CA-root two-version overlap, which must also be implemented for `CARootsPEM` on the agent's trust-bundle update — flagged uncovered by critics). **Back-compat migration:** when a loaded `ClusterConfig` has empty `TrustKeys`, treat `GrantKeys` AS `TrustKeys` (fail-open ONLY when `TrustKeys` is absent, never when present-but-non-matching) — `omitempty`, same pattern as P0's `GrantKeyScope`. Upgrade test: a pre-P4 config still self-verifies via `GrantKeys`; a config signed only by a `GrantKey` (not a `TrustKey`) is rejected once `TrustKeys` is present.
   - **§7 AgentPolicy most-restrictive floor (NEW build step, flagged uncovered):** add a locally-pinned `AgentPolicy` floor in `agentd/state.go` and a most-restrictive merge in the agent's policy-apply path (`worker.go` `agentPolicy()`) — push can tighten, never loosen. Test: push tightens, cannot loosen.
   - **§7 independent NetworkConfig route/VNI ceiling (NEW build step, flagged uncovered):** bound the pushed `NetworkConfig` (`networkpush.go` → agent WGPeer apply) routes/VNI against the agent's enrolled workspace (a failed-over/compromised controller pushing a foreign VNI/route is ceiling-checked).
- Files: `internal/types/cluster.go`, `internal/types/grant.go`, `internal/controller/server.go`, `internal/controller/init.go`, `internal/agentd/worker.go`, **`internal/agentd/state.go`** (the omitted file), `internal/agentd/enroll.go`, `cmd/geneza-trust/main.go` (NEW).

**S6 — Cell topology + scoped grant key per cell + DERP slice.** `controller.Config` gains `Region`/`CellID` (`region:""` ⇒ no cells). Each cell's controllers load that cell's intermediate-ca.key (S3) + a cell-scoped grant keypair whose `GrantKey.Scope` (P0) is the cell's workspace/region set; all cells' grant pubkeys + the cell's `TrustKeys` are published in the global signed `ClusterConfig` (any cell's leaf+grant verifies fleet-wide via the one root + the `GrantKeys` union). `buildClusterConfig` (`server.go:415`) emits the full per-cell `GrantKeys[]` union (leader-assembled from a global controllers table). DERP slice = the cell's region subset of the P3 signed `Relays[]` (broker candidate selection already does intersection-of-regions in P3; P4 ensures the cell offers its own region slice). **Land S5 strictly before S6** (the moment >1 grant key is in the union, a controller re-signing `ClusterConfig` with its grant key is the §7 hole).
- Files: `internal/controller/config.go`, `internal/controller/server.go`, `internal/controller/broker.go`, `internal/types/cluster.go`.

**S7 — Geo-DNS as signed-config-gated bootstrap hint + mTLS controller pin (§20).** Add `ControllerEndpoints []ControllerEndpoint{CellID, Region, Addr, Name}` to the signed `ClusterConfig`. The agent resolves `gw.<cluster>.geneza` via geo-DNS (UNTRUSTED hint), then REQUIRES the dialed controller to (a) present a `geneza://controller/<name>` mTLS server cert chaining to root (`ca.go` `KindController`), and (b) be in the signed `ControllerEndpoints` set. **Concrete site (from critic — the source named the requirement but not the code):** the live agent dial (`worker.go` grpc conn) does standard `RootCAs` verification with NO server-identity pin — add `VerifyPeerCertificate`/`ServerName` pinning to `geneza://controller/<name>` + the `ControllerEndpoints` membership check at that exact dial site, and in `enroll.go` `obtainCARoots`/Enroll. A spoofed DNS answer outside the signed set is refused; the real safety net stays F3's scope binding (a mis-route fails-and-retries, never over-grants).
- Files: `internal/types/cluster.go`, `internal/agentd/worker.go`, `internal/agentd/enroll.go`, `internal/controller/server.go`.

**S8 — Cross-cell routing directory (eventual, routes-not-authorizes) + the concrete cross-cell `CreateSession` path.** Add an eventual `workspace→cell` directory: `DirectoryLookup(ws) (cell, ok, err)` / `PutDirectory(ws, cell)` (NOT global-strong — routes only; rebuilds on reconnect; never read on the deny path). When a client lands on cell-B for a workspace homed to cell-A, **the concrete mechanism (from critic — the source hand-waved "redirect or proxy"):** cell-B returns a signed gRPC **redirect** (`go to cell-A's `ControllerEndpoints` entry`) the client dials (client gains redirect-follow in `userapi.go`), OR cell-B proxies the request to cell-A over the cross-cell superlink carrying the client's verified identity, and **cell-A re-checks the global deny set + mints the grant with ITS scoped key** (which the client already trusts via the global `GrantKeys` union). Pick one (recommend signed-redirect — simpler, keeps cell-A the sole authenticator), name the files, add an e2e check. **§ MUST #1 distinction (from critic):** single-use credential redemption (token/device-code/handoff/os-enroll) MUST be **hard-rejected at a non-owning cell, NOT routed** (the P1 SERIALIZABLE CAS is in-place at the owning cell); only workspace-scoped session brokering is redirected. A stale directory entry causes a redirect/retry, never an over-grant (the owning cell is the sole minter; cross-cell grant forgery is blocked by S5 scope + S3/S4 intermediate containment).
- Files: `internal/controller/directory.go` (NEW), `internal/controller/broker.go`, `internal/controller/userapi.go`, `internal/controller/sqlstore.go`, `internal/controller/store.go`.

**S9 — Partition fail-closed asymmetry + local-deny escape valve (§17).** Deny-path READS fail closed on global-store-unreachable (S2 cache TTL is the only allow-extension). Add a region-local deny table (`localdeny.go`, a strict subset of the global deny — can never under-deny): a cell can always write a LOCAL suspension/revocation its own controllers honor INSTANTLY without global quorum, replicated to the GLOBAL table on heal. `IsCertRevoked`/`IsSuspended` check (global-cached OR local-deny) ⇒ deny if EITHER hits. Suspend/revoke WRITES surface a HARD error to the admin on global-quorum loss (never silent success) but still write the local deny. **Alarm the "cannot issue new global deny" state loudly — concrete artifact (from critic):** a named metric (e.g. `geneza_global_deny_write_unavailable`) in `metrics.go` + a typed audit event, both tested (not prose). Invariant: losing quorum may BLOCK new access and block NEW global denies, but never silently allows a denied principal.
- Files: `internal/controller/auth.go`, `internal/controller/localdeny.go` (NEW), `internal/controller/sqlstore.go`, `internal/controller/continuousauthz.go`, `internal/controller/metrics.go`.

### New interfaces / libs / data model
- `ca.IssueIntermediate(...)`; Store `IsCertRevokedE`/`IsSuspendedE`, `RevokeIntermediate`/`IsIntermediateRevoked`, `WriteLocalDeny`/`LocalDenyHit`, `DirectoryLookup`/`PutDirectory`; `denyCache`; `types.TrustKey` + `ClusterConfig.TrustKeys[]` + `TrustedConfigKeys()`; `ClusterConfig.IntermediateDenylist[]` + `ControllerEndpoints[]`; `Config.Region`/`CellID`; `cmd/geneza-trust` (M-of-N signer). `Approved` split to a global `(ws,nodeID)` row (S1-note).
- **Libs:** pgx + CockroachDB (GLOBAL table locality via DDL — P1 dep, reused); nats.go (P2 dep); `crypto/x509`+`crypto/x509/pkix` (NameConstraints — already imported); `crypto.Signer` (existing seam, KMS/HSM opt-in for intermediates); pion/turn v5 (P3, unchanged). NO new protocol libs.
- **Data model:** GLOBAL (region-replicated, read-local/write-quorum, fail-closed) — `revoked_certs`, `suspensions`, `intermediate_denylist` (NEW), node `Approved` global row, single-use creds (SERIALIZABLE from P1), `node_ws`, `cluster_config` (CAS on version). CELL-LOCAL (REGIONAL BY ROW) — nodes/networks/subnets/bindings/sessions, per-controller audit chains. EVENTUAL — `workspace→cell` directory (NEW), node→controller affinity (P2), presence/metrics. REGION-LOCAL ESCAPE VALVE — `local_deny` (NEW, strict subset of global, replicated up on heal). `ClusterConfig` gains `TrustKeys[]`/`IntermediateDenylist[]`/`ControllerEndpoints[]`. Offline ROOT key stays offline (`offline-root/`), signs each cell intermediate out of band; the threshold trust-set key signs `ClusterConfig` out of band. bbolt single-node keeps ALL of these as the same buckets in one file — GLOBAL/REGIONAL/EVENTUAL is purely the `sqlStore` locality interpretation.

### Security MUSTs landed
§2/§4/§9/§10/§17/§18 (global-strong fail-closed deny + short-TTL cache + local-deny valve + loud alarm), §6 (agent (version,content-hash) fork-detect + CA-root/TrustKeys two-version overlap), §7 (separate trust-set signer + AgentPolicy most-restrictive floor + NetworkConfig route/VNI ceiling), §8 (intermediate name-constraint defense-in-depth + intermediate-denylist load-bearing), §9 (128-bit random serials kept), §20 (geo-DNS signed-config-gated + mTLS controller pin), § medium-1 (node `Approved` GLOBAL), § MUST #1 (single-use hard-rejected-not-routed at non-owning cell).

### Test / proof + lab + exit
- **Cross-cell revocation closed (headline):** workspace homes to cell-A; an agent that geo-DNS-fails-over to cell-B whose cert was revoked / principal suspended in cell-A is DENIED at cell-B within the deny-cache TTL — via the GLOBAL `revoked_certs`/`suspensions`, NOT gossip. **Whole-cell-A outage:** every ESTABLISHED E2E tunnel fleet-wide survives (data path never touched the controller); cell-A new-session brokering pauses; cell-B keeps serving; a globally-suspended/revoked principal stays denied at cell-B. **Compromised-intermediate:** `RevokeIntermediate` cell-A's intermediate at the root → all cell-A leaves rejected fleet-wide by the agent denylist WITHOUT a root rotation, cell-B unaffected; a leaked cell-A intermediate cannot mint a cell-B leaf (x509 name-constraint test documents real Go behavior + the denylist is the load-bearing reject). **Forked-config:** two writers attempt `ConfigVersion N+1` → exactly one wins the global CAS, the other clean retry; agents observing two distinct payloads at the same version fail CLOSED until a strictly-higher reconciled version (the agent-side (version,content-hash) detection). **Trust-set separation:** a single running controller CANNOT sign/publish a new `ClusterConfig` (`TrustKeys` verify fails); only the offline/threshold `geneza-trust` signer can; a compromised controller mints grants within its scope but cannot expand the trust set. **Lost-invalidation:** drop ALL NATS `cert.revoked`/`authz.suspend` → revoked cert denied within the cache TTL. **Partition fail-closed:** deny READS still deny (TTL then fail-closed); a LOCAL deny is honored instantly; suspend/revoke WRITES hard-error to the admin; the "no global deny" alarm fires; local deny replicates up on heal. **Geo-DNS spoof:** point `gw.<cluster>.geneza` outside the signed `ControllerEndpoints` → agent refuses (signed-set + mTLS `geneza://controller` pin); a mis-route only fails-and-retries. **Break-glass during store error:** a no-Subject operational cert still authenticates (S2-note exemption). **Single-node regression:** `region:""`, store=bbolt, router=inproc → the full `scripts/e2e.sh` stays green.
- **Lab:** extend geneza1 — two simulated regions (`region=eu`/`region=us`), the P1 3-node CRDB spanning both (GLOBAL for deny/single-use/trust; REGIONAL BY ROW for cell data). Cell-A (eu): geo-LB + NATS + intermediate-ca.key (root-signed out of band) + cell-scoped grant key + eu DERP slice (VM 105 family). Cell-B (us): same shape on additional VMs. The offline-root key off-box (separate hypervisor dir, NOT on either cell controller) signs both intermediates; `geneza-trust` (lab: 2-of-3 ed25519 shares) signs `ClusterConfig`. Agents (VM 106/107) enroll into cell-A; a geo-DNS flip re-homes one to cell-B to exercise the cross-cell deny. Geo-DNS = a `dnsmasq` entry the test flips; the signed `ControllerEndpoints` set is the real authority. New proof scripts: `cross-cell-deny-proof.sh`, `cell-outage-proof.sh`, `intermediate-revoke-proof.sh`, `forked-config-proof.sh`, `partition-faildeny-proof.sh`.
- **Exit:** all of the above green; single-node `--all-in-one` byte-for-byte; a single controller cannot publish a new `ClusterConfig`; partition deny-reads still deny + local-deny honored + write hard-errors + alarm fires + replicates on heal; dropping all NATS invalidations still denies within TTL; geo-DNS outside the signed set refused.

### Risks
X.509 URI name constraints under-enforced by Go (defense-in-depth only; denylist + scope are load-bearing — unit-test the real Verify behavior); GLOBAL-table write latency (size regions so a single-region partition keeps global write quorum; the local-deny valve + loud alarm cover the inducible "no global deny" state — a deliberate availability cost); trust-set/grant-key separation config edge (enforce in `init.go` that single-node fills both roles from one key; test a multi-cell controller's grant key is NOT in `TrustKeys`; the empty-`TrustKeys`-on-upgrade fail-open migration); directory mistaken for authorization (structurally assert no `IsSuspended`/`IsCertRevoked` ever reads the directory); concurrent intermediates + serials (keep 128-bit random; key the denylist on `(issuer-SKI, serial)` if a counter is ever introduced); offline-root/M-of-N operational weight (tooling must refuse to load a root key into a running controller); scope creep into P1–P3 (P4 marks tables GLOBAL + adds layers only — blocked if P0–P3 aren't landed).

---

## 5. Consolidated file-touch map

`g/` = `internal/controller/`, `t/` = `internal/types/`, `a/` = `internal/agentd/`, `c/` = `internal/ca/`, `r/` = `internal/relay/`, `sc/` = `internal/sessionconn/`, `v/` = `internal/vpn/`.

| File | P0 | P1 | P2 | P3 | P4 |
|---|---|---|---|---|---|
| `g/store_iface.go` (NEW P0) | ● define `Store` | ● `var _ sqlStore` | ● +affinity, +session_owner, +services | ● +relay methods | ● +deny-E, +intermediate-denylist, +local-deny, +directory |
| `g/store.go` | ● rename → `bboltStore`, OpenStore→iface | ● | ● affinity bucket | ● `bucketRelays` | ● `RevokeIntermediate`, `WriteLocalDeny`, `Approved` split |
| `g/membership.go` `g/session.go` `g/handoff.go` `g/authzstate.go` | ● receiver rename | | | | ● (authzstate: `IsSuspendedE`) |
| `g/device.go` | ● `PollDeviceGrant` closure | ● SERIALIZABLE | | | |
| `g/sqlstore.go` (NEW P1) | | ● impl | ● affinity SERIALIZABLE | ● relay UPSERT | ● GLOBAL locality, deny-E, local-deny, directory |
| `g/sqlschema.sql` (NEW P1) | | ● | ● | ● | ● GLOBAL/REGIONAL DDL |
| `g/leader.go` (NEW P1) | | ● advisory-lock | ○ consumed (sweep) | ○ consumed (map rebuild) | |
| `g/server.go` | ● `Store`/`NewBroker` iface, `buildClusterConfig` scope+relay-inject | ● CAS, leader | ● `router`, ControllerID | ● relay candidate accessor | ● `Region/CellID`, GrantKeys union, ControllerEndpoints |
| `g/init.go` | ● `AllWorkspaces` (via buildClusterConfig) | | | ● relay inject (via buildClusterConfig) | ● TrustKeys==GrantKeys single-node |
| `g/broker.go` | ● `store Store` | | ● `b.agents`→router, routed SendOffer | ● candidate list (drop `relayAddrs[0]`), two-cred | ● scoped grant, cross-cell mint, directory |
| `g/registry.go` | | | ● `agentHandle.affinityEpoch` (methods unchanged) | ● proto candidates populate | |
| `g/nodecontrol.go` | ● per-msg recheck (S8), heartbeat pull (S9) | | ● Claim/Release affinity, subscribe | ● `NodeRecord.Region` hello | ● intermediate-denylist on re-attach |
| `g/auth.go` | ● per-msg recheck wiring | | | | ● fail-closed deny-E + cache, exemption preserve, local-deny |
| `g/userapi.go` `g/sessionsignal.go` | ● per-msg recheck on UserAPI (S8) | | ● bridge (BridgeToAgent/Client), `sigEntry.clientControllerID` | | ● cross-cell redirect-follow (userapi) |
| `g/disco.go` | | | ● bridge when peer remote | | |
| `g/continuousauthz.go` | (C3 reused, not touched) | | ● routed revokeSession, sharded sweep (3 lifetimes), bus fan-out | | ● local-deny on suspend, txn audit |
| `g/streamrouter.go` (NEW P2) | | | ● iface + inprocRouter | ● | |
| `g/natsrouter.go` (NEW P2) | | | ● natsRouter, epoch-gated delivery | | |
| `g/registrar.go` (NEW P3) | | | | ● relay heartbeat + leader map rebuild | |
| `g/networkpush.go` | ● VNI alias (S0) | | | ● `WGPeer.Candidates` | ● route/VNI ceiling source |
| `g/turncreds.go` | | | | ● per-region secrets, region tag, BOTH minters | |
| `g/audit.go` `g/audit_sink.go` | | | ● `controller_id` stamp (chains unchanged) | | |
| `g/config.go` | | ● `Store`/`DSN`, validate | ● `ControllerID/Router/NATSURL`, validate gate | ● `RelaySecrets` | ● `Region/CellID` |
| `g/denycache.go` (NEW P4) | | | | | ● |
| `g/localdeny.go` (NEW P4) | | | | | ● |
| `g/directory.go` (NEW P4) | | | | | ● |
| `g/metrics.go` | | | | | ● global-deny-unavailable alarm |
| `t/vni.go` (NEW P0) | ● `VNIForWorkspace` | | | | |
| `t/cluster.go` | ● `GrantKeyScope`, `CoversWorkspace` | ● (version,hash) identity helpers | | ● `RelayNode`, `Relays[]` | ● `TrustKeys`, `TrustedConfigKeys`, `IntermediateDenylist`, `ControllerEndpoints` |
| `t/grant.go` | ● `VerifyGrant`→keyID, Routes⊆ | | | ● `RelayCandidate`, `SessionGrant.RelayCandidates` | ● |
| `a/offer.go` | ● `EvaluateOffer` scope/VNI/Routes, in-handshake re-verify | | | ● relay-cert-vs-map (UDP-anchored) | ● intermediate-denylist + revocation in re-verify |
| `a/worker.go` | ● `scopedTrustedKeys`, heartbeat pull, VNI derive | | | ● candidate wiring | ● `TrustedConfigKeys`, AgentPolicy floor, NetworkConfig ceiling, controller mTLS pin |
| `a/state.go` | ● `Workspace`+`fileWorkspace`, backfill | ● (version,hash) fork-detect in parseAndCheckClusterConfig | | | ● pinned TrustKeys + 2-version overlap, AgentPolicy floor file |
| `a/enroll.go` | ● persist workspace from cert | | | | ● controller endpoint pin |
| `p/ice.go` `v/icebind.go` `a/wg_userspace.go` | | | | ● `Candidates`, probeRTT, re-pick | |
| `c/ca.go` | | | | ● relay-URI verified SAN | ● `IssueIntermediate` (128-bit serial kept) |
| `c/intermediate.go` (NEW P4) | | | | | ● |
| `r/turnserver.go` `r/config.go` `r/relay.go` | | | | ● custom AuthHandler, Permission/Quota, per-region secret | |
| `api/proto/geneza/v1/control.proto` | ● DenySetRequest/Response (S9) | | ● (turn in offer payload — no proto change if reused) | ● `repeated candidates` | |
| `cmd/geneza-ca/main.go` | | | | | ● intermediate ceremony |
| `cmd/geneza-trust/main.go` (NEW P4) | | | | | ● M-of-N trust-set signer |
| `/root/labs/geneza1/deploy/*.sh`, `controller.yaml`, `nats.conf`, LB fragment | | ● CRDB | ● gw-b, NATS, LB | ● relays, regions, netem | ● cells, geo-DNS, offline-root |
| `/root/labs/geneza1/scripts/e2e.sh` (+ `e2e.env`) | ● red-team checks | ● double-mint/fail-closed | ● 6 HA-profile checks | ● relay/region checks | ● 5 cell proof scripts |

(● = primary touch; ○ = consumes a primitive built elsewhere.)

---

## 6. "First PR" starter — the smallest safe first commit

**Scope: P0-S0 + P0-S1 + P0-S3 + P0-S4 only** — the `Store`-interface extraction and the VNI relocation. This is a pure mechanical refactor with **zero behavior change** and no new dependency; it lands the load-bearing seam everything else plugs into, and it is the safest possible first commit (the compiler + the existing e2e battery are the proof). The scoped-grant *enforcement* (S5–S10) is deliberately a **second** PR, deployed controller-first per the §2 ordering hazard.

### Why this slice
- The interface extraction touches ~81 receiver definitions but **zero call sites** (callers use interface-dispatched `s.store.X`), so the blast radius is mechanical and compiler-checked.
- Moving `vniForWorkspace` to `internal/types` is a prerequisite for the agent-side VNI check (S7) and is itself behavior-preserving (a thin controller alias keeps every existing caller byte-identical).
- It introduces **no** new go.mod entry, **no** proto change, **no** deploy change — `scripts/e2e.sh` is the entire acceptance gate.

### Precise initial steps
1. **Branch.** This is a fresh HA workstream; per the geneza git workflow, work on `wip` (not `main`), and per the project memory use the plain commit identity with **no AI/Co-Authored-By annotation**. Create the worktree/branch off `wip`.
2. **S0 — relocate VNI.** Add `internal/types/vni.go` with `func VNIForWorkspace(id string) uint32` (copy the FNV-1a body verbatim from `server.go:397`, plus the `"default"→1` pin — but parameterize the default-workspace constant so `internal/types` doesn't depend on `internal/controller`). In `controller`, replace the body of `vniForWorkspace` with `return types.VNIForWorkspace(id)` (keep the alias so `server.go:384`, `broker.go:299/308`, `networkpush.go:61`, `networkpush_test.go` are untouched). Add `internal/types/vni_test.go` asserting parity against a few known workspace ids incl. `"default"==1`.
3. **S1 — enumerate.** `grep -rhoE '\.store\.[A-Za-z]+\(' internal/controller/*.go | sort -u` (already run — 80 distinct methods) is the interface population; cross-check against the 81 `func (s *Store)` definitions. Drop the four unexported helpers.
4. **S3 — extract.** Create `internal/controller/store_iface.go` with `type Store interface { ... }` (the full set). Mechanically rename `type Store struct` → `type bboltStore struct` and every `func (s *Store)` → `func (s *bboltStore)` across `store.go membership.go session.go device.go handoff.go authzstate.go` (single `sed`-style pass over those six files only; the receiver token is unambiguous). Change `OpenStore` to `func OpenStore(path string) (Store, error)` returning `&bboltStore{db}`. Add `var _ Store = (*bboltStore)(nil)`. **S2 (PollDeviceGrant closure)** can ride in this PR or the next — if included, change the interface method to the backend-agnostic `issue func(g *DeviceGrant) ([]byte, error)` and adjust the bbolt impl to run it inside `db.Update`.
5. **S4 — switch holders.** `Server.store` `*Store`→`Store` (`server.go`); `NewBroker(store *Store, ...)`→`NewBroker(store Store, ...)` (`broker.go:88`, call site `server.go:194`). `grep -rn '\*Store\|\*controller\.Store' internal/ cmd/` and convert every remaining holder (incl. test helpers).
6. **Build + test gate.** `go build ./...` (the real completeness check — the `var _` assert alone is insufficient), then `go test ./... -race`. Both must be green with **no diff in behavior**.
7. **Lab regression.** Cross-compile, deploy to VM 105–107 via the lab's `deploy/*.sh`, run `scripts/e2e.sh`, assert all ~47–48 checks green (single-node, no-behavior-change proof). This is the cardinal-constraint gate.
8. **Commit.** Message: a plain description of the extraction (`controller: extract Store interface (bboltStore default) + relocate VNIForWorkspace to types`), **no Co-Authored-By line** (geneza workflow). Do **not** push unless the user asks.

**Exit for the first PR:** `var _ Store = (*bboltStore)(nil)` present; `go build ./... && go test ./... -race` green; `Server.store` and `NewBroker` hold the `Store` interface; `grep` shows no `*controller.Store` holder outside the bbolt impl/tests; `types.VNIForWorkspace` is the single VNI source (parity test green); `scripts/e2e.sh` byte-for-byte green on geneza1; `go.mod` unchanged. The scoped-grant enforcement floor (S5–S10) follows as PR #2, controller-deployed before the agent enforcement.
