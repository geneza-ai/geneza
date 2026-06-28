# Trust-anchor split: anchoring the fleet trust set in an offline / threshold key

Implementation-ready design for closing the **circular self-signing** gap in
Geneza's signed map (the HA red-team **C3** concern; item #4 in
`docs/key-hierarchy-threat-model.md`'s priority order).

## The gap, precisely

The "signed map" is one document — `types.ClusterConfig` (`internal/types/cluster.go`) —
wrapped in one `types.Signed` envelope. It carries two very different kinds of data:

- **Routine map** — mutable, high-churn, low-stakes: `ControllerEndpoints`, `Relays`,
  `RelayAddrs`. Rebuilt online by controllers on every relay/controller flap
  (`maintainRelayMap`, `reconcileClusterConfig`).
- **Trust anchors** — rarely-changing, fleet-critical: `GrantKeys` (*who* may mint
  grants and sign the routine map), `CARootsPEM` (*which* CA roots leaf certs chain
  to), `AuditRecipient`, `AgentPolicy`.

Both are signed by one signer and verified as one blob. Today the envelope is verified
against `TrustedConfigKeys()` — the `TrustKeys` set if present, else the `GrantKeys`
(the back-compat / single-node fallback where the grant key *is* the implicit trust
root). An online grant key therefore signs a document that **declares which grant keys
and CA roots are trusted**. A single stolen online grant key can publish a `v(N+1)`
config that adds the attacker's key to `GrantKeys` / swaps `CARootsPEM`, and every node
accepts it because it was signed by a currently-trusted key. The trust set is
**circularly self-signed by an online key**.

### What already exists (and why it is not enough)

The codebase has a *partial* mitigation: the `TrustKeys` field, `TrustedConfigKeys()`,
`canSignConfig()`, and the offline `geneza-trust` signer. With `TrustKeys` populated, a
controller holding only a grant key **cannot** re-sign the config (`canSignConfig` returns
false; `reconcileClusterConfig` keeps the offline-signed config and logs a warning).

That closes the rewrite gap but **breaks online operation of the routine map**: because
trust anchors and the routine map live in *one envelope signed by one key*, once you
move signing offline, **nobody online can re-sign the relay/endpoint churn either.**
A multi-controller fleet with an offline anchor would freeze its routing map. So
`TrustKeys` is, in practice, only usable in deployments where the routing map never
changes — the opposite of the HA fleet that most needs it.

**The fix is to split the one envelope into two independently-signed documents**, each
with its own signer and its own monotonic version, exactly mirroring the TUF-lite
artifact-update split already shipped in `internal/types/rootkeys.go` /
`docs/update-trust.md` (`RootKeys` offline-signed authorizes online release-signing
keys, which sign manifests). Here: an offline/threshold-signed **trust-anchor document**
authorizes the online grant keys, which sign the **routine map**.

## 1. Object split & schema

Two documents, two envelopes, two version lines.

```
  OFFLINE TRUST KEY(S)   (air-gapped / HSM / YubiKey; N-of-M threshold)   ← PUBLIC half PINNED on every node
       │ signs (≥N of M signatures)
       ▼
  TrustAnchors            (types.TrustAnchors, monotonic AnchorVersion)
     { who is trusted: GrantKeys, CARootsPEM, AuditRecipient, AgentPolicy,
       and the next-level TrustKeys themselves }
       │ authorizes the CURRENT GrantKeys set (overlap allowed during rotation)
       ▼
  ONLINE GRANT KEY(S)     (on the controller; HSM/KMS-backed per threat model)
       │ signs
       ▼
  RoutineMap              (types.RoutineMap, monotonic ConfigVersion)
     { ControllerEndpoints, Relays, RelayAddrs } + AnchorVersion binding
       │ describes
       ▼
  live routing / discovery / relay fleet
```

### 1a. `TrustAnchors` (offline / threshold-signed)

```go
// TrustAnchors is the fleet trust ROOT document: it names WHO is trusted, and is
// signed OFFLINE (or by an N-of-M threshold) so no single online compromise can
// rewrite it. Its PUBLIC signer set is PINNED on every node at enrollment. It is
// monotonically versioned (rollback protection) and may carry the next-level
// TrustKeys (rotation overlap), mirroring types.RootKeys for artifact updates.
type TrustAnchors struct {
	AnchorVersion int64        `json:"anchor_version"`
	GrantKeys     []GrantKey   `json:"grant_keys"`            // who may sign RoutineMap + grants
	CARootsPEM    []byte       `json:"ca_roots_pem"`          // which CA roots leaf certs chain to
	AgentPolicy   AgentPolicy  `json:"agent_policy"`          // host guardrails (trust-class)
	AuditRecipient string      `json:"audit_recipient,omitempty"`
	TrustKeys     []TrustKey   `json:"trust_keys"`            // who may sign THIS doc (the pinned set)
	Threshold     int          `json:"threshold,omitempty"`  // N in N-of-M; 0/1 = single-signer
	ExpiresAt     time.Time    `json:"expires_at,omitempty"` // optional freeze protection (VERIFY: adopt?)
}
```

A **multi-signature envelope** is required because the existing `types.Signed` carries
exactly one `(KeyID, Sig)`. Add a sibling, leaving `Signed` untouched:

```go
// MultiSigned is a detached-signature envelope carrying ONE OR MORE signatures over
// the SAME payload bytes — the threshold form of types.Signed. Each Sig is verified
// independently against the pinned signer set; ≥Threshold valid distinct-key sigs
// accept. A single-signer TrustAnchors is just len(Sigs)==1.
type MultiSigned struct {
	Payload []byte    `json:"payload"`
	Sigs    []OneSig  `json:"sigs"`
}
type OneSig struct {
	KeyID string `json:"key_id"`
	Sig   []byte `json:"sig"`
}
```

### 1b. `RoutineMap` (online grant-key-signed)

```go
// RoutineMap is the high-churn, low-stakes routing view: discovery, relay fleet,
// relay addrs. Signed ONLINE by a grant key. It BINDS to a specific TrustAnchors
// version (AnchorVersion + AnchorDigest) so a routine map can never be paired with
// a stale or forged trust set. Verified against the GrantKeys that the CURRENT
// pinned TrustAnchors authorizes.
type RoutineMap struct {
	ConfigVersion    int64             `json:"config_version"`
	AnchorVersion    int64             `json:"anchor_version"` // the TrustAnchors version this map was built against
	AnchorDigest     []byte            `json:"anchor_digest"`  // SHA-256 of the canonical TrustAnchors payload bytes
	RelayAddrs       []string          `json:"relay_addrs,omitempty"`
	Relays           []RelayNode       `json:"relays,omitempty"`
	ControllerEndpoints []ControllerEndpoint `json:"controller_endpoints,omitempty"`
}
```

### 1c. Binding the routine map to a specific trust-anchor version

The map declares **both** the anchor version it was built against and the
**SHA-256 digest of the canonical `TrustAnchors` payload bytes**. A verifier accepts a
`RoutineMap` only if:

- `map.AnchorVersion == heldAnchors.AnchorVersion`, **and**
- `map.AnchorDigest == sha256(heldAnchorsPayloadBytes)`.

The version alone is not sufficient — an attacker who could forge anchors would reuse a
version number. The digest pins the map to the *exact* anchor content the node holds, so
a routine map signed against a different (forged or stale) trust set is rejected even at
the same version number. (The digest is over the exact bytes that were signed, matching
Geneza's invariant "verification is always over the exact payload bytes that were
signed.")

**Why `AgentPolicy` moves to the anchors.** `AgentPolicy` is a security guardrail
(`ForbidDetach`, `MaxSessions`, recording ring sizes). Loosening it is a trust-class
change — a stolen grant key must not be able to flip `ForbidDetach: false`. So it lives
in `TrustAnchors`. If operators want some policy fields to be online-tunable, that is a
**separate future split** (a `RoutinePolicy` block in `RoutineMap`); not in scope here —
default-safe is anchors-only. (VERIFY: confirm no code path online-mutates `AgentPolicy`
today; `buildClusterConfig` sources it from static `cfg.AgentPolicy`, so it is already
effectively static — good.)

## 2. Verification flow

Two-step verify, everywhere a `ClusterConfig` is verified today (`agentd`, `relay`,
follower controllers). Pseudocode:

```
verifyFleetState(pinnedTrustKeys, pinnedThreshold,
                 heldAnchorVersion, heldAnchorDigest, heldConfigVersion,
                 anchorEnvelope MultiSigned, mapEnvelope Signed):

  # --- step 1: trust anchors against the PINNED offline/threshold key set ---
  if anchorEnvelope present:
      anchors := verifyMultiSig(pinnedTrustKeys, pinnedThreshold,
                                CTX_TRUST_ANCHORS, anchorEnvelope)   # ≥N distinct valid sigs
      require anchors.AnchorVersion >= heldAnchorVersion             # rollback floor
      require anchors.ExpiresAt is zero OR now < anchors.ExpiresAt   # freeze floor (if adopted)
      # a rotation may carry a NEW TrustKeys/Threshold, but it was just verified
      # against the OLD pinned set — the chicken-and-egg rotation rule (§3).
      newPinnedTrustKeys, newThreshold := anchors.TrustKeys, anchors.Threshold
  else:
      anchors := heldAnchors                                        # no newer anchor pushed this round

  grantKeys := anchors.GrantKeys                                    # authorized signers for the map

  # --- step 2: routine map against the grant keys the anchors authorize ---
  map := Verify(grantKeys, CTX_ROUTINE_MAP, mapEnvelope)           # single-sig, existing path
  require map.ConfigVersion >= heldConfigVersion                    # rollback floor
  require map.AnchorVersion == anchors.AnchorVersion                # map built against THESE anchors
  require map.AnchorDigest  == sha256(anchorEnvelope.Payload)       # ...these EXACT anchor bytes

  commit (anchors, map) atomically; advance both held versions; re-pin TrustKeys if rotated
```

`verifyMultiSig` requires **≥ Threshold signatures from DISTINCT pinned key ids**, each
valid over `signingInput(CTX_TRUST_ANCHORS, payload)` (reusing the existing
domain-separated `signingInput`). Duplicate key ids count once. Threshold 0 or 1 is the
single-signer case.

### What is pinned where, and bootstrap

- **Pinned on every node: the `TrustKeys` set + `Threshold`** — the offline/threshold
  *public* keys that may sign `TrustAnchors`. This is the new root of trust on the node.
  It is **not** the grant keys (those are now *authorized by* the pinned set, not pinned
  themselves).
- **Bootstrap (TOFU-at-enrollment, unchanged trust model):** the very first
  `TrustAnchors` arrives over the enrollment channel (mTLS to the pinned bootstrap CA),
  and the node **pins its `TrustKeys`+`Threshold` from that first document** — exactly
  how `parseAndCheckClusterConfig` / the relay `controllerControlResolver` pin
  `TrustedConfigKeys()` from the first config today. The mTLS-authenticated enrollment
  channel is what anchors the TOFU; thereafter every push verifies against the *held*
  pinned set, never the incoming document's own (the existing invariant in
  `worker.handleClusterConfig`: "verify against the PINNED trust set ... never the
  incoming config's own").
- **Optional shipped-at-join hardening (VERIFY / future):** an enrollment token / image
  may carry the expected `TrustKeys` fingerprint so even the first document is checked
  against an out-of-band pin, removing TOFU. Additive; default stays TOFU.

The node persists three things alongside today's `cluster_raw`: the signed
`TrustAnchors` envelope, the pinned `TrustKeys`/`Threshold` (derived from it), and the
signed `RoutineMap` envelope. On restart it reloads and re-pins from the held anchors
(the `state.go` reload path), never trusting the channel.

## 3. Threshold signing (N-of-M)

Mechanism is deliberately boring: **collect M ed25519 signatures over the canonical
`TrustAnchors` payload bytes; accept if ≥ N are valid from distinct pinned key ids.** No
Shamir, no FROST, no aggregation — M independent ed25519 signatures in `MultiSigned.Sigs`.
This is auditable, has no novel crypto, and matches the CARDINAL "reuse standard
primitives, never reinvent protocols" mandate.

Typical posture: **2-of-3 security officers**, three YubiKeys held by three people; any
two sign a trust change. `Threshold=2`, `len(TrustKeys)=3`.

### Operational flow — the offline `geneza trust-sign` step

Extend the existing `geneza-trust` offline tool (today single-signer
`cmd/geneza-trust/main.go`) with a threshold workflow:

1. An operator runs `geneza-trust propose --in anchors.json` on an online box to produce
   a **canonical, deterministic** `TrustAnchors` payload (stable JSON key order; this is
   the bytes everyone signs). Output: `anchors.payload` (the exact bytes) + a human-
   readable diff vs the currently-held anchors.
2. Each security officer, **offline**, runs `geneza-trust sign --payload anchors.payload
   --key trust.key` (key on YubiKey/HSM via the same `crypto.Signer`/`KeySource` seam the
   threat model describes). Produces one `OneSig`. The signer **never sees or signs the
   routine map** — only the anchor payload.
3. `geneza-trust assemble --payload anchors.payload --sig a.sig --sig b.sig` collects the
   `OneSig`s into a `MultiSigned` envelope and validates ≥Threshold distinct valid sigs
   *before* emitting (refuse-to-emit-DOA, mirroring today's `newSignCmd` check that the
   signing key is listed in `trust_keys`).
4. An operator hands the assembled `MultiSigned` to a controller, which CASes it into the
   store (§5). The controller holds **no** trust key and cannot author or alter it.

The single-signer file path stays available (`Threshold` unset, one key) — that is the
back-compat anchor below.

### Rotating the threshold set (chicken-and-egg)

Rotating *who* may sign anchors must itself be a signed anchor change:

- A new `TrustAnchors` carrying the new `TrustKeys`/`Threshold` is signed by **≥ the OLD
  threshold of the OLD keys**. Nodes verify it against their currently-pinned (old) set,
  accept it, then **re-pin to the new set** for the next round. This is the same
  "verified against the old, authorizes the new" overlap that `RootKeys` rotation uses
  for artifact signing keys, and that `worker.handleClusterConfig` already does for
  `TrustKeys` (a config may carry a new trust set, but only if signed by a currently-
  pinned key).
- **Overlap window:** list both old and new keys in `TrustKeys` for one or more
  versions, then drop the old, so a node that missed an intermediate version still
  chains forward. Raising/lowering `Threshold` is just a field change in the same signed
  document.
- **Lost-quorum recovery is out of band by design:** if you lose more than M−N officer
  keys you cannot sign a rotation, exactly as a lost offline root is unrecoverable in
  TUF. Mitigation is operational (M−N spare margin, escrowed key, break-glass officer);
  not a protocol feature. Stated honestly in §7.

## 4. Backward compatibility — CRITICAL

The split is **opt-in and additive**. A deployment with **no offline/threshold anchor
configured must keep working byte-for-byte.**

### The "no offline key configured" behavior (genesis / single-node / today)

- **Genesis (`init.go`) and single-node** stay exactly as today: the controller generates
  its grant key and writes a config where **the grant key is the implicit trust root**.
  No `TrustAnchors` document, no `MultiSigned`, no separate signer. `canSignConfig`
  returns true (no separate trust root), reconcile re-signs online with the grant key.
- **Wire-level compatibility:** the combined `ClusterConfig` + `TrustedConfigKeys()`
  fallback (grant keys double as trust root when `TrustKeys` empty) **remains the
  default representation** when no anchor is configured. The split documents
  (`TrustAnchors`/`RoutineMap`) are produced **only** once an operator establishes an
  offline/threshold anchor. An un-split cluster never sees the new types on the wire, so
  existing nodes, the existing CAS, and the existing e2e battery are unaffected
  byte-for-byte.

  Implementation note: model the split as an *envelope mode* on the stored config —
  `legacy` (one `ClusterConfig` in one `Signed`, today) vs `split` (a `TrustAnchors`
  `MultiSigned` + a `RoutineMap` `Signed`). The verifier picks the path by what is
  present. `legacy` is the zero value, so absence of an anchor = today's behavior.
- **Degrade-cleanly rule:** `canSignConfig` already encodes the property we need —
  "trivially true when there is no separate trust root." In split mode it becomes:
  *true for the routine map always (online grant key signs it); never for the trust
  anchors (only the offline/threshold holder signs those).* A follower holding only a
  grant key re-signs the **routine map** freely on relay/controller churn, and **refuses**
  to author trust anchors — which is the whole point, and is exactly the partial behavior
  that exists today, now without freezing the routing map.

## 5. Version / CAS interaction & rollback resistance

There are now **two monotonic versions** over **one** trust domain, stored in the single
`cluster_config` row.

- **`AnchorVersion`** (trust anchors) and **`ConfigVersion`** (routine map) are
  independent monotonic counters. A trust change bumps `AnchorVersion`; a routine churn
  bumps `ConfigVersion`. Each is independently rollback-protected by its own `>= held`
  floor (the `RoutineMap` rule `map.ConfigVersion >= held` and the anchor rule
  `anchors.AnchorVersion >= held`).
- **CAS on the routine map** stays exactly as today: `SetSignedClusterConfig` advances
  the row only if `stored == version-1` (`sqlstore.go`), keeping the routine bump
  globally linearizable across the controller pool. The high-churn writer is unchanged.
- **CAS on the anchors:** anchor publication is rare and offline-authored, but must still
  be linearized so two officers' submissions don't clobber. Store the signed anchor
  bytes + `AnchorVersion` in the **same `cluster_config` row** (new columns
  `anchor_version`, `anchor_signed`) under the **same serializable transaction**, with a
  CAS predicate `anchor_version == new-1`. Crucially, a new routine map and a new anchor
  can be committed in the same CAS transaction (an anchor bump usually ships with a
  routine map re-pinned to it), so the row never holds a `RoutineMap` bound to an
  `AnchorVersion` that isn't also in the row.
- **Cross-binding invariant at rest:** the stored routine map's `AnchorVersion`/
  `AnchorDigest` must always reference the stored anchor. Enforce in the CAS: reject a
  `RoutineMap` write whose `AnchorVersion` ≠ the row's current `anchor_version` (or whose
  digest mismatches), unless the same transaction also advances the anchor to that
  version. This makes "stale map paired with new anchors" and "new map paired with stale
  anchors" both impossible to persist, not just impossible to verify.
- **Rollback resistance for BOTH objects** is the per-document monotonic floor on every
  verifier (node, relay, follower controller), identical to today's single-version check —
  now applied twice. A downgrade of either document is refused independently.

## 6. Migration path (no flag day)

A live cluster adopts an offline/threshold anchor in three non-breaking stages, each a
normal monotonic config bump:

1. **Introduce + pin (passive).** Officers generate the offline/threshold keys
   (`geneza-trust keygen`, ×M) and publish a `TrustAnchors` document carrying the
   *current* grant keys + CA roots + the new `TrustKeys`/`Threshold`. The first such
   anchor is signed by the threshold and CASed in. Nodes pin its `TrustKeys` from this
   document on next pull (TOFU over the mTLS push channel, anchored by their existing
   pinned grant-key trust — i.e. the document is delivered inside today's
   grant-key-signed config during the transition, then split out). At this stage nodes
   *learn* the anchor signers but the routine map may still be grant-key-signed in legacy
   mode. **No behavior change yet; reversible.**
2. **Split the documents.** Controllers begin emitting the routine map as a separate
   `RoutineMap` (grant-key-signed) bound to the published anchor, and the anchor as a
   separate `MultiSigned`. Nodes that have pinned the anchor verify both; nodes mid-
   upgrade still accept the legacy combined config until they've pinned. Version floors
   ensure no downgrade.
3. **Require it (enforce).** Once all nodes have pinned the anchor and seen a split
   config, flip the controller to **refuse** to legacy-sign trust-class fields: a grant key
   may sign only `RoutineMap`; any `TrustAnchors` change requires the threshold. This is
   `canSignConfig` going from "true (implicit root)" to "false for anchors" for that
   cluster. From here a stolen grant key cannot rewrite trust.

Rollback at any stage is a monotonic bump back to the prior shape; there is no instant
where nodes can't verify what they're being served.

## 7. Blast radius after the split (honest residual risk)

**A stolen ONLINE grant key, after the split:**

- **CAN** sign a forged `RoutineMap` at `ConfigVersion N+1` → redirect agents/clients to
  attacker-chosen `ControllerEndpoints`/`Relays`. *Bounded:* the redirect target must still
  present valid leaf certs (chaining to the *unchanged* `CARootsPEM`) and valid grants to
  broker anything; the data path is E2E (Noise/WireGuard) regardless; no past session or
  recording is readable (forward secrecy + offline audit key). Redirection is detectable
  (endpoints not matching expectation) and self-limiting.
- **CAN** still mint session grants and actively MITM *new* sessions for the workspaces
  its key is scoped to (the grant key's existing power; unchanged by this split — that is
  the issuing-CA/grant-key HSM problem, priority #1–2 in the threat model, orthogonal to
  this gap).
- **CANNOT** add an attacker key to `GrantKeys`, swap `CARootsPEM`, loosen `AgentPolicy`,
  or change `AuditRecipient` — those live in `TrustAnchors`, which it cannot sign. The
  forged routine map binds to the *real* anchor digest or it is rejected; it cannot pair
  its forgery with a forged trust set. **The circular self-signing is broken.**

**Residual risks (be honest):**

- **Grant-key power is unchanged for grants/MITM.** This split protects *who is trusted*,
  not *what a currently-trusted online key can do within its authority*. Closing that is
  the HSM/KMS work (sign-in-place converts "steal once, abuse forever" into "must stay
  resident"), tracked separately. This document does **not** reduce the value of HSM-
  backing the grant key.
- **TOFU at first enrollment** still trusts the enrollment channel for the initial
  `TrustKeys` pin. A compromise *at* enrollment can pin attacker anchors. Mitigated by
  the optional shipped-at-join fingerprint (§2); default remains TOFU, same trust surface
  as today's first-config pin.
- **Lost quorum is unrecoverable in-protocol.** Losing more than M−N officer keys means
  no future trust change can be signed (you can still run on the last-signed anchors).
  This is the deliberate TUF trade: offline strength costs recoverability. Mitigate
  operationally (spare margin, escrow, break-glass officer). VERIFY: decide M/N defaults
  and whether to ship an escrow recipient by default.
- **Threshold is only as strong as key custody.** N independent YubiKeys held by N people
  is the intended posture; M files in one vault is theatre. Out of protocol scope, worth
  stating in the runbook.
- **Anchor freshness vs. freeze.** If `ExpiresAt` is adopted, a fleet that can't reach
  its officers to re-sign before expiry fails closed on anchors. VERIFY: whether to adopt
  anchor expiry (freeze protection, as `RootKeys` has) or omit it (availability over
  freeze-resistance for the trust set, given grant-key rotation is the faster lever).

## Appendix: mapping to existing code (for the implementer)

| Concern | Today | After split |
|---|---|---|
| Trust-set document | embedded in `ClusterConfig.{GrantKeys,CARootsPEM,TrustKeys,AgentPolicy,AuditRecipient}` | `types.TrustAnchors` in a `types.MultiSigned` |
| Routine document | embedded in `ClusterConfig.{Relays,ControllerEndpoints,RelayAddrs}` | `types.RoutineMap` in a `types.Signed` |
| Pinned-on-node | `TrustedConfigKeys()` (grant keys, or `TrustKeys` if set) | `TrustAnchors.TrustKeys`+`Threshold`, pinned at enrollment |
| Verify entry points | `parseAndCheckClusterConfig` (`agentd/state.go`), `worker.handleClusterConfig`, relay `controllerControlResolver.resolve` | add a two-step `verifyFleetState` alongside; legacy path unchanged |
| Online re-sign | `reconcileClusterConfig` + `canSignConfig` | re-sign **routine map only**; refuse anchors |
| Offline signer | `cmd/geneza-trust` (single-sig) | extend: `propose`/`sign`/`assemble` threshold flow |
| CAS | `SetSignedClusterConfig` (`sqlstore.go`, one row, one version) | one row, two versions + cross-binding invariant in the same serializable tx |
| Precedent to copy | — | `types.RootKeys` / `VerifyRootKeys` / `VerifyArtifactChain` (TUF-lite, `docs/update-trust.md`) |

The decisive structural symmetry: **`TrustAnchors : RoutineMap :: RootKeys : Manifest`.**
Geneza already ships the offline-root-authorizes-online-signer pattern for binaries; this
applies the identical shape to the fleet trust set.
