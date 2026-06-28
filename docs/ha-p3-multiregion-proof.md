# HA P3 — multi-region relay fleet: lab validation

The DERP relay fleet (per-region TURN secrets, signed relay map, registrar,
leader-rebuilt map, closest-pick, two-cred cross-region) was validated on a
4-VM rig of real processes, separate from the single-node lab. This records what
was proven; the rig + repeatable battery live in `labs/geneza1/ha-p3/` on the
lab host (`scripts/fleet-proof.sh`, 23 checks, green).

## Rig

- `ha-gw` — controller pinned to region `eu`, Postgres store (region mode requires
  SQL), holds the `eu` + `us` minting secrets, `session_p2p` on, leader.
- `ha-relay-eu` / `ha-relay-us` — one relay per region, each holding only its own
  region's secret, each with a per-relay cert whose identity Name equals its
  `relay_id`, self-registering via the registrar.
- `ha-agent` — enrolled worker; reports its STUN-closest region.
- Client + raw-TURN prober run from the lab host.

## What was proven

**Registration + signed map.** Both relays authenticate the registrar heartbeat
with their own mTLS cert and self-register; the leader rebuilds the signed
`ClusterConfig.Relays[]` with both entries. Each entry's `relay_cert_pub` is
byte-equal to the relay's actual leaf SPKI — i.e. the registrar derived the pin
from the authenticated mTLS leaf, not the self-reported field.

**Region containment (raw TURN allocations).** An `eu`-tagged credential
allocates at relay-eu and is rejected at relay-us (foreign-region tag), and
symmetrically for `us`. A leaked `eu` secret cannot forge a `us` credential (the
HMAC is verified under the region's own secret). Expired and wrong-secret
credentials are rejected. So a leaked region secret is confined to its region.

**Debounce.** Four relay restarts (re-registration churn) produce zero
ConfigVersion bumps — the leader rebuild only fires when the relay *set* changes.

**Stale expiry + recovery.** Stopping a relay drops its row after the stale TTL;
the signed map shrinks to one entry and the version bumps exactly once. Restart
re-registers and the map regrows to two.

**Blackhole-failover precondition.** With one relay down, the other region's
relay still serves allocations — the basis for pion's fungible ICE re-pick
(unit-tested separately).

**Closest-pick.** With a `tc netem` RTT delta, the agent's STUN-RTT probe selects
the nearer region (proven in both directions, so it is RTT-driven, not static).

**Two-cred cross-region.** A session whose client home region differs from the
agent's region yields exactly two region-tagged relay candidates (one per
region), each a session-bound `<expiry>:<region>:sess-<id>` username pointing at
its region's relay; a same-region pair yields one.

**Cross-region session.** A real `exec` on the `us` agent with the client
declaring home region `eu` brokers and runs through the multi-region SQL controller.

**Cardinal gate.** The single-node `scripts/e2e.sh` battery stays 55/55
byte-for-byte across every product change in this phase.

## Bug found and fixed by this validation

Relay certs carried only the server-auth EKU, but a relay uses that same cert as
a TLS *client* to authenticate its registrar heartbeat — the controller rejected it
("bad certificate") so no relay could ever register. Fixed: relay certs now carry
both server- and client-auth EKUs (`internal/ca/ca.go`; regression test in
`internal/ca/eku_test.go`). The single-node relay never registers, so this
surfaced only in a multi-relay deployment.
