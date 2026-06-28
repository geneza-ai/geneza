# Geneza controller HA

The authoritative design for running Geneza's control plane at scale. It replaces
the earlier CockroachDB / regional-cell / per-cell-CA sketch (see
`ha-architecture-spec.md` / `ha-build-plan.md`, kept for history).

## The model in one paragraph

**Managed PostgreSQL is the single linearizable source of truth and the realtime
bus; controllers are a flat pool of stateless, interchangeable workers; relays are
stateless forwarders that pull a signed map.** Two moving pieces. The Postgres
primary serializes every Geneza invariant, so "the consensus" is the database's
own primary — the cloud provider's job to operate, not ours. No controller acks
another controller's writes; a write is durable the instant the primary commits and
every controller observes it by reading the same row. Realtime change-propagation is
a **doorbell** (`LISTEN/NOTIFY` carries a version or a small key, never data — the
receiver re-reads the authoritative row). Fleet chores are ownership-sharded,
idempotent, and version-CAS'd, with a single transient `pg_advisory_lock` debounce
on the one chore where concurrent work is merely wasteful. The cluster view is the
**signed, monotonic `ClusterConfig`** any controller serves; agents/relays/clients
seed from any controller → full signed view → realtime epoch deltas.

There is no controller leader election, no Raft we operate, no second datastore, no
message bus to run. Single-node (`store: bbolt`, `router: inproc`) is byte-for-byte
the path the controller has always run.

## Who holds what

| Holder | Holds | Authority |
|---|---|---|
| **Managed Postgres primary** | all strong truth (deny set, single-use creds, trust set, affinity directory, the monotonic signed `ClusterConfig`) | **yes — the sole serializer** |
| **Controller (flat pool, N identical)** | soft per-process state only (in-RAM registry of connected agents, the LISTEN connection, the cached signed config) | no — interchangeable; killing one loses nothing durable |
| **Relay** | nothing durable; heartbeats presence, pulls + verifies the signed map, reconciles | no — never written-into; identity is its mTLS leaf |
| **Agent** | its pinned controller, its signed `ClusterConfig`, its fail-closed session lease | the workload, not an HA component |

## Strong vs eventual data

The split is physical in the schema; the architecture classifies it and proves
each class is safe under N flat writers.

- **Strong** — serialized by the primary (a `SERIALIZABLE` txn or a single-row CAS),
  fail-closed on unreachable, never gossiped: revoked certs, suspensions, the node
  approval flag, single-use credentials (tokens / device / handoff / enroll), and
  the single `cluster_config` row (version CAS).
- **Eventual** — idempotent, epoch/version-fenced upserts that route but never
  authorize, safe to be briefly stale because the fence is in the SQL predicate:
  the agent/session affinity directory, relay and controller presence, advertised
  services.

## Flat and leaderless

No controller is elected. The chores a single "leader" used to run are reclassified:

- **Per-session re-auth / suspension enforcement** runs on *every* controller, each
  touching only the agents whose stream it holds (ownership-sharded).
- **Janitorial GC** (expiring stale presence, auth sessions, single-use codes) is
  idempotent `DELETE … WHERE expired` — two controllers racing delete the same rows;
  the second deletes nothing.
- **The signed-map rebuild** is the one chore where redundant concurrent work is
  wasteful, so it is guarded by a transient `pg_try_advisory_xact_lock` released at
  commit and re-contended every tick by whoever fires first. Two concurrent
  rebuilds cannot fork: the version CAS makes the loser adopt the winner, and the
  map is assembled deterministically, so even identical concurrent rebuilds produce
  identical signed bytes.

## Realtime: the doorbell, never the pipe

`LISTEN/NOTIFY` carries only a monotone version or a small key; the receiver's
reaction is always "re-read the authoritative row." This neutralizes its
weaknesses — at-most-once within a connection (a dropped notify only delays a
re-read), the small payload cap (we send versions/keys), no request/reply (removed
by redirect, below). Notifications fire transactionally, on commit. Each controller
issues one `LISTEN` per broadcast channel plus one for **its own** channel and
self-filters, so subscriptions are O(controllers), not O(agents). On every reconnect
a controller re-reads the current versions before trusting deltas (resync-on-connect
is the correctness backstop under any transport).

## Discovery and failover

The signed `ClusterConfig` is the cluster view: it carries the controller set and the
relay set, signed, so it can be served by any controller and distributed eventually
without losing integrity (a stale copy is authentic, just old; the monotonic
version prevents rollback). Agents, relays, and clients seed from any controller, get
the full signed view, and receive realtime epoch deltas — the MongoDB-driver
discovery shape.

- **Agents dial out**; on their control stream dropping they reconnect to another
  controller from the signed set (or a stable LB endpoint). The new controller, being
  stateless, reads the agent's row and re-claims it with a higher affinity epoch.
  The epoch fence stops a partitioned old controller from double-owning. Sessions keep
  re-leasing through whichever controller the agent is on; the lease TTL is sized to
  exceed the reconnect window so a single controller dying never tears a session.
- **Relays** are stateless forwarders (Ceph OSD ↔ mon): they heartbeat presence to
  any controller (an idempotent upsert — no ownership), pull the signed map, verify
  their own membership, and re-home to any signed controller endpoint when their seed
  dies. An in-flight splice survives a controller death entirely (the data path never
  touches the controller); a relay that can reach no controller simply ages out of the
  map for *new* traffic while live splices keep flowing.
- **The controller↔relay relationship is declarative**: everything the controller wants
  of a relay is desired-state in the signed map; the relay reconciles to it on
  every connect. Nothing important lives *in* the channel, so either party can
  bounce and the relationship re-converges from Postgres + the relay's pull.

Cross-controller session signaling is removed by **redirect**: when a session lands on
a controller that doesn't own the target agent, the broker returns a signed redirect
to the owner; the client re-dials and brokers entirely locally. The residual
cross-controller control flows (an agent re-homing mid-session, agent-directed config
pushes) ride the owner's NOTIFY channel, each backed by the strong store.

## The single trade-off

One managed-Postgres primary means new-access availability is bounded by Postgres
failover (~10–40s on managed offerings); there is no seamless cross-region
active-active *write* survival. This is deliberate and **strictly fail-closed**:

- in-flight E2E tunnels are unaffected — the data path never touches Postgres;
- deny-path reads fail closed, smoothed by the short-TTL deny cache (a fresh cached
  deny stands; a lapsed entry on a store fault denies — a fault never re-opens
  access past the TTL);
- new sessions / logins / single-use spends refuse cleanly (`Unavailable`), never a
  torn write.

A deployment that genuinely needs cross-region active-active strong writes can
point `store_dsn` at a Postgres-wire-compatible distributed SQL engine — but Geneza
does not carry that complexity by default.

## The one hard rule

**Controller deny-path reads and the LISTEN connection MUST target the Postgres
primary/writer endpoint, never a read replica.** A stale-but-successful read from a
lagging replica would return "not suspended" and cache an *allow* — the deny cache
only fails closed on a read *error*, not on stale data. A replica may *enforce* a
deny it already holds, but must never *grant*. This is enforced at config
validation, not left to documentation.

## Build order

Delivered as incremental, single-node-byte-for-byte-safe steps (each behind
`store: postgres` + `router: pg`; bbolt/inproc untouched until the final cleanup):

1. **de-CRDB** — collapse the store backend to `postgres`; this document. No behavior change.
2. **signed controller discovery** — a `controllers` presence table + `ControllerEndpoint`s in the signed map.
3. **`pgrouter` + NOTIFY plumbing** — the doorbell channels, notify-in-txn, deny-cache flush, primary-only enforcement.
4. **follower config propagation** — apply path + periodic version poll + heartbeat-piggyback, bounding trust-set staleness.
5. **delete the leader** — replace with the transient `pg_advisory_xact_lock` debounce.
6. **NOTIFY router for agent-directed pushes** — routes config/disco/module pushes to the owning controller.
7. **client redirect + re-home fail-fast** — removes the synchronous cross-controller hop.
8. **relay register-and-watch** — relays stream their heartbeat and reconcile the signed map; re-home on seed loss.
9. **delete NATS** — the bus collapses into Postgres.
10. **failover + partition battery** — chaos tests asserting no fail-open under any combination of NOTIFY loss, primary failover, and partition.
