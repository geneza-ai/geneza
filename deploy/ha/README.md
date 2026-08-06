# ha — running Geneza in high availability

This directory is a **configuration reference**, not a stack to launch. HA
topology is site-specific — your Postgres, your load balancer, your regions — so
there is no one compose file to ship. You build an HA fleet by running the
[compose installer](../compose/README.md) **once per node** and pointing every
controller at the **same external backends**.

For the design rationale (leaderless controllers, the DERP edge fleet, regional
cells, global deny-path), see [`docs/ha-architecture-spec.md`](../../docs/ha-architecture-spec.md).

## The shape

```
            clients / agents
                  │
          ┌───────┴───────┐         relays (N, any region)
        gw1             gw2   …      each self-registers to a controller,
          └───────┬───────┘         lands in the signed map, fails over
        shared Postgres (HA)        on its own
        shared VictoriaMetrics
```

- **Controllers are stateless and leaderless.** Every replica serves every request
  over one shared store; there is no election. A controller that owns a given node
  redirects peers to it, so an LB in front needs no session affinity.
- **Each replica must be individually reachable on `:7401`, and must advertise its
  OWN address** — not a shared LB address. `controllerEndpoint()` publishes
  `advertise.*` into the signed cluster map, and that is verbatim what a
  `ControllerRedirect` hands a peer. If every replica advertises the LB, a
  redirect sends the peer back through the LB, which may land on the same replica
  that just redirected it — and a client refuses to chase a second redirect. The
  signed map is the global view; peers re-home across it themselves. An LB is
  optional and buys only a stable bootstrap address (and the console on `:443`).
- **One shared Postgres** holds all signed records under SERIALIZABLE
  invariants. Use a managed/replicated Postgres (or a Postgres-wire HA cluster).
  This is the single component whose own HA you must provide.
- **One shared VictoriaMetrics** (or a vmcluster). Because controllers keep no
  series locally, a metric ingested via `gw1` is queryable through `gw2` — no
  per-replica fragmentation.
- **Relays self-register.** Each relay names a controller as its registrar, learns
  the live controller set from the signed map, and fails over when one dies. Relays
  share nothing at runtime and can sit in any region.

## Standing it up

On **each controller host**, run the installer with `role=controller` and the shared
backends (note the **unique** `--controller-id`):

```sh
sudo ./deploy/compose/install.sh --role controller \
  --controller-id gw1 \
  --site geneza.example.com --public-ip <this-host-public-ip> \
  --postgres-dsn 'postgres://geneza:PW@db.internal:5432/geneza?sslmode=verify-full' \
  --metrics-url  'http://vm.internal:8428' \
  --yes
```

Run the same on `gw2` with `--controller-id gw2`, its own `--public-ip`, and
`--router pg`. They share the CA and grant key — generate them once and copy
`data/controller/ca` + `data/controller/keys` to each controller before first start
(a flat-HA controller set is **one** trust anchor, not per-controller
intermediates).

> **Do not copy `ca/offline-root/`.** That directory holds the fleet ROOT private
> key, which the running controller never reads — it signs with the issuing CA.
> Copying it replicates the key that can mint any identity in the fleet onto every
> internet-facing machine. Move it once to an HSM/KMS/air-gapped media, keep a
> copy (the CA cannot be rotated without it), and delete it from the hosts:
>
> ```sh
> rsync -a --exclude 'offline-root/' data/controller/ca/ gw2:/opt/geneza/data/controller/ca/
> ```

`--router pg` is required, not optional, once a second controller runs: the
default in-process router cannot reach a peer, so a module or network change made
on a controller that does not hold an agent's stream is committed and then
silently dropped.

On **each relay host**, run `role=relay` pointing at the controller LB (see the
[compose README](../compose/README.md#relay-join-rolerelay)).

## Configuration reference

These are the `controller.yaml` / `relay.yaml` keys that differ from a single node.
The installer sets the first group for you from its flags; the rest you add by
hand for production hardening.

### Controller

| Key | HA value | Notes |
|---|---|---|
| `store` | `postgres` | the SQL store; `mariadb`/`mysql` also supported |
| `store_dsn` | external DSN | use `sslmode=verify-full` to a managed Postgres |
| `controller_id` | unique per replica | affinity-owner value, per-controller bus subject, audit label — **must** be globally unique |
| `metrics_url` | shared VictoriaMetrics | every replica points at the same one |
| `advertise.dns_names` / `.ips` | **this replica's own** name/IP (plus the LB name if clients hit it) | published into the signed cluster map as this controller's dialable endpoint, and stamped into its server cert |
| `relay_addrs` / `relay_data_addrs` | reachable relay addresses | where grants tell peers to find relays |
| `cluster_control_listen` | e.g. `:7405` | optional: move the controller↔relay registrar onto its own mTLS port so you can firewall it to the relay/management subnet |
| `router` / `region` | future | parsed today; multi-region routing and cells are not wired yet — leave default |

### Relay

| Key | HA value | Notes |
|---|---|---|
| `registrar_addr` | a controller / the LB `:7401` | the relay heartbeats here and learns the rest of the controller set |
| `relay_id` | unique per relay | its stable identity in the signed map |
| `region` | region id | a relay validates only TURN credentials tagged for its region |
| `shared_secret` | the controller's `relay_shared_secret` | enables the TURN floor; must match (rotating it is a synchronized flag-day) |
| `controller_ca_file` | CA roots | verifies every controller it fails over to |

### Backends you operate

- **Postgres** — managed or replicated; this is the durability and the
  consistency boundary. `sslmode=verify-full` from every controller.
- **VictoriaMetrics** — single instance shown here; for real HA run `vmagent` +
  `vmcluster`. Controllers only push/query, they never scrape.
- **Load balancer** — a plain TCP/L4 balancer over the controllers' `:7401` (mTLS
  gRPC) and `:7402` (HTTPS). No session affinity required.
- **Shared blob storage** — set `storage:` on every controller. Session recordings
  and managed-domain TLS bundles default to LOCAL DISK, and the recording metadata
  lives in the shared Postgres — so every controller *lists* every recording while
  only the one that ingested it holds the bytes. Playback then succeeds or 404s
  ("recording blob missing") depending on which controller the browser landed on.
  Point all of them at the same S3-compatible bucket.

## What this directory is not

There is intentionally **no `docker-compose.yml` here**. An HA Postgres, an LB,
and multi-host networking are yours to provide; the per-node stack is whatever
the [compose installer](../compose/README.md) renders. This file tells you how to
point those nodes at shared infrastructure — nothing here needs to be run.
