# Postgres-flat HA — two-controller control plane: lab validation

The flat, leaderless multi-controller control plane (per-owner Postgres `NOTIFY`
routing, client redirect, NATS removed, stateless relay register-and-watch, agent
and relay failover) was validated on two LIVE controllers sharing one Postgres. This
records what was proven; the rig + repeatable battery live in `labs/geneza1/ha-p3/`
on the lab host (`scripts/chaos-2gw.sh`, 15 checks, green).

## Rig

Two controller processes co-located on the `ha-gw` VM, each with its own ports and
`data_dir` but the SAME localhost Postgres and the SAME CA + grant key (so any
controller's certs, grants, and signed config verify fleet-wide — the flat model):

- `ha-gw` — gRPC `:7401`, cluster-control `:7405`.
- `ha-gw2` — gRPC `:7411`, cluster-control `:7415` (`deploy/deploy-gw2.sh`).
- `ha-relay-eu` / `ha-relay-us` — relays seeded at gw1's control port.
- `ha-agent` — enrolled worker.
- Clients drive gw1 (profile `ha3`) and gw2 (profile `ha3gw2`).

Both controllers self-heartbeat into the `controllers` table, and the signed
`ClusterConfig.ControllerEndpoints` carries both — each with `addrs` (the gRPC port,
the client/agent redirect target) and `control_addrs` (the cluster-control port,
the relay registrar), so discovery dials where each service actually answers even
under a split cluster-control listener.

## What was proven

**Both controllers live + discoverable.** Two rows in `controllers`; the signed config
carries two `ControllerEndpoints`; the agent is online and owned by exactly one controller
(`agent_affinity`).

**Client redirect to the agent's owner.** A client brokering on gw2 for an agent
whose control stream is owned by gw1 is redirected to gw1's signed endpoint, re-brokers
there, and runs the session — gw2 never tries to push an offer to an agent it does
not hold. `exec` succeeds identically through gw1 (direct) and gw2 (redirected).

**Cross-controller revoke ring.** A revoke issued on gw2 for a session brokered on gw1
rings gw1's per-owner `NOTIFY` channel; gw1 signs a fresh-epoch revoke with its own
durable epoch and delivers it to the agent. The live session is torn down (the
backgrounded `exec` is actually killed) — a deny raised on any controller reaches the
controller that holds the stream.

**Relay + agent re-home on a controller-node kill.** Stopping gw1's process
black-holes the relay and agent control streams; gRPC keepalive (both ends, timeout
inside the stale-TTL) tears them, and both re-home to gw2 — the relay re-registers
via the controller it discovered from `ControllerEndpoints.control_addrs` and stays in the
signed map (presence stays fresh, never aging out), and the agent fails over to gw2
(`agent_affinity` flips to `ha-gw2`, a new epoch) and keeps serving sessions. gw1
rejoins the fleet on restart.

## Boundary

Two processes on one host prove the cross-controller CONTROL plane (routing, redirect,
revoke, presence, failover) but not a true cross-machine network partition; the
single managed-Postgres-primary failover bound (new-access fail-closed, in-flight
tunnels unaffected) is the documented trade-off, not exercised here. The data plane
is unaffected by a controller loss — established E2E tunnels never traverse a controller.
