# Relay-homed control

> Status: bootstrap split + relay-side acceptor + agent homing built and on `wip`
> (default-off, single-node byte-for-byte). Multi-controller revoke routing and the
> multi-VM production proof are follow-ups (see the end).

## Problem

An agent today holds two outbound things: one long-lived mTLS control stream to a
controller, and ephemeral per-session dials to a relay. At scale the controller tier is
small (a few replicas) while the relay tier is large (many PoPs), so terminating
every agent's control stream on the controller tier concentrates connection cardinality
exactly where there is least capacity, and the agent's control socket may be far
from it. We want the agent to hold **one** outbound connection — to its nearest
relay — and let that relay carry the control stream to a controller, without the relay
ever becoming a trusted party or learning what the control stream says.

## Shape

Three pieces, each independently shippable and inert until the fleet opts in:

1. **Bootstrap split.** A cheap unary `NodeControl.FetchClusterConfig(have_version)`
   lets an enrolled agent refresh the signed cluster map (controllers, relays, trust
   keys) without holding the heavy `NodeControl.Stream`. The controller returns the
   current signed map when the caller is behind, an empty reply otherwise. An agent
   runs a jittered refresh loop so a just-restarted or long-disconnected node
   converges its fleet view directly, and a wedged push is caught within one period.
   This decouples "learn the map" from "open the control stream" — the prerequisite
   for moving the stream off the controller.

2. **Relay control mux (relay side).** The relay's existing TCP rendezvous listener
   gains a second hello kind. A `RelayHello{Kind:"control", ControllerID}` (vs the
   single-use token rendezvous, `Kind:""`) asks the relay to forward this connection
   to a controller. The relay resolves the agent-supplied `ControllerID` — a routing
   **label**, never an address — to a dial address from its own signed,
   signature-verified map, dials the controller's `NodeControl` listener over **plain
   TCP** (no TLS on this leg), and raw-splices. Because the relay terminates no inner
   TLS, the agent's own end-to-end mTLS rides through it and terminates **on the
   controller**; the relay parses not one inner byte.

3. **Agent homing (agent side).** When the signed map advertises a control-mux relay,
   the agent homes its control stream through it: it dials the relay (TLS, leaf
   pinned to the signed fleet), sends the control hello, then runs its normal mTLS
   `NodeControl.Stream` over the spliced connection. The inner TLS pins the **controller**
   (its CA + cert SAN) at TLS 1.3, so the relay sees the SNI and ciphertext but never
   the agent cert or the control payload.

## Why this keeps the relay out of the control plane

The relay is a blind L4 pipe, not a control-plane participant. The agent's stream
still terminates on exactly one controller — the one the relay dialed — and that
controller runs the same affinity claim it runs for a directly-connected agent. The
relay is invisible to ownership: cross-controller routing (a revoke raised on controller A
for an agent whose relay forwarded to controller B) stays the job of the existing
publish-to-owner router, unchanged. So relay homing carries only the **last hop** to
a dial-out agent and composes with the HA routing already in place rather than
duplicating it.

## Trust and blindness

- **The relay dials only signed controllers.** The agent supplies a controller-id label
  with no address field. The relay resolves it against its own map, which it
  **verifies** (decode + signature check against a trust set pinned from its first
  signed map, with a monotonic version floor) before populating the routing table —
  stricter than the relay's own failover discovery, which may skip verification
  because it only ever dials those addresses back with its own mTLS. A label not in
  the verified map is refused; the relay dials nothing.
- **Belt-and-braces deny-list.** A resolved target that is loopback, link-local
  (including the cloud metadata address), multicast, or unspecified is refused, and
  the address is resolved once and dialled as a literal so a rebinding name cannot
  slip a denied IP past the check.
- **The relay cannot read or forge control.** The inner session is the agent's own
  mTLS to the controller, TLS 1.3, so the agent cert and the payload are encrypted from
  the relay. The relay can drop or delay bytes — a liveness attack, not a
  confidentiality or forgery one — and a dropped controller→agent direction simply
  starves the fail-closed session lease, so a revoke still bites within the lease
  TTL. The relay can neither fake delivery nor suppress that starvation.

## Gating — off by default, single-node byte-for-byte

Three independent gates, all absent on a single-node deployment, plus an agent
kill-switch:

- **Relay config** `control_mux` (default off). A relay without it rejects every
  control hello. It requires a registrar — a relay with no signed controller map to
  validate against fails control closed.
- **Signed capability.** The relay advertises the capability and its TCP control
  address in its heartbeat; the controller carries them as signed `RelayNode` fields.
  The single-node synthesized map never sets them.
- **Agent predicate.** The agent homes only when the signed map has a control-mux
  relay and a controller discovery set (a real fleet) and it is not in a post-failure
  cooldown. On single-node the discovery set is empty, so the agent builds the
  identical direct dial it builds today.
- **Kill-switch** `relay_homed_control` (default on, inert without a capable relay)
  forces direct everywhere for a staged rollout.

## Fallback — direct is always the floor

Any relay failure degrades to a direct controller dial, never to no control plane:

- A relay dial or handshake failure falls back to a direct dial for that attempt and
  starts a short cooldown, so the agent does not immediately retry a bad relay.
- A relay-homed stream that establishes then dies fast triggers the same cooldown, so
  a flapping relay cannot hot-loop the agent between relay and direct.
- The relay forwards to the same controller the direct path would dial, so a relay-homed
  stream and its fallback target one controller, and the controller rotation re-targets both
  together. The spliced control connection is single-use; any gRPC reconnect attempt
  re-homes from scratch.

The unary map refresh always uses a direct seed connection, so an agent re-homing or
cooling down still refreshes its map and renews its cert.

## A note on the observed source IP

The controller records a control stream's source IP as half of the node's direct-WG
endpoint hint. Under relay homing that IP is the relay's. This only mis-hints the
non-default kernel-WG direct path; the default userspace data plane gathers its own
server-reflexive candidates via STUN and ignores it, and relay homing implies a
multi-region fleet where kernel-WG's same-L2 assumption does not hold. It is a
documented tension, not a regression for the default plane.

## What is proven, and what is not yet

Proven: the relay blind-splices arbitrary bytes verbatim over a plain leg (relay
unit tests); the agent's full path — dial the relay, run gRPC mTLS through the
splice to a controller, hello up and a push back, relay parsing nothing — works against
a real gRPC mTLS controller (an in-process integration test with real certificates); the
signed-map verification, the SSRF guard, the homing predicate and fallback gates, and
single-node byte-for-byte behavior (the full lab battery stays green).

Follow-ups: a multi-VM production proof (a registrar-mode controller plus a real
control-mux relay plus an agent homing through the real signed map) closes the
real-relay-against-real-agent gap end to end; multi-controller revoke routing for an
agent relay-homed to a different controller than the one a revoke is raised on composes
with the existing publish-to-owner router and is exercised when the HA topology is
stood up.
