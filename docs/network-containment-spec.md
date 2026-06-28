# Network containment

Let a machine owner quarantine a (possibly compromised) machine from the Geneza
console — cut its network so an attacker who is already inside (via SSH or any
other path) loses C2, exfil, lateral movement, and their own access — while the
Geneza agent's lifeline to the controller survives so the owner keeps eyes on the
box and can release containment.

## Threat model

The attacker has a foothold INSIDE the guest, possibly with root, reached by a
path Geneza does not mediate (a stolen SSH key, a service exploit). They may try
to kill or tamper the agent to defeat containment. The network may still be up
(the owner is reaching the box through Geneza) or the attacker may have cut the
agent's control channel.

## The principle: enforce OUTSIDE the guest

An in-guest agent **cannot** be made to survive guest-root such that *it* enforces
irreversible containment — root can `kill` it and `nft flush ruleset`. So the
load-bearing containment is enforced **outside the guest**, where guest-root has
no reach: the hypervisor / cloud network layer and the Geneza control plane.

Two consequences shape everything below:

1. **Containment must not route through the compromised VM.** The path is owner →
   controller → hypervisor/cloud → cut. The VM (and its agent) is never in the trust
   path of its own containment, so a fully-owned guest cannot undo it.
2. **The agent is a sensor + trigger, not the enforcer.** "The agent survives the
   hack" means the agent's *job* survives: killing or tampering it is itself a
   containment trigger (a dead-man's switch evaluated at the controller, enforced
   out-of-guest). Killing the agent triggers the very cut the attacker wants to
   avoid.

## Layered containment — the `containmentProvider` seam

Containment fans out to the providers configured for a machine, best-first. The
seam mirrors Geneza's other pluggable backends (DNS, storage, keysource):

```
type containmentProvider interface {
    Contain(ctx, machine, allow []endpoint) error // deny all but the allowlist
    Release(ctx, machine) error
    Kind() string
}
```

1. **Hypervisor / cloud — primary, irreversible by guest-root.**
   - `openstack-neutron`: swap the instance to a quarantine security group (or
     detach the port) via gophercloud. gophercloud is already a dependency (used
     for Keystone identity today); this extends it to Neutron with a service
     account scoped to SG/port mutation on Geneza-managed instances. It reuses the
     same cloud trust relationship Geneza already uses to enroll VMs.
   - `proxmox`: the Proxmox firewall API / NIC config on the VM's vNIC.
   - `libvirt`: nwfilter.
2. **`overlay` — already exists, instant.** De-approve the node
   (`SetNodeApproval(false)` → `repushAllNetworks`): every peer drops it from its
   WireGuard set and it loses all Geneza-mesh reach immediately. Controller-side, so
   guest-root cannot undo it — but it only cuts the Geneza path, not the
   attacker's non-Geneza SSH, which is why the hypervisor/cloud layer is primary.
3. **`agent-nftables` — defense-in-depth + bare-metal fallback.** The agent
   applies a default-deny ruleset. Defeatable by guest-root, but it raises the
   bar, covers hosts with no cloud/hypervisor API, and its *removal is a tamper
   signal* that escalates to the out-of-guest layers.

## Selective containment — keep the lifeline

Containment cuts everything EXCEPT the agent↔controller control channel (the `allow`
list = the controller/relay endpoints). The attacker loses C2 / exfil / lateral /
SSH; the owner keeps observability, can run forensics *through* Geneza, and can
Release. The lifeline is an authenticated mTLS/Noise control channel, not a
general egress, so the attacker cannot tunnel out through it. A "hard" mode (no
allowlist, total cut) is available for the case where even the lifeline is
distrusted.

## The agent as a survivable trigger (anti-tamper)

- **Authority lives at the controller + hypervisor**, out of guest — guest-root
  cannot revoke it.
- **Death / tamper = trigger.** The controller watches the agent heartbeat and an
  integrity self-check; silence beyond a grace window OR an integrity failure
  auto-contains via the hypervisor/cloud + overlay providers. The watchdog is the
  controller — outside the guest by construction.
- **Harden the agent to make tamper loud, not invincible:** signed binary +
  periodic self-verify, `geneza-bootstrap` restart (systemd `Restart=always` +
  watchdog), the session-host/worker split, a locked-down unit. Never depend on
  the agent surviving; make its death fast-detected and self-defeating.

## Console flow

`Machine → Contain` → controller: (a) revoke overlay membership now; (b) call the
configured hypervisor/cloud provider to apply the quarantine SG/firewall; (c)
push an in-guest deny to the agent if it is still reachable. The machine shows
**Contained**, with which layers succeeded. `Release` reverses all three. Every
action is audited. The manual path works even if the agent is already dead or cut
— the controller calls the cloud/hypervisor API directly.

## The tension to calibrate

Auto-contain-on-silence needs a **grace window + path diversity** (a DERP/relay
mesh so a single cut link does not look like death) so a flaky network does not
quarantine a healthy VM. Manual contain is always available and needs no agent
cooperation. Containment can be graduated by asset sensitivity (deny-new →
drop-overlay → full cut) at increasing grace thresholds.

## The honest limit

Containment bounds blast radius and persistence; it does not undo a breach. Data
already on the box, and actions inside the grace window, cannot be clawed back —
they are minimized (short windows, no standing secrets, encryption at rest), not
reversed. The guarantee is: the attacker keeps the box but loses the network, and
cannot use it to pivot or to forge continued trust.

## Build phases

1. **`containmentProvider` seam + `overlay` provider** (wraps the existing
   de-approve/repush) + the console Contain/Release action + audit.
2. **`openstack-neutron` provider** (gophercloud → quarantine SG) — the primary
   out-of-guest cut for the OpenStack path Geneza already enrolls.
3. **`agent-nftables` provider** (in-guest defense-in-depth + tamper signal).
4. **Tamper trigger**: controller auto-contain on agent silence / integrity failure,
   with the grace-window calibration.
5. **`proxmox` / `libvirt` providers** for self-managed hypervisors.
