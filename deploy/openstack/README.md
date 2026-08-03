# Geneza on OpenStack — Terraform + Ansible

An HA control plane (controllers + Postgres + Caddy) and a multi-region relay
layer, on any OpenStack cloud. Written against OVH Public Cloud; nothing in it
is OVH-specific except the defaults.

```sh
cd deploy/openstack
cp terraform/terraform.tfvars.example terraform/terraform.tfvars   # edit
export OS_CLOUD=...                       # or source an openrc
export GENEZA_SSH_KEY=~/.ssh/id_ed25519   # private half of var.ssh_public_key
./deploy.sh
```

`deploy.sh` applies the Terraform, generates the Ansible inventory from its
outputs, **verifies DNS before going further**, then runs the playbooks.

`GENEZA_SSH_KEY` is required unless the key is already in `ssh-agent`: Terraform
only ever sees the public half, so nothing generated from it can tell Ansible
where the private half lives. It is also used for the jump to the database,
which has no floating IP.

Between `terraform apply` and the DNS check the script stops and prints the
records to create — the controllers' own names must resolve before Caddy can
complete an ACME challenge.

---

## What it builds

```
        browsers / tenant portal            agents + geneza CLI
                  │ :443                         │ :7401 :7402
        ┌─────────┴──────────────────────────────┴─────────┐
        │  gw1        gw2        gw3   (anti-affinity)     │
        │  each with its OWN name, floating IP and cert    │
        └──────────────┬───────────────────┬───────────────┘
             :7405     │ private net       │ shared Postgres
        (registrar,    │                   │
     relay FIPs only)  │                   │
        ┌──────────────┴─────┐   ┌─────────┴────────┐
        │ relays (home)      │   │ relays (region B │
        │ :7403/tcp :7404/udp│   │  or another cloud)│
        └────────────────────┘   └───────────────────┘
```

- **Controllers** — hard anti-affinity server group, so losing a hypervisor
  cannot take the control plane with it. A soft policy is available for regions
  that refuse hard placement, but a hard failure is better than silent
  co-location.
- **Relays** — stateless, payload-blind, one security group per cloud. They
  self-register and fail over across controllers on their own.
- **Everything boots from volume**, sized and typed by variable.

## Networking, and the two traps

Floating IPs are 1:1 NAT here: the instance only ever sees its private address.
Two settings therefore cannot be left to defaults, and both are handled for you:

**1. A relay must be told its floating IP.** The TURN server advertises
`public_ip` *statically* to clients. Set it to the private address and TURN hands
out an unroutable target — no error anywhere, UDP simply never establishes.
Terraform passes the floating IP through to `relay.yaml`.

**2. Controllers must advertise their OWN names, never a shared LB name.**
`controllerEndpoint()` publishes `advertise.*` into the signed cluster map, and
that is verbatim what a `ControllerRedirect` hands a peer. If every replica
advertised one balancer name, a redirect would route back through it — possibly
onto the controller that just issued it — and a client refuses to chase a second
redirect. Redirects would become a coin flip. So each controller gets
`gw<N>.<site_domain>`, its own floating IP, and a cert covering both that and the
site name.

A load balancer is optional on top: it buys a stable bootstrap address and
nothing else, because peers re-home across the signed map themselves.

**Controllers talk to each other privately.** They dial siblings *by advertised
name* so TLS verifies, but `/etc/hosts` resolves those names to private
addresses — hairpinning out to a sibling's floating IP and back into the same
project is unreliable, and this codebase has already been bitten by it once (see
`console_shell.go` on the relay hairpin).

**A third trap, if your cloud has several external subnets.** One `public`
network can carry many, with different routing and different exhaustion. Neutron
will happily hand you an address from a range that is not globally announced:
the allocation succeeds, the instance goes ACTIVE, and the floating IP is simply
unreachable — from outside *and*, for outbound NAT, to much of the internet.
Nothing in the API reports this. Set `public_subnet_id` to pin allocation to a
subnet you have confirmed is routed. To check one before you rely on it:

```sh
# from a host OUTSIDE the cloud, once port 80 is open in the security group
#   "connection refused" = routed;  "no route to host" / timeout = not
timeout 6 bash -c 'echo > /dev/tcp/<floating-ip>/80'
```

## The control channel

You asked for the controller↔relay control channel to be closed to everything
but the known peers. It is, and the mechanism is worth knowing:

The relay registrar runs on its **own** port (`cluster_control_listen: :7405`)
rather than sharing `:7401`. That split is what makes the restriction possible —
`:7401` must stay open to agents and clients everywhere, so a registrar sharing
it could only be "open to everyone" or "open to no one". On `:7405` the security
group admits exactly the relay floating IPs Terraform allocated, `/32` each,
across every region and every cloud. Adding a relay adds precisely one rule.

Direction matters: a relay is never dialled by a controller — registration is
relay-initiated — so the restriction belongs at the controller's ingress and
there is nothing to open on the relay side.

`:7401` additionally admits the other controllers' floating IPs, for the
cross-controller redirect and the web-shell re-broker.

## Certificates

Four kinds, four different clocks. Conflating them is how people lock themselves
out of their own fleet:

| Kind | Rotation |
|---|---|
| Public web TLS (console, launch URLs) | **Caddy + Let's Encrypt**, automatic |
| Controller server certs | `geneza-cert-renew` systemd timer, daily with jitter, renews inside a 30d window via `reissue-tls` against the existing CA |
| **Relay certs** | **automatic, nothing deployed** — a relay attaches a CSR to its registrar heartbeat and the controller signs it in place. SANs come from the relay's authenticated mTLS leaf, not the CSR, so a relay can only ever renew *itself* |
| User/node leaf certs | short TTL, minted per login/enrolment. Expiry *is* revocation |
| **CA root** | **no rotation exists** — see below |

The CA root key is generated on the primary controller and then **retrieved to
the operator's machine and removed from the instance** (`geneza_evacuate_root_key`).
ARCHITECTURE §2 ranks it above the controller itself — "whoever holds them owns
the fleet" — so leaving it on an internet-facing instance would make a controller
compromise a fleet compromise, defeating the two-tier CA entirely. It lands in
`ansible/.ca/<site_domain>/offline-root/`; move it somewhere real (an HSM, a KMS,
a safe) and delete it from there.

Retrieval happens *before* deletion, and deletion is gated on the retrieval
having succeeded. An un-retrieved root key that gets deleted is unrecoverable.

The staging path is **namespaced by site** for the same reason: managing two
clusters from one checkout would otherwise have the second `init` overwrite the
first's staged root key, and that copy is the only one left after evacuation.

**There is no CA root rotation.** `rotate-ca.yml` is a stub that refuses to run
and explains why: the controller CLI has no way to publish a second root, emit a
combined old+new bundle, or report which root each node trusts — and without that
last one there is no safe moment to switch. Agents dial out, so a node that has
not learned the new root before a switch is unreachable forever with no inbound
path to repair it.

This is less alarming than it sounds, because an offline root does not need
emergency rotation, and everything beneath it rotates on its own (see the table
above). If the root is ever believed compromised, treat it as a rebuild.

## Postgres

The one component whose HA you must provide yourself — controllers and relays
are stateless and survive anything. Set `external_postgres_dsn` to a managed,
replicated Postgres and Terraform skips the database instance entirely. The
built-in single-instance role is for labs.

## Adding a relay region

1. Declare a provider alias in `versions.tf` (three are pre-declared).
2. Add an entry to `relay_regions` keyed by that alias.
3. Copy a `module "relay_<alias>"` block in `relays.tf` — Terraform cannot select
   a provider from a `for_each` key, so the blocks are explicit by necessity.
4. `./deploy.sh`. The new relay's floating IP is added to every controller's
   registrar allow-list automatically.

A relay in a wholly different cloud works the same way; it needs its own
`public_network_id` and a pre-existing keypair in that cloud.

## What this does not do

- **No agent enrolment.** Deploying the control plane is separate from joining
  nodes to it; use `geneza node enroll` or the OpenStack vendordata path.
- **No OpenStack *integration*.** Hosting Geneza on a cloud and integrating with
  that cloud are different things — vendordata enrolment and trusted-dashboard
  SSO both require operator access to Nova and Keystone. Against a public cloud
  you are a tenant of, they are unavailable. See `docs/hosted-ui-launch-guide.md`.
- **Single-instance Postgres by default.** It is the one stateful component and
  the one single point of failure; set `external_postgres_dsn` to a managed,
  replicated service and this Terraform skips building it.
- **CA root rotation does not exist.** See the certificates section above.

## Upgrading

`geneza_image_tag` in `ansible/group_vars/all.yml` pins the controller and relay
images to a released version. **Do not set it to `latest`.** That tag only moves
when a `v*` tag is pushed, so it lags `main` silently — a deploy from this repo
once ran a month-old build with nobody the wiser. A mutable tag also means two
controllers provisioned a week apart can end up on different builds.

To move the fleet: bump `geneza_image_tag` and re-run `./deploy.sh`. Controllers
roll one at a time (`serial: 1`), and a restart drops no live session — sessions
are end-to-end between client and agent over the relay, so the controller is out
of the data path. It briefly refuses NEW sessions, which is why the play is
serialised.

## Status

Applied and run against **two** live OpenStack clouds on 2026-08-03: acvile
eu-east-1 (single controller) and OVH Public Cloud EU-WEST-PAR (two controllers,
HA). The Terraform, security groups, CA role, Postgres, Caddy and the relay
issuance and registration paths have all executed for real, not just validated.
On OVH the HA paths are proven end to end: the trust anchor seeded to a
secondary, per-controller certificates carrying their own advertised names, both
controllers registered advertising those names, and a session minted on one
accepted by the other. See FINDINGS.md.

**OVH auth note:** OVH issues OIDC client credentials, and the OpenStack
Terraform provider has no `v3oidc*` plugin. Mint an application credential from
the OIDC session and give Terraform that:

```sh
source ~/.rc/ovh/geneza.sh          # OIDC
openstack application credential create geneza-tf
export OS_AUTH_TYPE=v3applicationcredential
export OS_APPLICATION_CREDENTIAL_ID=... OS_APPLICATION_CREDENTIAL_SECRET=...
```

Two things are worth knowing before you trust a green run elsewhere:

- **`terraform validate` cannot catch a `for_each` over apply-time values.**
  That class of error only appears at `plan` time against real credentials. Run
  a `plan`, not just a `validate`.
- **`ansible-playbook --syntax-check` does not render templates.** An undefined
  variable in a `.j2` surfaces only when the task actually runs, three plays in.
  A `--check` run against real hosts finds them; a syntax check never will.
- **A floating IP can be allocated and still be unreachable.** See the
  networking section on `public_subnet_id`. Verify from outside the cloud.
