# Installing Geneza

Geneza gives you identity-aware SSH, exec, file transfer, port-forward and L3 VPN
to a fleet of nodes, with end-to-end encryption through a payload-blind relay.

Two parts:

- **Control plane** — a controller + a relay, run with Docker Compose.
- **Agents** — one per node, installed with a one-line script. Agents **dial
  out** (no inbound ports), so there is nothing to open on the node itself.

---

## Prerequisites

- A control-plane host with **Docker + Docker Compose**, reachable by your nodes.
- Inbound on that host: **7401** (control), **7402** (HTTPS login/enroll),
  **7403/tcp** + **7404/udp** (relay rendezvous + NAT-traversal floor).
- The `geneza` client on your laptop — download it for your OS from the
  [releases page](https://github.com/geneza-ai/geneza/releases).

---

## 1. Run the control plane

```sh
curl -fsSL https://raw.githubusercontent.com/geneza-ai/geneza/wip/deploy/compose/install.sh \
  | sudo bash
```

Pick **controller+relay** when asked. The installer renders `/opt/geneza` and brings
up `controller`, `postgres`, `victoriametrics`, `caddy`, and `relay`, then prints a
break-glass **admin password** — save it. Re-run the same command anytime to
**upgrade** (it pulls newer images and reuses your answers).

> Control plane on one host and relays elsewhere? Choose **controller**, then run the
> installer with **relay** on each relay host. Several controllers for high
> availability? See [`deploy/ha/`](deploy/ha/README.md).

---

## 2. Become admin

Use the break-glass identity the installer issued:

```sh
export GENEZA_HOME=/opt/geneza/generated
geneza --profile admin ls            # should connect and show an (empty) fleet
```

For day-to-day users, configure an IdP (`oidc:` or `clouds:` in `controller.yaml`)
and have them run `geneza login --controller <host>`.

---

## 3. Enroll a node

Mint a one-time enrollment code. `geneza node enroll` prints a ready-to-paste
one-liner — copy it onto the node you're enrolling:

```sh
geneza --profile admin node enroll --ttl 1h
# ...
# Run this on the new node:
#   curl -fsSL https://<controller>:7402/install.sh | sudo sh -s -- gzk_XXXX
```

The `gzk_` code bundles the one-time join token and the pinned root-key
fingerprint; the controller-served `install.sh` verifies that fingerprint before
trusting anything it downloads, so the `curl | sh` is safe. Just run the printed
line on the target Linux node.

Prefer to install from the GitHub release assets (pinned versions, a
pre-placed CA bundle, or `--uninstall`)? The same code works there too:

```sh
# on the Linux node to enroll:
curl -fsSL https://raw.githubusercontent.com/geneza-ai/geneza/wip/deploy/install/install-agent.sh \
  | sudo bash -s -- gzk_XXXX --controller <host>:7401
```

(That installer trusts the controller via `--ca` / trust-on-first-use rather than
the root-key pin, and the `node enroll` code carries no endpoints, so pass
`--controller`. See `--help` for `--version`, `--ca`, and `--uninstall`.)

The node enrolls and lands **PENDING** (the token alone grants no access).
Approve it:

```sh
geneza --profile admin node approve <name>
```

---

## 4. Use it

```sh
geneza --profile admin ls                  # the fleet
geneza --profile admin ssh <name>          # interactive shell
geneza --profile admin exec <name> -- uptime
geneza --profile admin connect <name> <service>   # forward a service to localhost
geneza --profile admin vpn <name>          # L3 overlay
```

Every session is brokered by the controller, runs end-to-end encrypted, and traverses
NAT through the relay — the relay never sees plaintext, the agent never listens.

---

## 5. OpenStack: zero-touch VM enrollment

Geneza can auto-enroll OpenStack VMs at boot and let project members log in with
their Keystone identity.

> The steps below are the quickstart; the full operator walkthrough (production
> auto-provisioning, verify, troubleshooting) is in
> **[`docs/openstack-integration-guide.md`](docs/openstack-integration-guide.md)**,
> and the trust model is in
> [`docs/openstack-integration.md`](docs/openstack-integration.md).

**a. Register the cloud** in the controller's `clouds:` block (`controller.yaml`):

```yaml
clouds:
  mycloud:                              # service-uid: your stable slug
    kind: openstack
    keystone_url: https://identity.example.com/v3
    require_nova_service_token: true    # only Nova's service token may enroll a VM
    auto_provision: true                # prod: false, and pre-bind projects to workspaces
    role_map: { admin: ws-admin, member: ws-user, reader: ws-viewer }
```

**b. Point Nova at the controller's vendordata endpoint** (`nova.conf`, then restart
`nova-api`):

```ini
[api]
vendordata_providers = StaticJSON, DynamicJSON
vendordata_dynamic_targets = cloud-init@https://<controller>/openstack/vendordata/mycloud
```

Now any VM booted with `--config-drive` in a bound project **auto-joins Geneza** at
boot, is reachable by name, and its project members can sign into the Geneza
console with their Keystone password (or via Horizon SSO).

Full trust model, the access plane, and hardening: **`docs/openstack-integration.md`**.

---

## Production notes

- The bundled **Caddy** already fronts the console with a Let's Encrypt cert when
  you give the installer a `--site` FQDN (and an `--acme-email`). Point your DNS
  at the host and browser/CLI logins get a publicly-trusted cert automatically.
- A relay that serves **Funnel** (public exposure) needs a public IP — set
  `public_ip`, or let the installer's `geneza-relay detect-public-ip` confirm it.
- Publicly-trusted certs for workspace/funnel hostnames: **`docs/managed-domain-spec.md`**.
- Quarantine a compromised node from the console: **`docs/network-containment-spec.md`**.
</content>
