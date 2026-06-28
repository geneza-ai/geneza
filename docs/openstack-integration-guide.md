# Integrating OpenStack with Geneza

Make every VM in an OpenStack project **auto-enroll into Geneza at boot** — no
token to bake in, no per-VM step — and let project members log into the Geneza
console with their **Keystone identity**. This is implemented and validated
against real Nova (2026.1).

> **Scope.** This is the OpenStack-specific wiring for a Geneza control plane you
> **already run**. Deploying Geneza itself — a controller, one or more relays (often
> across regions), Postgres, and the DNS / managed-domain setup for
> browser-trusted TLS — is operator-run and out of scope here; start from the
> [install tutorial](../INSTALL.md). For the trust model behind this integration
> (confused-deputy defense, the service-token gate, per-project isolation), read
> [`docs/openstack-integration.md`](openstack-integration.md) before production.

Three operator steps: register the cloud on the controller, point Nova at the
controller's vendordata endpoint, then boot VMs with a config drive.

## 1. Register the cloud on the controller

Add a `clouds:` block to the controller config, keyed by an operator-chosen **slug**
Geneza owns (not the Keystone FQDN):

```yaml
clouds:
  mycloud:                              # service-uid: your stable slug (e.g. prod-fra)
    kind: openstack
    keystone_url: https://identity.example.com/v3
    require_nova_service_token: true    # only Nova's service token may enroll a VM
    auto_provision: true                # lab: true; prod: false, pre-bind projects to workspaces
    role_map: { admin: ws-admin, member: ws-user, reader: ws-viewer }
```

Apply it the way you manage the rest of the controller config (with the compose
installer, edit `config/controller.yaml` and re-render with `docker compose up -d`;
don't hand-edit a rendered `generated/controller.yaml` that an installer run will
overwrite).

> `auto_provision: true` is the lab default — the first VM in an unbound project
> creates and binds a workspace automatically. In production set it to `false`
> and pre-bind projects to workspaces with the platform-admin API; unbound VMs
> then land PENDING instead of self-provisioning (see the project-binding and
> auto-provision model in `openstack-integration.md`).

## 2. Point Nova at the vendordata endpoint

On the cloud's controllers, set Nova's dynamic vendordata target to the controller's
endpoint for this slug, then restart `nova-api`:

```ini
# nova.conf
[api]
vendordata_providers = StaticJSON, DynamicJSON
vendordata_dynamic_targets = cloud-init@https://<controller>/openstack/vendordata/mycloud
```

`<controller>` is the control plane's public name on `:443` (e.g.
`geneza.example.com`) — the same TLS front that serves the console. The slug
(`mycloud`) at the end of the path selects the `clouds:` entry from step 1. The
endpoint is reached over `7402` behind the TLS front; Nova must be able to
resolve and reach it over system-trusted TLS.

```sh
# kolla-ansible example; for a manual deploy, restart your nova-api service.
systemctl restart nova-api    # or: kolla-ansible -i inventory reconfigure -t nova
```

## 3. Boot VMs with a config drive

Any VM booted **with a config drive** in a bound project auto-joins at boot:

```sh
openstack server create web1 \
  --image ubuntu-24.04 --flavor m1.small \
  --network mycloud-net --key-name mykey \
  --config-drive true
```

The VM's cloud-init runs the controller-served `#cloud-config`, installs the agent,
and enrolls. Nova attaches its service token to the vendordata call; the controller
validates it, resolves the VM's project from Nova's authoritative `tenant_id`,
maps it to a workspace, and admits the node. Project members then log into the
Geneza console with their **Keystone password** (cloud dropdown) or via **Horizon
SSO**, and see the project's VMs.

## Verify

Boot a test VM and watch it appear by name, then reach it:

```sh
openstack server create geneza-probe \
  --image ubuntu-24.04 --flavor m1.small \
  --network mycloud-net --key-name mykey --config-drive true

# within a minute, from any member of the same workspace:
geneza ls                  # geneza-probe shows up, auto-enrolled
geneza ssh geneza-probe    # reachable by name over the Noise tunnel through the relay
```

If it doesn't appear: confirm the VM was booted `--config-drive true`, that
`vendordata_dynamic_targets` points at the right slug and the controller can be
reached from the compute / `nova-api` host over TLS, and check the controller log
for the vendordata hit (a `404` means the slug isn't in `clouds:`; a rejected
token means `require_nova_service_token` saw a non-service caller). The full
request contract and failure modes are in
[`docs/openstack-integration.md`](openstack-integration.md).
