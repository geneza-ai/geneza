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

Apply it the way you manage the rest of the controller config. With the compose
installer that means editing `config/controller.yaml` and **re-running
`install.sh`** — the container mounts `generated/controller.yaml`, which only an
installer run re-derives, so `docker compose up -d` on its own applies nothing.
The installer keeps a `config/controller.yaml` you have edited and drops its own
newer template next to it as `config/controller.yaml.new` for you to merge; don't
hand-edit `generated/controller.yaml`, which is overwritten every run.

> `auto_provision: true` is the lab default — the first VM in an unbound project
> creates and binds a workspace automatically. In production set it to `false`
> and pre-bind projects to workspaces with the platform-admin API; unbound VMs
> then land PENDING instead of self-provisioning (see the project-binding and
> auto-provision model in `openstack-integration.md`).

## 2. Point Nova at the vendordata endpoint

Set Nova's dynamic vendordata target to the controller's endpoint for this slug.
**Put this in `nova.conf` on the compute nodes**, not just the controllers: step 3
boots with a config drive, and the config drive is built by `nova-compute`, so a
target configured anywhere else is never consulted. (Configure it on
`nova-metadata` as well if you also want the `169.254.169.254` metadata service to
serve it — that path needs DHCP isolated-metadata or a router.)

```ini
# nova.conf — on the compute nodes
[api]
vendordata_providers = StaticJSON, DynamicJSON
vendordata_dynamic_targets = cloud-init@https://<controller>/openstack/vendordata/mycloud

[vendordata_dynamic_auth]
# Nova signs the callback with its own service token; the controller requires it
# when the cloud sets require_nova_service_token.
auth_type = password
auth_url = https://identity.example.com/v3
username = nova
project_name = service
# password / user_domain_name / project_domain_name as for your other Nova credentials
```

`<controller>` is the control plane's public name on `:443` (e.g.
`geneza.example.com`) — the same TLS front that serves the console. The slug
(`mycloud`) at the end of the path selects the `clouds:` entry from step 1. The
endpoint is reached over `7402` behind the TLS front; Nova must be able to
resolve and reach it over system-trusted TLS.

```sh
# kolla-ansible example; for a manual deploy, restart nova-compute (and
# nova-metadata if you configured it there too).
systemctl restart nova-compute    # or: kolla-ansible -i inventory reconfigure -t nova
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
