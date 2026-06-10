# OpenStack metadata enrollment + boot-time agent (PoC seam)

This document specifies the integration seam that lets a Geneza agent enroll
itself **at VM boot** using the cloud's instance identity, with **no join token
to distribute** — the tokenless path described in ARCHITECTURE.md §5
("cloud instance identity docs ... one-time tokens otherwise").

The seam is already wired in the gateway: `internal/gateway/enroll.go` defines
an `EnrollmentProvider` interface and registers two providers —

- `token` — implemented; single-use, expiring join tokens.
- `openstack-metadata` — **registered as a stub** that returns
  `codes.Unimplemented`. This file is the spec for filling it in.

Nothing else in the system needs to change to add a provider: the agent already
sends `provider` + `provider_document` in `EnrollRequest`, and the gateway
dispatches on `provider`.

## How OpenStack instance identity works

An OpenStack instance can prove its identity to an external service without any
pre-shared secret using the **signed instance identity document** exposed via
the metadata service / config drive:

```
GET http://169.254.169.254/openstack/latest/meta_data.json   # claims (uuid, name, project_id, ...)
GET http://169.254.169.254/openstack/latest/vendor_data2.json # optional vendordata
```

Nova can also issue a **signed** document; where the deployment provides one
(e.g. via a Barbican-backed signing key or the `vendordata` dynamic plugin),
the agent fetches the signature and the gateway verifies it against the cloud's
published certificate. Where a deployment does *not* expose a signed document,
the equivalent trust is obtained by having the gateway **call back to Keystone**
to validate an instance-scoped token, or by validating the instance UUID +
project against the Nova API over the management network. Both are supported
shapes of the same provider.

## Agent side (already structured for this)

`geneza-agent enroll` takes `--provider`. Today it sends `provider=token`. The
PoC adds `--provider openstack-metadata`, on which the agent:

1. Reads `meta_data.json` (and the signature/vendordata if present) from
   `169.254.169.254` or the config-drive mount.
2. Puts the raw document bytes in `EnrollRequest.provider_document` and the
   instance name in `requested_name`.
3. Sends the same CSR + Noise static key as the token path.

Everything after enrollment (cert custody, control channel, session handling)
is **provider-independent** and already done.

## Gateway side (to implement)

Replace the stub in `enroll.go`:

```go
type openstackProvider struct {
    keystoneURL string
    novaURL     string
    trustRoots  *x509.CertPool // cloud's instance-document signing chain
    httpc       *http.Client
}

func (p *openstackProvider) Name() string { return "openstack-metadata" }

func (p *openstackProvider) Verify(ctx context.Context, req *genezav1.EnrollRequest) (labels map[string]string, name string, err error) {
    // 1. Parse req.provider_document as the OpenStack meta_data.json (+ signature).
    // 2. Verify the signature against p.trustRoots, OR validate the instance
    //    via Keystone/Nova (uuid + project_id must reference a running instance).
    // 3. Enforce a binding policy: which projects/images/keypairs/metadata tags
    //    are allowed to enroll, and with which labels.
    // 4. Return labels derived from instance metadata (project_id, az, flavor,
    //    server-group, user metadata `geneza.role=...`) and the instance name.
    //    Reject (error) on any mismatch — fail closed.
}
```

Registration (already present, swap the stub for the real one):

```go
gw.enrollers["openstack-metadata"] = &openstackProvider{ ... } // config-driven
```

### Anti-replay

The instance document is long-lived, so the gateway must prevent a captured
document from enrolling twice: key the dedupe on instance UUID and refuse a
second enrollment for a UUID that already has a live node, unless the existing
node's cert has expired (instance was rebuilt). This mirrors the single-use
semantics of the token provider.

## Boot-time install (cloud-init)

`cloud-init/geneza-agent.cloud-config.tmpl` installs the bootstrap at first
boot and points it at the gateway. With the OpenStack provider, **no token is
templated in** — the instance authenticates with its own identity:

```yaml
runcmd:
  - geneza-agent enroll --config /etc/geneza/agent.yaml --provider openstack-metadata
  - systemctl enable --now geneza-bootstrap
```

Set the desired Geneza role through standard OpenStack instance metadata, e.g.
`openstack server create --property geneza.role=web ...`; the gateway maps it to
node labels, and policy keys off those labels — so a freshly booted VM is
reachable under the right policy with zero manual steps.

## Demo wiring against an existing lab cloud

The hypervisor already runs OpenStack labs (`kolla1`, `sunbeam1`, `scs1`). A
full PoC would:

1. Run the Geneza gateway/relay reachable from the OpenStack tenant network
   (the geneza-core VM, or a floating IP).
2. Bake `geneza-bootstrap` + the pinned `artifact.pub` into a Glance image (or
   install via cloud-init `packages`/`runcmd`).
3. Boot an instance with `--property geneza.role=...`; watch it appear in
   `geneza ls` within ~1 boot cycle, enrolled with no operator action.

This file is referenced by the gateway's stub error message so the path from
"why did enrollment say Unimplemented" to "here's how to finish it" is one hop.
