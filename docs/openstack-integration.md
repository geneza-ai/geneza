# OpenStack → Geneza integration — design spec

**Status:** design (2026-06-13). Trust model + wire format **empirically validated**
on the kolla1 lab (Nova 2026.1): live vendordata capture, Keystone token
validation, and project→domain resolution all confirmed (see "Validated facts").
Supersedes the earlier seam draft (which wrongly assumed Nova signs metadata —
**it does not**; see §3).

The integration has two independent planes; build them separately:

- **Enrollment plane** (this spec's focus, PoC): a VM **auto-joins Geneza at boot**
  via the cloud's metadata, no pre-distributed secret. After it joins, it is a
  normal Geneza node — reachable from `geneza ssh`/`exec` and the overlay.
- **Access plane** (§13, design): a human, **already authenticated to OpenStack**,
  drives Geneza (web shell / CLI) by presenting a **Keystone token** that Geneza
  validates — no separate Geneza login.

Both planes share one substrate: a **workspace** is the hub, and OpenStack
**projects** (and IdP groups, and direct invites) are **bindings** onto it (§6).

---

## 1. Goal & non-goals

**Goal:** `openstack server create … --property geneza.workspace=…` → the VM boots,
enrolls into the correct **Geneza workspace** (derived from its OpenStack tenancy,
not chosen by the courier), and is reachable over the Geneza overlay + in-network
DNS from co-members (e.g. `geneza-laptop`), with **zero operator action per VM**.

**Non-goals (deferred):** the access-plane web-shell-in-Horizon SSO (§13 is design
only); forked cloud-init / custom Glance image (stock image suffices, §12);
multi-cloud providers beyond OpenStack (§14 sketches the generalization).

---

## 2. Trust model (the spine)

**The auth guard is Keystone-token validation — not a per-domain OIDC issuer.**
Geneza validates every credential against the Keystone cluster(s) it is configured
to talk to:

- **Enrollment:** the vendordata call carries **Nova's service token**; Geneza
  validates it (`GET /v3/auth/tokens`) → proves *"Nova called."*
- **Access:** the human presents **their own** Keystone token; Geneza validates it
  → the user's identity / project / roles.

Because trust = "a valid token from a configured Keystone," **there is no domain
whitelist** — the trust boundary is *which Keystone(s) Geneza validates against*
(the **clouds registry**, §7). Per-domain federation / IdP choice is the cloud's
concern, not Geneza's. (This replaced the earlier domain-keyed default-deny
registry: with token validation as the guard, the domain is no longer the trust
gate.)

**Tenancy maps at the PROJECT, not the domain.** Project IDs are globally unique
UUIDs *within a Keystone*, so `project-id` — already present in the vendordata body
and in a user's token — is the mapping key directly; **the domain is not needed for
the mapping** (it drops to naming/labels only, §5). The remaining authorization
question ("*which* workspace?") is answered by per-project **bindings** + per-project
**isolation** (§6), not by a whitelist.

| OpenStack | Geneza |
|---|---|
| **Project** (UUID, scoped to a Keystone) | **a binding onto a workspace** — a workspace may bind many projects (§6) |
| **Cloud / Keystone** | a **clouds-registry** entry (`service-uid`); the trust boundary (which token issuer Geneza validates) (§7) |

---

## 3. Reality check: OpenStack does NOT sign metadata

Unlike AWS (signed Instance Identity Document + published region cert) or GCP/Azure
(signed identity JWT / attested document), **vanilla Nova metadata is unsigned
plaintext.** There is **no cloud public key**, no offline-verifiable instance
identity. So the trust anchor is **not a signature** — it is:

- **The authenticated `vendordata` call** (Nova attaches its Keystone service
  token — Geneza validates it → "Nova called me"), plus
- **A gateway→Keystone/Nova callback** (resolve/verify the instance's project,
  optionally confirm it is `ACTIVE`).

This is the courier/callback model, not the SPIFFE/attestation model AWS allows.

---

## 4. Validated facts (live, kolla1 / Nova 2026.1)

**Nova's dynamic-vendordata request** (captured from a real boot):

```
POST <target-url>                          # exactly the configured vendordata_dynamic_targets URL
Host: <host:port>
User-Agent: openstack-nova-vendordata      # distinctive — secondary "is this Nova?" signal
Content-Type: application/json
Accept: application/json
X-Auth-Token: gAAAAAB…                      # Nova's SERVICE Keystone token (Fernet)
Content-Length: …

{ "project-id":  "<instance's project UUID>",
  "instance-id": "<instance UUID>",
  "image-id":    "<image UUID>",
  "user-data":   <raw user-data or null>,
  "hostname":    "<instance hostname>",
  "metadata":    { <instance key/value metadata> },
  "boot-roles":  "reader,member,admin,…" }   # COMMA-SEPARATED STRING (not an array)
```

Confirmed against Keystone:
- **`X-Auth-Token` validates** (`GET /v3/auth/tokens` → 200): caller = `nova`,
  project = `service`, domain = `Default`, roles include `admin`/`reader`, 24h TTL.
- **The same token can `GET /v3/projects/<id>` → `domain_id`** (200) — so in kolla
  Geneza needs **no separate Keystone cred**; it reuses the presented token.

**Behavioral gotchas that change the design:**
1. **Nova hits the endpoint ~5× per instance build** (all within milliseconds).
   The endpoint **MUST be idempotent** — dedupe on `instance-id` and mint **one**
   token, or you cut 5 join tokens per VM.
2. **Which Nova service calls it depends on the metadata path:**
   - **config-drive** → generated by **`nova-compute`** at build (put the config
     in nova-compute). Required when the network metadata path is unreachable.
   - **network metadata** (`169.254.169.254`) → served by **`nova-metadata`**
     (needs DHCP isolated-metadata or a router; absent on a `--no-dhcp` provider
     net). On the kolla1 all-in-one we used **config-drive + nova-compute**.
3. **cloud-init nesting trap:** Nova wraps each target's response under the target
   **name** in `vendor_data2.json`. Stock cloud-init only runs a **top-level**
   `cloud-init` key — so the Nova target MUST be named `cloud-init`
   (`vendordata_dynamic_targets = cloud-init@http://…`), making the file
   `{"cloud-init": "#cloud-config…"}`. Then **no forked cloud-init / custom image**
   is needed.

---

## 5. Identity resolution (project is the key; domain is not)

The mapping key is the **`project-id`** — already present, no lookup needed for the
decision itself:

- **Enrollment:** `project-id` from the vendordata **body**.
- **Access:** `project.id` from the user's validated token body.

`GET /v3/projects/{project-id}` is **optional**, used only to fetch the human
**project name** (to slug an auto-provisioned workspace, §6) and labels — NOT as a
trust gate. The domain is no longer load-bearing for mapping.

> **Trap (we hit this live):** do NOT read the *instance's* identity off the
> *courier* token. On enrollment the `X-Auth-Token` is **Nova's** (project=
> `service`), so its `project`/`domain` are the caller's, not the instance's — they
> coincidentally match in a single-domain cloud and mislead. The instance's
> `project-id` is in the request **body**. (On the access plane the token *is* the
> user's own, so its `project` is correct there.)

---

## 6. Workspace model & bindings (the hub)

**The workspace is the hub; everything else binds onto it.** A workspace has its
**own** stable identity (`slug` + `uuid`) that is independent of any cloud, IdP, or
project. It is *not* "a project's shadow" — projects, IdP groups, and direct
invites are all **bindings** that point at a workspace. This is what lets the same
workspace be reachable from OpenStack VMs *and* a NAT'd laptop *and* a future AWS
account at once.

**Bindings are cloud-qualified.** A binding is a typed, namespaced reference:

```
openstack:project:<service-uid>:<project-uuid>     # an OpenStack project under a specific Keystone
idp:group:<realm>:<group>                          # an OIDC/Keycloak group (the laptop's path)
invite:<email-or-token>                            # a direct human invite
aws:account:<account-id>                           # future (§14)
```

The `<service-uid>` qualifier on the OpenStack binding is **load-bearing**: project
UUIDs are unique only *within* a Keystone, so the bare UUID is ambiguous across
clouds. Qualifying by `service-uid` (the clouds-registry key, §7) makes the binding
globally unique and routes validation to the right Keystone. Two different clouds
with a colliding project UUID map to two different workspaces — never collide.

**One binding serves BOTH planes.** The binding
`openstack:project:<svc>:<proj>` answers enrollment (a VM's `project-id` from the
vendordata body → its workspace) *and* access (a human's token `project.id` → the
same workspace). No separate config; the VM and the project's users land in the
same place by construction.

**Cross-source membership.** Because the hub is the workspace (not the project),
add `idp:group:geneza:eng` to the *same* workspace and the engineer's laptop
(joining via OIDC) shares the overlay + in-network DNS with the project's VMs. A
workspace can carry any mix of bindings.

### Auto-provision (per-project isolation makes whitelist-free safe)

When an enrolling VM's `(service-uid, project-uuid)` has **no** binding, the cloud's
registry entry (§7) chooses:

- `auto_provision: true` (PoC default): Geneza **creates** a workspace
  `slug = <project-name>-<short-project-uuid>` (project name via the optional
  `/v3/projects/{id}`, §5; falls back to the UUID), records the binding
  `openstack:project:<svc>:<proj>`, and enrolls the VM into it. Audited as an
  auto-provision event.
- `auto_provision: false` (production default): the VM lands **PENDING /
  "unbound project"** in the console — surfaced, never silently misrouted —
  awaiting an operator binding (§9).

**Why auto-provision is safe without a whitelist** (this is the crux of dropping
the old default-deny registry):
1. The **token is validated against a configured Keystone** — the trust boundary
   is the clouds registry, so only projects on a Keystone the operator already
   trusts can reach this path at all.
2. **Each project gets its OWN isolated workspace.** A project Geneza has never
   seen can only ever provision and reach *its own* fresh workspace — never another
   tenant's. Auto-provision cannot cross tenants because the binding it creates is
   keyed by the exact `(service-uid, project-uuid)` the validated call carried.

An auto-provisioned workspace starts with only the project binding; an operator (or
the platform-admin API, §9) can add `idp:group` / `invite` bindings later, or
**pre-create** the workspace with all bindings *before* any VM boots so production
runs with `auto_provision: false` and still onboards seamlessly.

---

## 7. Clouds registry & multi-Keystone routing

Geneza validates against **many** Keystones. The clouds registry is the trust
boundary — each entry is one cloud, keyed by an operator-chosen **`service-uid`**:
a **stable slug** Geneza owns (e.g. `kolla1`, `prod-fra`).

> **The `service-uid` is NOT the Keystone FQDN.** The FQDN can change (DNS
> migration, re-IP, new region endpoint) — and it lives in the *mutable*
> `keystone_url` field, which an operator can update in place. The slug is the
> **stable, never-rekeyed identity** of the cloud: every binding is qualified by it
> (`openstack:project:<service-uid>:<project-uuid>`), so if the slug moved with the
> FQDN, every binding would break on a Keystone rename. Keying by a slug decouples
> the binding graph from infra DNS.

```yaml
geneza:
  clouds:
    kolla1:                              # <service-uid>
      kind: openstack
      keystone_url: http://<internal-vip>:5000/v3
      # Geneza's own reader cred — FALLBACK for hardened clouds where the Nova
      # token cannot read projects; in kolla the presented Nova token suffices.
      reader_creds: { username, password, project_name, user_domain_id, project_domain_id }
      require_nova_service_token: true   # caller must be user=nova / project=service
      auto_provision: true               # PoC; prod: false (operator pre-binds, §9)
      default_labels: { env: lab, cloud: kolla1 }
      role_map: { admin: ws-admin, member: ws-user, reader: ws-viewer }   # §8
    prod-fra:
      kind: openstack
      keystone_url: https://identity.fra.example.com/v3
      require_nova_service_token: true
      auto_provision: false
```

**The service-uid lives in the vendordata path suffix.** Each cloud's Nova is
configured to call a per-cloud URL:

```
vendordata_dynamic_targets = cloud-init@https://<geneza>/openstack/vendordata/<service-uid>
```

The suffix tells Geneza **which registry entry** to use → **which Keystone** to
validate the presented token against → which `service-uid` to qualify the binding
with.

> **The suffix is a ROUTING key, not an auth grant.** It selects a Keystone; it
> grants nothing. A forged or wrong `service-uid` either (a) matches no registry
> entry → **404**, or (b) routes to a cloud whose Keystone the presented token does
> **not** validate against → **401**. Auth comes entirely from token validation
> against the *selected* Keystone, so steering the router to the wrong cloud only
> makes the call fail. (An attacker who could forge a *valid token for the targeted
> Keystone* would already be inside that cloud's trust boundary — the routing
> suffix adds no exposure.)

This also fixes the cross-cloud project-UUID ambiguity: the binding written is
`openstack:project:<service-uid>:<project-uuid>`, unique per cloud (§6).

---

## 8. Role & group mapping (OpenStack roles → Geneza policy)

Geneza's connection authorization runs through `policy.Input{User, Roles, Workspace,
NodeLabels, …}`. OpenStack identity feeds it on **both** planes, but they map to
**different** fields — and carry **different** trust weight:

**Access plane — Keystone roles → policy roles/groups (a GRANT).** The user's
validated token carries `roles[]` scoped to *their* project. The cloud's
`role_map` (§7) translates them into Geneza policy roles/groups, which become
`policy.Input.Roles` for web-shell / CLI authorization:

```
member → ws-user      admin → ws-admin      reader → ws-viewer
```

A default map ships; operators override per cloud (or per binding). These are real
grants because the token is the user's own, project-scoped credential.

**Enrollment plane — boot-roles / instance metadata → node LABELS (a HINT, not a
grant).** The vendordata body's `boot-roles` (comma-separated, §4) are the roles of
the *user who launched the VM*, and instance `metadata` is tenant-set — both are
**advisory**. They map to **node labels** (`policy.Input.NodeLabels`), never to
grants:

```
boot-roles "admin,member"        → node labels  os-role:admin, os-role:member
metadata   geneza.role=db        → node label   role:db
metadata   geneza.labels=a,b     → node labels  a, b
```

Labels shape *who may connect to this node* via policy (e.g. "only `ws-admin` may
SSH a node labeled `role:db`); they never elevate the node itself. This keeps the
typo-prone, tenant-mutable inputs (tags, boot-roles) firmly on the **labels** side
of the line and the validated, project-scoped token on the **grants** side.

The role/label maps are part of the cloud registry (operator config) or the
binding (platform-admin API, §9), so a tenant can never invent a role name that
becomes a Geneza grant.

---

## 9. Platform-admin API & keys

Auto-provision (§6) is the *zero-touch* path; the platform-admin API is the
*operator-driven, ahead-of-time* path. It lets an operator **pre-create workspaces,
bindings, and clouds** so production can run with `auto_provision: false` and still
onboard the first VM of a project seamlessly.

**A distinct credential class — separate trust root from Keystone tokens.** A
Keystone token proves "a *tenant* user"; it must **never** be able to create
cross-tenant bindings or register clouds (that would be privilege escalation across
the tenancy boundary). Platform-admin authority is **cloud-operator-scoped — above
any single tenant** — and authenticates with **platform-admin keys/certs**, not
tokens:

- Reuses the existing admin **mTLS** API surface + cert class (the breakglass
  `--profile admin` path) with a dedicated `platform-admin` role.
- Keys/certs are issued **out-of-band**, **rotatable**, and **every call is
  audited**. They are the *only* credential that can mutate the hub graph
  (workspaces, bindings, clouds, role maps).

**Capabilities** (the same operations auto-provision performs, but operator-driven):

```
geneza platform-admin cloud register <service-uid> --kind openstack \
        --keystone-url … [--reader-creds …] [--auto-provision=false]
geneza platform-admin workspace create <slug>
geneza platform-admin workspace <slug> bind   openstack:project:<svc>:<proj>
geneza platform-admin workspace <slug> bind   idp:group:<realm>:<group>
geneza platform-admin workspace <slug> bind   invite:<email>
geneza platform-admin workspace <slug> unbind <binding>
geneza platform-admin role-map set <service-uid> member=ws-user admin=ws-admin …
geneza platform-admin workspace <slug> bindings|audit
```

`bind openstack:project:…` is validated against the named cloud's Keystone at bind
time (the project must exist), recorded, and audited — the same validation
auto-provision does, just earlier. With workspaces + bindings pre-created, an
enrolling VM whose project is already bound enrolls straight into the right
workspace with `auto_provision: false`.

---

## 10. Geneza vendordata endpoint (the contract)

A plain-HTTP listener (`gateway.yaml: vendordata_listen: ":7407"`), reachable from
Nova; PoC uses HTTP (no CA trust needed), productize to mTLS / Nova-source
allowlist. `POST /openstack/vendordata/<service-uid>`:

```
1. ROUTE: look up <service-uid> in the clouds registry (§7). Unknown → 404, log.
2. AUTH: read X-Auth-Token; validate via THAT cloud's Keystone GET /v3/auth/tokens.
   If require_nova_service_token: require caller = nova / project = service;
   optionally also require User-Agent: openstack-nova-vendordata.   → else 401, log.
   (A forged service-uid that routes here fails this step — routing ≠ auth, §7.)
3. PARSE body (hyphenated keys). project-id from the BODY (NOT the token, §5).
   project name/domain := optional GET /v3/projects/{project-id} (naming/labels).
4. BIND/PROVISION: look up binding openstack:project:<svc>:<project-id> (§6).
     - bound     → that workspace.
     - unbound + auto_provision=true  → create workspace <name>-<short-uuid>, bind, audit.
     - unbound + auto_provision=false → surface PENDING "unbound project", return {}.
5. IDEMPOTENCY (Nova hits ~5×): dedupe on instance-id. If a token was already
   minted for this instance-id (and no live node/cert yet), RETURN THE SAME ONE.
   Single-node-per-UUID anti-replay (refuse a 2nd live node for a UUID unless its
   cert expired = rebuild).
6. LABELS: derive node labels from default_labels + boot-roles + instance metadata
   (§8) — labels only, never grants.
7. MINT a bounded join token via the existing tokenProvider: workspace-scoped,
   short TTL (~1h, covers boot), the derived labels, auto_approve per registry.
8. (defense-in-depth, optional) GET /v3/servers/{instance-id} → require ACTIVE in
   that project before minting.
9. RETURN: {"cloud-init": "#cloud-config\n" + render(cloud-init template)}
   with @PROVIDER@=token, @JOIN_TOKEN@=<minted>, @GATEWAY_HOST@=<public FQDN>,
   pinned artifact.pub fingerprint.
```

---

## 11. Geneza OpenStack client (gophercloud)

`internal/gateway/openstack.go`, `go get github.com/gophercloud/gophercloud/v2`.
Per-cloud client, selected by `service-uid`:
- `ValidateToken(ctx, svcUID, token) → (user, project, roles, ok)` (Keystone token
  validate against that cloud).
- `ResolveProjectDomain(ctx, svcUID, projectID) → (domainID, name)` (identity v3
  `projects.Get`), using the **presented Nova token** (kolla) or `reader_creds`
  (fallback).
- `GetServerStatus(ctx, svcUID, instanceID) → status` (optional ACTIVE check).

---

## 12. Agent / cloud-init side

**No forked cloud-init, no custom image for the PoC.** Stock Ubuntu 24.04 cloud
image. The vendordata endpoint returns a `#cloud-config` (under the `cloud-init`
target name, §4.3) that installs + enrolls Geneza:

```yaml
#cloud-config
runcmd:
  - curl -fsSL https://<gateway>/install.sh | sh -s -- --token <minted> --provider token
  - systemctl enable --now geneza-bootstrap
```

The bootstrap is root-pinned (TUF-lite) and pulls the signed worker. Set the
target workspace/role via OpenStack: `--property geneza.workspace=…` (and bind the
project, §6/§9). **Productization follow-up:** a native `cc_geneza` cloud-init
module (idempotent, status reporting, no token in plaintext) + a baked Glance image.

Note: the join token in vendordata is a bearer secret in the metadata/config-drive
— bounded TTL + single-use + admission gate limit blast radius; the productized
path can switch to the `openstack-metadata` provider where the **agent** sends its
instance identity and the gateway re-verifies, removing the token from metadata.

---

## 13. Access plane (Keystone-token auth) — design

For humans already authenticated to OpenStack to drive Geneza without a separate
login: Geneza accepts a **Keystone token** as a bearer credential.

- **Web shell (browser):** the dashboard passes the user's Keystone token to the
  Geneza API; Geneza validates it (`GET /v3/auth/tokens`) against the cloud, derives
  user / project / roles → maps to workspace (project binding, §6) + policy roles
  (role map, §8), then brokers the existing `client_path=web` shell (Noise tunnel +
  PTY over WebSocket). Embed via `CSP: frame-ancestors <dashboard-origin>`.
  > Unlike enrollment, here the bearer token is the **user's own**, scoped to
  > *their* project — so `project` + `project.domain` + `roles` come straight from
  > the validation body; **no extra `/v3/projects/{id}` call** is needed on this
  > plane.
- **CLI:** `geneza` uses a Keystone token (`OS_TOKEN`) the same way.

Trust anchor = **Keystone** (per the chosen direction), uniform for API + CLI.
Policy + the agent's independent grant re-verify still bound everything; the
dashboard/CLI is a presenter, never an authority.

---

## 14. Multi-cloud generalization (forward-looking)

The integration splits into a per-cloud **verifier** + a common pipeline (clouds
registry + workspace bind + admission + token mint). Geneza's existing
`EnrollProvider` interface is the seam — one provider per cloud kind; the clouds
registry (§7) already supports `kind:`:

- **Class A (signed identity, offline-verifiable):** AWS (Instance Identity
  Document), GCP (identity JWT), Azure (attested doc) → verify the signature; no
  callback; Geneza federates the cloud's keys like an IdP. *Easier than OpenStack.*
- **Class B (no signed identity → callback/courier):** OpenStack, DigitalOcean,
  Vultr, Hetzner → authenticate the courier + callback the cloud API to verify the
  instance. *OpenStack is this class — the hardest case, so it de-risks the rest.*

Tenancy maps uniformly through cloud-qualified bindings (§6): AWS account / GCP
project / Azure subscription / OpenStack project → a workspace, keyed by
`<kind>:<scope>:<service-uid>:<id>`.

---

## 15. Security analysis

Adversarial multi-agent audit (6 attack lenses → per-finding verification against the
spec text → synthesis): 46 candidate findings, **43 verified** as real or partially
mitigated gaps, 2 judged already-mitigated. The single highest-leverage fix is
**#1** below — it is the precondition the §6 "auto-provision is safe without a
whitelist" proof silently assumes, and fixing it collapses #1/#4/#14/#22/#23 and
half of #21 at once.

### Trust model & assumptions

The security of this integration rests on a small set of load-bearing assumptions.
Where any of these does not hold, the residual risks below follow.

- **The only auth anchor is Keystone-token validation against a configured *clouds registry* (§2, §7).** There is no domain whitelist and — critically — **no cryptographic proof of the metadata's origin**: vanilla Nova metadata is unsigned plaintext (§3, "there is no cloud public key"). The whole model is courier+callback: "Nova called" is proven by the service token; "this instance is really in project X" is proven only if the gateway *makes the callback*.
- **Two credential planes share one trust root but are asymmetrically hardened.** Enrollment carries Nova's long-lived (24h) cluster-wide *service* token (§4); access carries a human's *own* token (§13). The spec assumes — but does not enforce — that each plane only ever sees its intended token class and scope.
- **Per-(service-uid, project-uuid) isolation is the substitute for a whitelist (§6).** This holds *only if* (a) the body's `project-id` is authoritative, (b) `require_nova_service_token` is on, and (c) each `service-uid` maps to a distinct Keystone trust root. The spec's auto-provision safety proof silently depends on all three.
- **"Trust is the signature, never the channel" for binaries (§12).** This holds for the *worker* the bootstrap pulls (TUF-lite), but assumes the stage-1 bootstrap/agent themselves, and the root pin that anchors them, arrive intact — which on the zero-touch OpenStack path they do not.
- **Labels are advisory hints, grants come only from validated tokens (§8).** This is a *convention enforced at the mapping step*, not a structural property of the policy engine.

### Threats the design already handles

- **Wrong/forged routing suffix → no exposure (§7):** a `service-uid` that matches no entry returns 404; one that routes to a Keystone the token doesn't validate against returns 401. Routing is correctly separated from auth — *provided each suffix maps to a distinct Keystone* (see residual #18).
- **User-Agent spoofing as a Nova signal (§4, §10 step 2):** UA is explicitly "secondary"/"optionally also" and is *additive* on top of the unconditional `GET /v3/auth/tokens` validation. It never substitutes for token validation; a spoofed UA with no valid token still 401s.
- **Tenant inventing a privilege-granting role name (§8):** role/label maps live in operator config (registry) or the platform-admin binding, so a tenant-supplied role *string* cannot reach the grants field — "a tenant can never invent a role name that becomes a Geneza grant."
- **Cross-tenant *workspace access* via auto-provision (§6):** each unbound project gets its *own* isolated fresh workspace, keyed by the exact `(service-uid, project-uuid)` of the validated call — *so long as that key is authoritative* (residual #1).
- **Cross-cloud project-UUID collision (§6, §7):** `service-uid`-qualified bindings make UUIDs that collide across *genuinely distinct* Keystones map to distinct workspaces.
- **Artifact *forgery* over a hostile channel (§12, TUF-lite):** a compromised/MITM gateway "can serve stale-or-junk bytes but cannot forge an artifact the root never authorized"; anti-rollback floor closes the downgrade window.
- **Dashboard/CLI as a presenter, not an authority (§13):** the agent's independent grant re-verify still bounds connections, so a compromised presenter cannot itself authorize access.
- **Break-glass / platform-admin as a separate credential class (§9):** hub-graph mutation is reserved to mTLS certs above any single tenant — a Keystone token cannot register clouds or create cross-tenant bindings *as designed* (the gaps are in enforcement detail, residuals #11–#13).

### Residual risks & recommendations

Ranked by severity; duplicates across review lenses are merged.

| # | Sev | Risk (one line) | Recommendation | Spec |
|---|-----|------------------|----------------|------|
| 1 | **Critical** | **Confused-deputy enrollment:** `project-id` is taken from the courier *body* and used directly as the binding key, while AUTH only proves "Nova called" — never that the instance is in that project. A holder/replayer of the cluster-wide Nova service token can POST `{project-id: <victim>, instance-id: <attacker>}` and enroll into any project's workspace — falsifying the §6 "cannot cross tenants" claim, whose key is attacker-supplied. | Make `GET /v3/servers/{instance-id}` **mandatory & authoritative**: read `tenant_id` from Nova's server record and **discard the body `project-id`**; reject if the instance is absent. Never let the body be the trust input. | §5, §10 steps 3-4-8 |
| 2 | **Critical** | **Unverified stage-1 binaries (supply chain):** `install.sh` fetches `geneza-bootstrap`/`geneza-agent` and `chmod +x`/execs them with **no signature/hash check**. Only `root.pub` is pinned — a trojaned bootstrap ignores it; the TUF-lite chain never sees the verifier. Unattended root at every boot ⇒ fleet-wide RCE. | Pin & verify stage-1 binaries: emit `--bootstrap-sha256`/`--agent-sha256` (or a `root.pub`-signed manifest) and `die` on mismatch *before* `chmod`/exec. Treat the channel as hostile. | §10 (RETURN), §12 |
| 3 | **High** | **Plaintext, replayable courier token:** the endpoint is plain HTTP (§10/§17) carrying Nova's 24h cluster-wide service token. On the routed fabric an on-path host harvests it; with #1/#5 it mints join tokens for arbitrary projects, and (#9) doubles as access-plane admin. Tampering the returned `#cloud-config` is itself RCE. | Make **server-auth TLS (mTLS preferred)** a *hard requirement* — not a follow-up. Bind the token to the client cert; bind the listener to the mgmt interface + Nova source-IP allowlist. Never return executable cloud-init over cleartext. | §4, §10, §17 |
| 4 | **High** | **`require_nova_service_token` optional + body project-id never cross-checked.** Unset/false on any cloud ⇒ *any* valid tenant token enrolls a node into an attacker-named project (compounds #1). It's `true` only in *example* config, not an invariant. | Make it **default-true, non-overridable** for `kind:openstack`. Non-service caller ⇒ **reject**, never fall through to a body-asserted project. (Closes the §6 isolation precondition; combine with #1.) | §10 step 2, §7, §5 |
| 5 | **High** | **Join token = plaintext bearer in config-drive/metadata, not bound to the instance.** Readable by any VM root process, a snapshot/captured image, or an on-path MITM; the holder enrolls a rogue node, first-to-claim wins. | Prioritize the `openstack-metadata` provider (agent sends identity, gateway re-verifies — removes the bearer). Until then **bind the token to the verified instance-id**; minimal TTL. | §10 steps 7-9, §12 |
| 6 | **High** | **No leaf-cert revocation:** "rotatable" re-keys the signer but there's **no CRL/OCSP/serial-denylist** — a leaked platform-admin/break-glass cert is usable for its full TTL with only a fleet-wide CA re-key as kill switch. The most powerful credential has no revocation path. | Add an enforced revocation path *before shipping platform-admin*: revoked-serial set checked in `authorize()` on every mTLS RPC, `cert revoke <serial>`, ≤1h TTLs, off-box-mirrored revocations, per-operator intermediate CAs. | §9 |
| 7 | **High** | **"Labels never grant" is unenforced** — pure convention. `policy.Input.NodeLabels` is just a field; tenants control label *content* (`geneza.labels=`, `geneza.role=`). Any rule reading NodeLabels on the *initiator/egress* side turns a tenant-set label into authority. | Make it **structural**: route tenant/node-derived labels into a field allowed only on connection-*target* clauses; forbid (at parse/compile time) referencing node-self labels in grant/initiator positions; ship a linter. A node's own labels MUST be ignored when it is the initiator. | §8, §6, §13 |
| 8 | **High** | **Rebuild = cert-expiry conflation:** the anti-replay exception "unless its cert expired = rebuild" treats a passive, attacker-reachable condition (just wait for expiry) as proof of rebuild ⇒ at each rotation boundary a new live node claims the UUID with no check the original is gone (identity takeover). | Don't infer rebuild from expiry. On a 2nd node for a UUID require a fresh Nova-courier call **plus** a `GET /v3/servers/{id}` ACTIVE callback with a changed launched/updated timestamp; retire the prior cert in the transition. | §10 step 5 |
| 9 | **Medium** | **Access plane accepts the Nova service token:** §13 validates "any" token with no guard symmetric to enrollment. A captured service token (which the design intentionally broadcasts) maps `admin→ws-admin` ⇒ ws-admin web-shell/CLI for 24h where `service` is bound. | On the access plane **reject service-account tokens** (project=service / user=nova / service role); make acceptance an allowlist of token *types*. Mirror enrollment's guard. | §13, §2, §8 |
| 10 | **Medium** | **Access plane assumes project-scoped tokens:** §13 reads `project/roles` without requiring `token.project`. Unscoped ⇒ missing `project.id` (fail-open/NPE); domain-scoped ⇒ *domain* roles feed the map. Scope is never asserted. | Require project-scoped tokens: reject unscoped/domain/system-scoped (or define handling); assert `token.project.id` present + matching the bound project. State the required scope in `ValidateToken` (§11). | §13, §8, §11 |
| 11 | **Medium** | **Tenant→platform-admin escalation surface:** §9 mandates a dedicated role but proposes reusing a gate on bare `admin` with no workspace check, and the token→cert mint has no reserved-role denylist ⇒ a misconfigured role_map declaring `admin` mints a passing cert. | `platform-admin` strictly distinct from `admin`; gate hub-mutation RPCs on `hasRole("platform-admin") AND ident.Workspace=="" AND non-token provider`; hard-deny `admin`/`platform-admin` as role-map/cert-mint outputs regardless of config. | §9, §8 |
| 12 | **Medium** | **Break-glass cert reused as routine platform-admin cred:** the break-glass issuer mints 12h certs with arbitrary roles **out-of-band from the audit chain** (offline CLI) ⇒ a platform-admin cert can exist with no record until first use ("every *call* is audited", issuance is not). | Keep break-glass separate + alarm-raising: ≤1h TTL, distinct role, **issuance written to the audit chain + off-box sink before emit** (ideally two-operator). Routine platform-admin = its own ceremony; record serial at issuance. | §9 |
| 13 | **Medium** | **Audit defeatable by the same host compromise that mints the cred:** the audit HMAC key sits beside the CA signing key; the off-box sink is optional (`nopSink` default). A host-root attacker who forges a cert can rewrite the local chain self-consistently. | Make the off-box append-only sink **mandatory + fail-closed** for all platform-admin/break-glass ops; store audit key and CA key on different trust boundaries (HSM/KMS for the CA). | §9 |
| 14 | **Medium** | **Auto-provision = de-facto platform-admin via a service token:** it performs two "platform-admin-only" mutations (create workspace + write binding) driven solely by a validated Nova token; same-tenant safety rests entirely on #4 + #1. | Treat auto-provision as a *constrained* platform-admin capability: same mandatory off-box audit (#13) + per-cloud rate/quota cap; make the `/v3/servers` ACTIVE-in-project check **required** (closes via #1). | §6, §7, §9, §10 |
| 15 | **Medium** | **Idempotency mint is non-atomic check-then-act:** §10 step 5 dedupes "on instance-id" with no atomic primitive, under ~5× near-simultaneous hits ⇒ up to 5 join tokens per VM (the exact failure the spec set out to prevent). | Make mint-per-instance atomic: single-flight/mutex on `(service-uid, instance-id)` or a DB unique constraint (`INSERT … ON CONFLICT RETURNING`); reserve the slot at mint; single-node-per-UUID as a unique-active-cert constraint. | §4 gotcha 1, §10 step 5 |
| 16 | **Medium** | **No revocation re-check; sessions outlive Keystone revocation:** access-plane shells are brokered after one point-in-time validation; a user disabled in OpenStack keeps the live PTY + minted token until Geneza TTL lapses. | Cap join-token TTL by the token's `expires_at`; periodically re-validate or consume Keystone revocation events and tear down the session. Make revocation propagation a §11 contract item. | §10, §13, §11 |
| 17 | **Medium** | **No lifecycle teardown on instance deletion:** dedupe state + node certs are never invalidated when a VM is deleted ⇒ a ghost node lingers in overlay/DNS with the dead VM's labels; an outstanding token + config-drive snapshot stays redeemable. | Reconcile via Nova delete-notification or periodic `GET /v3/servers/{id}`: on DELETED/missing, revoke tokens, retire the cert, remove from overlay/DNS. Make the ACTIVE callback mandatory at enroll. | §10 steps 5 & 8, §12 |
| 18 | **Medium** | **Shared/federated Keystone breaks routing≠auth + per-cloud uniqueness:** nothing enforces 1:1 `service-uid`↔Keystone (§14 even cites one identity service fronting two regions) ⇒ the §7 "401 on wrong suffix" guarantee fails and a token-holder *chooses* which namespace to write a binding into. | After validating, verify the token's *issuer* matches the routed `service-uid`'s pinned Keystone identity (issuer URL + TLS/CA), not just "validates against the URL"; forbid two entries sharing a `keystone_url` (reject at registry load). | §6, §7, §10 |
| 19 | **Medium** | **Node fully controls its own DNS name, no uniqueness/authorization check:** in a multi-source workspace (§6 co-locates VMs + laptops) a node can name itself `geneza-laptop`/`db-prod`; the pushed record poisons co-members' bare-name resolution (last-writer wins). The broker `geneza ssh` path fails closed; bare-name resolution does not. | Make the name server-authoritative: derive it from the validated instance-id/project (or admin-assigned); enforce per-workspace uniqueness (reject/suffix on collision); namespace by binding source; audit changes. The naming analogue of §8's label discipline. | §6, §8, §1 |
| 20 | **Medium** | **Tenant label namespace collides with operator policy labels:** `geneza.labels=`/`geneza.role=` map verbatim into the same flat namespace as `default_labels`/role_map outputs, no reserved prefix ⇒ a tenant mints a node wearing `env:prod`/`role:db`. | Reserve an operator-only namespace; force tenant labels into a fixed `tenant:`/`unverified:` prefix the pipeline can't escape; strip/reject tenant labels targeting reserved prefixes; require label-keyed policy to be workspace-scoped. | §8, §7, §10 step 6 |
| 21 | **Medium** | **Default role_map grants interactive access to every project member:** the shipped default maps `member → ws-user` (the role *every* project user holds) with no opt-in — and with PoC `auto_provision: true` a never-seen project auto-grants every member ws-user, zero operator action. | Default least-privilege: ship an empty/viewer-only map; require opt-in for `member`/`admin`. Document that `member` granting interactive access is a deliberate, surfaced choice. (Blast radius bounded to the project's own workspace.) | §8, §7, §13 |
| 22 | **Low** | **Anti-replay state keyed by bare `instance-id`, not `(service-uid, instance-id)`** — the one place the spec drops the qualifier it enforces everywhere else ⇒ a cloud-B service-token holder submits cloud-A's UUID for a cross-cloud DoS on A's enrollment slot. | Key all dedupe/anti-replay/idempotency state by `(service-uid, project-id, instance-id)`; bind the idempotent return to the same courier + verified instance→project (with #1). | §10 step 5 |
| 23 | **Low** | **Auto-provision flood + binding squat:** with `auto_provision: true` + #1 a courier iterates arbitrary `project-id`s to mint unbounded workspaces (no quota) and pre-claims a not-yet-bound project so a later operator bind collides. | Gate auto-provision behind the mandatory instance→project check (#1); per-cloud creation rate limits/quotas; precedence rule — operator pre-binds win, auto bindings provisional + reconcilable. | §6, §9 |
| 24 | **Low** | **Platform-admin `bind` validates existence, not uniqueness:** nothing forbids binding the same project into multiple workspaces ⇒ non-deterministic resolution (operator footgun, not tenant-reachable). | Enforce one project → at most one resolving workspace; on `bind` reject/`--force` if already bound; reconcile against a prior auto-provisioned binding. | §6, §9, §10 step 4 |
| 25 | **Low** | **Stale bindings outlive deleted projects (TOFU):** `bind` validates only at bind time; enrollment falls back to the cached binding on 404. (UUID non-reuse defuses cross-tenant leak; residual = orphaned bindings + fail-open + risk for future Class-B clouds.) | Periodically re-validate active project bindings; fail closed on 404 during enrollment; wire project-delete → unbind or document a runbook. | §9, §6 |
| 26 | **Low** | **No out-of-band root-pin provenance on the OpenStack path:** §12 invokes `install.sh` without `--root-fp`, and any fingerprint would ride the **unsigned** vendordata response (TOFU against an unauthenticated source); a MITM substitutes its own root key. (Also §10's "pinned **artifact.pub**" is the wrong key — `install.sh` pins the *root* key.) | Deliver the root pin via an independent channel (baked into the Glance image, or platform-admin-controlled validated metadata); make `--root-fp` mandatory; pass the *root* key in the template. | §12, §3, §10 |
| 27 | **Low** | **Misleading `os-role:admin` label name:** `boot-roles` (the launcher's unverified roles) map to an authoritative-*sounding* label any project-admin can mint, inviting grant-shaped policy. Grant-path is closed (§8); the naming is the residual. | Prefix tenant-derived role labels into an explicitly-untrusted namespace (`claimed-os-role:`/`tenant:`); spec warning that `os-role:*` reflects the launcher's unverified roles and MUST NOT gate anything outside the node's own workspace. | §8, §4 |
| 28 | **Low** | **Per-binding role_map provenance not pinned:** auto-provisioned (tenant-triggered) bindings inherit the possibly-permissive cloud default with no floor/marker; an operator typo (`member: ws-admin`) silently over-grants every project on that cloud. | Apply a least-privilege floor to auto-provisioned bindings regardless of cloud default; mark them tenant-originated in audit; validate `role-map set` against a known-role allowlist + warn on low→high mappings. | §8, §6, §9 |
| 29 | **Low (doc)** | **"Labels never elevate" overstated:** selectors are bidirectional — a tenant-set label can pull a node *into* a reachability/exposure/DNS group even though the node's own *authority* is protected. | Tighten the language: tenant labels MUST only *narrow inbound* access and MUST NOT be selectors that add the node to reachability/egress/exposure groups (enforce via #7/#20). | §8, §6, §13 |
| 30 | **Info** | **Hostile/MITM gateway can serve stale-or-junk bytes (boot-availability DoS):** forgery is prevented (TUF-lite) but a degraded channel stalls onboarding; bounded token TTL turns a transient fault into failed enrollment. Largely bounded by idempotent re-serve + persistent config-drive. | Make bootstrap idempotently retriable across reboots/token-refresh; authenticate `/v1/updates/desired` to the node cert; alert on stuck-PENDING nodes. | update-trust, §10, §16 |
| 31 | **Info** | **Audit *content* for hub-graph mutations unspecified:** "every call is audited" mandates the fact, not required fields (service-uid, binding target, role-map before/after) ⇒ a malicious change is detectable but not reconstructable. | Specify required detail fields per verb (cloud register / bind / role-map set / auto-provision); always record actor cert serial; test emission + off-box mirror + chain-verify. | §9 |
| 32 | **Low** | **`reader_creds` secret handling unspecified:** a standing long-lived Keystone user/password shown inline in on-disk YAML, runtime-mutable via the platform-admin API, no at-rest protection/rotation/redaction. (Optional fallback, unused on the kolla path.) | Store in a secrets backend / `0600` handle, never inline where audit/list echoes it; redact from logs; prefer application credentials; gate registration on `platform-admin` + operator-workspace scope. | §7, §9, §11 |

### Hardening backlog

**Must-fix before *any* non-lab deployment (these break the spec's own isolation/trust claims):**

1. **Make instance→project authoritative (#1, #4, #14):** `GET /v3/servers/{instance-id}` mandatory; bind on Nova's server-record project; discard the body `project-id`; `require_nova_service_token` default-true + non-overridable; reject non-service callers on enrollment. *This single change closes the critical confused-deputy + auto-provision-abuse cluster.*
2. **Pin & verify stage-1 binaries (#2)** before `chmod`/exec, and **deliver root-fp out-of-band** (baked image / platform-admin metadata, not the unsigned response) (#26). Until done, the zero-touch path is unattended fleet-wide RCE.
3. **TLS (server-auth min, mTLS preferred) on the vendordata endpoint (#3)** — never return executable cloud-init over an unauthenticated channel.
4. **Leaf-cert revocation (#6)** — serial-denylist in `authorize()`, `cert revoke`, ≤1h TTLs — **before shipping the platform-admin API.**
5. **Reject service tokens + enforce project scope on the access plane (#9, #10)** before §13 is built.
6. **Structural labels≠grants (#7)** — field-level separation + parse-time prohibition + linter — before any label-keyed policy ships in a multi-source workspace.

**Should-fix before production:** bind join token to verified instance-id + move to `openstack-metadata` (#5); atomic idempotent mint (#15); callback-verified rebuild transition (#8); lifecycle teardown/GC on deletion (#17); revocation propagation + `expires_at`-capped TTLs (#16); reserved operator-only label/name namespaces + server-authoritative unique DNS names (#19, #20, #27); pin `service-uid`↔Keystone issuer + forbid shared `keystone_url` (#18); qualify anti-replay state by `(service-uid, project-id, instance-id)` (#22); least-privilege default role_map + auto-binding floor (#21, #28); separate break-glass from routine platform-admin with issuance-time audit (#12); mandatory fail-closed off-box audit sink + key separation (#13); binding-uniqueness + stale-binding re-validation (#24, #25); `reader_creds` hygiene (#32).

**PoC-acceptable (document as known limitations, fix at productization):** plain-HTTP transport **only** on a fully isolated single-host lab with no untrusted tenants on the path — anything routed (the geneza1 `vmbr5` fabric) already exceeds this, so treat #3 as must-fix there; `auto_provision`+`auto_approve`+token-in-metadata *provided #1/#4 land*; auto-provision rate limits + audit-record detail (#23, #31); boot-availability DoS + `os-role:` naming nit (#30, #27, #29).

---

## 16. Phased PoC plan

- **P0 — wire (done):** reachability verified (geneza-core↔kolla1 Keystone/Nova;
  kolla1↔geneza-core 7401/7402); vendordata wire format + token validation +
  project→domain captured live.
- **P1 — Keystone domain `geneza`** federated to Keycloak realm `geneza` (mirror
  the existing kolla1 federation); a project under it for the test VM.
- **P2 — Geneza:** gophercloud client + clouds registry + vendordata endpoint
  (§6–§11); platform-admin `bind` command; auto-provision.
- **P3 — Nova:** `vendordata_dynamic_targets = cloud-init@http://<geneza>:7407/openstack/vendordata/kolla1`
  + `[vendordata_dynamic_auth]` in **nova-compute** (config-drive path);
  `kolla-ansible reconfigure -t nova`.
- **P4 — prove:** boot Ubuntu 24.04 `--config-drive true` under the geneza domain's
  bound project → it enrolls into workspace W → `geneza-laptop` (in W) resolves its
  name (in-network DNS) and `geneza ssh`/`exec` reaches it over the overlay.

**Success = laptop reaches a freshly-booted OpenStack VM by name, zero operator
action on the VM.**

---

## 17. Open decisions
- Endpoint transport for prod: mTLS vs Nova-source-IP allowlist (PoC = plain HTTP).
- Auto-provision default per cloud: `true` (zero-touch, PoC) vs `false` (operator
  pre-binds via platform-admin, prod).
- PoC `auto_approve: true` vs production PENDING + admission gate.
- Token-in-metadata (`provider=token`, PoC) vs agent-sends-identity
  (`provider=openstack-metadata`, productized — removes the bearer secret).
- Reuse the Nova token for project→domain (kolla) vs require Geneza `reader_creds`
  (hardened clouds where nova has only the `service` role).
- ~~`service-uid` naming~~ **RESOLVED:** a stable operator-owned slug, **not** the
  Keystone FQDN (the FQDN is mutable and lives in `keystone_url`; keying bindings by
  it would break them on a Keystone rename — §7).
