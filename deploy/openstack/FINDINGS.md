# What running this against a live cloud found

Everything here was found by applying the Terraform and running the playbooks
against a real OpenStack (acvile eu-east-1, 2026-08-03), not by review. Recorded
because most of them are invisible to `terraform validate` and
`ansible-playbook --syntax-check`, which both passed throughout.

## Would have stopped the deploy dead

| # | Where | What |
|---|---|---|
| 1 | `roles/geneza_ca` | Every CA filename wrong (`ca.pem`, `intermediate.key`, `keys/grant.key`). `init` writes `ca-roots.pem`, `issuing-ca.crt`, `issuing-ca.key`, `grant.key`. Play aborted at the CA step. |
| 2 | `site.yml` | Role order started the controller **before** the CA existed → `load CA (did you run init?)` crashloop, then a 120s timeout on a port that could never open. Only ever fails on a first deploy. |
| 3 | `controller.yaml.j2` | `geneza_relays` undefined — config render failed three plays in. |
| 4 | `security.tf` | `for_each` over floating IPs unknown until apply. `validate` passes; `plan` cannot even be produced. |
| 5 | `deploy.sh` | `"${ANSIBLE_ARGS:-}"` expands to one empty argument → `the playbook: could not be found`. |
| 6 | `group_vars`, `files/` | `geneza_postgres_password`, `geneza_relay_shared_secret`, `geneza_postgres_dsn` defined nowhere; `files/policy.yaml` absent. |
| 7 | inventory / `ansible.cfg` | Nothing told Ansible which SSH key to use, and the database hop used `ProxyJump`, which spawns an inner ssh that does not inherit `--private-key`. |
| 8 | `security.tf` | Database reachable only via a controller, but its security group admitted SSH from `admin_cidrs` only — never from the controllers. |

## Silent — would have looked fine and been wrong

| # | Where | What |
|---|---|---|
| 9 | `roles/geneza_ca` | Root-key evacuation deleted `ca/ca.key`, which never exists. Reported success while the real root key sat on the internet-facing controller at `ca/offline-root/root-ca.key`. Now retrieves first and gates deletion on that succeeding. |
| 10 | `rotate-ca.yml` | Invoked `init --add-root`, `ca_epoch`, a combined old+new bundle — none of which exist anywhere in the product. Replaced with a stub that refuses and documents what real rotation would need. |
| 11 | `*.tf` | No `config_drive`. An instance that cannot reach the metadata service in time falls back to `DataSourceNone`, skips SSH key injection, and comes up ACTIVE and unreachable. Hit for real on the relay. |
| 12 | `geneza_ca`, `geneza_relay`, cert-renew | `docker run` without `--user` → root-owned files in a data dir the controller reads as uid 65532. Would have surfaced at first cert renewal, ~30 days in. |
| 13 | `controller.yaml.j2` | No `local_users`, no OIDC, empty `clouds` → a console nobody can authenticate to. |
| 14 | `controller.yaml.j2` | No `install_dir` → `/install.sh` 404s, so vendordata enrolment hands booting VMs a URL that does not answer. |
| 15 | `roles/geneza_relay` | `/tmp/relaycerts` bind-mount created root-owned by Docker; the nonroot container could not write the cert into it. |

## Robustness

| # | Where | What |
|---|---|---|
| 16 | `*.tf` | Floating-IP association raced the router interface → `ExternalGatewayForFloatingIPNotFound`. Needs an explicit `depends_on` (3 places). |
| 17 | `roles/postgres` | Hardcoded `/etc/postgresql/16/`; now discovered from the host. |
| 18 | `roles/common` | apt raced cloud-init's own apt run on a fresh boot. Now waits for cloud-init and retries. |
| 19 | `roles/common` | IPv4-only tenant network still gets AAAA first from the cloud resolver. |
| 20 | `variables.tf` | No way to pin which external subnet floating IPs come from — see below. |
| 22 | `roles/geneza_relay` | A `delegate_to: localhost` check inherited the play's `become: true` and tried to `sudo` on the OPERATOR'S machine — `sudo: a password is required`. |
| 23 | `roles/geneza_ca` | My own first fix was not idempotent: the second run tried to fetch a root key the first run had (correctly) deleted, so every re-run failed. Now gated on a `stat` of both ends, and the removal is gated on the LOCAL copy existing rather than on the fetch having run. |
| 24 | `roles/geneza_ca` | `changed_when: reissue.rc == 0` marked `reissue-tls` changed on every run and fired the `restart controller` handler with it — an idempotent re-run restarted the control plane. Now it asks `openssl x509 -checkhost` whether the cert already covers the advertised name. |
| 25 | `roles/geneza_ca` | `fetch` writes with the operator's umask, so the fleet root key and the issuing key landed 0644 on the operator's machine. Now chmod 0600 after staging. |
| 21 | `files/policy.yaml` | Written with the wrong schema first: `roles` is a **map** keyed by name, and rules match `node_labels`, not `nodes`. |

## Not our bugs — cloud findings worth reporting

- **`gp-nvme` volume type is broken.** Every volume of that type errors, including
  a blank 40 GB one. `NVMe` works. This is what made the first `db` instance fail.
- **Floating IPs can be allocated and be unreachable.** `public` carries six
  external subnets; only `dn-1` (185.104.181.0/24) is globally routed and it is
  **exhausted** (`409 No more IP addresses available`). `dn-2`, `ro-1`, `ro-3`
  allocate happily and are not announced — confirmed from two independent
  networks (`no route to host` vs `connection refused`). Nothing in the API says
  so. This is why `public_subnet_id` now exists.
- **Server-group quota** was 10/10, all empty orphans from magnum clusters in
  DELETE_FAILED / DELETE_IN_PROGRESS.
- **Intermittent control-plane errors** throughout: Keystone 504, Nova 500
  `DBConnectionError`, Placement `another process changed the consumer`,
  Neutron 502 mid-delete (which orphaned a port and blocked a subnet delete).

## The lesson that generalises

Both validators are shape checks, not execution:

- `terraform validate` never evaluates `for_each` against apply-time values.
- `ansible-playbook --syntax-check` never renders a template, so every undefined
  variable above passed it.

A `terraform plan` against real credentials and an `ansible-playbook --check`
against real hosts would have caught roughly half of this before any resource
was created.

## Result

`DEPLOY EXIT=0` against acvile eu-east-1 on 2026-08-03, and **fully idempotent**
on re-run — `changed=0` on every host, no handler fired, no restart:

```
geneza-db   : ok=14  changed=0  failed=0
gzp-gw1     : ok=33  changed=0  failed=0
gzp-relay1  : ok=22  changed=0  failed=0
localhost   : ok=5   changed=0  failed=0
```

With:

- console live on a real Let's Encrypt certificate at `https://gzp.lab.osie.cloud`
- local admin login returning `roles:["ws-admin"]` (so the policy binding resolves)
- CA initialised, and the **root key verifiably off the controller**:
  `offline-root: gone` on the host, `root-ca.key` staged locally at 0600
- relay registered in the store over mTLS on `:7405`, advertising its FLOATING
  IP for TURN and publishing its authenticated leaf key:

```
 region_id | relay_id   | doc
 eu-east-1 | gzp-relay1 | addrs: ["185.104.181.75:7404"]
                          control_addr: "185.104.181.75:7403"
                          relay_cert_pub: MFkwEwYHKoZIzj0CAQ…
```

That last row is the one worth keeping: agents pin the relay's leaf key from the
registry, and a Postgres-backed deploy takes that path rather than the static
single-node one. It is the same pin that broke the gold-2 lab when the relay was
pointed at a different (equally valid) certificate.

## Second run: OVH Public Cloud EU-WEST-PAR, TWO controllers

acvile could supply only one routable floating IP, so the multi-controller paths
went untested there. OVH had 15 free, so they were re-run properly — and the
secondary path immediately produced a defect that a single controller can never
reach:

| # | Where | What |
|---|---|---|
| 26 | `roles/geneza_ca` | `init` lays out `data_dir/{ca,tls,artifacts,recordings}` but only ever runs on the PRIMARY. A secondary is seeded by copy, so nothing created `tls/`, and `reissue-tls` died on `open .../tls/controller.crt: no such file or directory`. Secondaries now get the same layout. |
| 27 | `group_vars/all.yml` | `geneza_local_ca_dir` was a flat `.ca/`. Deploying a SECOND cluster from the same checkout overwrites the first one's staged root key — and since evacuation deletes that key from the controller, the local copy is the only one. Now namespaced by `site_domain`. |

Proven on OVH and not before:

- trust anchor seeded to a secondary: gw2 holds exactly
  `ca-roots.pem`, `issuing-ca.crt`, `issuing-ca.key`, `root-ca.crt` and
  **no** `offline-root` — the root never reaches a secondary
- each controller carries its OWN advertised name in its cert
  (`SANs: gw2.gzo.lab.osie.cloud, gzo.lab.osie.cloud, 57.130.73.56`)
- both register in the shared store advertising their own names first, which is
  what makes a `ControllerRedirect` verifiable:

```
gw1 | addrs: ["gw1.gzo.lab.osie.cloud:7401", "gzo.lab.osie.cloud:7401", ...]
gw2 | addrs: ["gw2.gzo.lab.osie.cloud:7401", "gzo.lab.osie.cloud:7401", ...]
```

- **leaderless sessions**: a token minted on gw1 is accepted by gw2 (200/200),
  so there is no session affinity to lose.

### Also learned on OVH

- **The Terraform cannot use OVH's own credentials.** OVH issues OIDC client
  credentials (`v3oidcclientcredentials`); the OpenStack provider has no such
  auth plugin. Mint an application credential from the OIDC session and use
  that. Worth stating plainly, since this repo names OVH as its reference cloud.
- **Caddy fell back to ZeroSSL rather than Let's Encrypt** for the shared site
  name. Both controllers request a certificate for the same round-robin name, so
  an HTTP-01 challenge lands on whichever IP DNS returned — the race flagged in
  the Caddyfile comments, observed for the first time. Harmless here (Caddy keeps
  whichever issuer succeeds) but it is why the two clusters have different
  issuers.
- OVH's Neutron endpoint reset the connection twice mid-apply
  (`read: connection reset by peer`). Terraform is resumable, so re-running
  cleared it both times.

## Still not covered

- No agent has joined either cluster, so no session has crossed a relay on a
  deployed control plane. Registration is proven; the splice is not.
- Cross-region relay modules (`relay_b/c/foreign`) — never instantiated.
- `external_postgres_dsn` — the built-in Postgres always ran.
- In-window certificate renewal (only the no-op path, on both clusters).
- `terraform destroy` — ran once on acvile and left a security group behind on a
  Neutron timeout.
- `horizon-geneza-console/` — never deployed.
