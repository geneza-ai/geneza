# Geneza — Product Roadmap

> Synthesized by the geneza-product-roadmap workflow: 5 product lenses → 26 features → independent customer-value + engineering-feasibility scoring → prioritized roadmap. Grounded in ARCHITECTURE.md deferred scope and the security audit (docs/SECURITY-AUDIT.md).

## Product vision

Geneza is an identity-aware access fabric: every byte to every target — shells, databases, internal web apps, Kubernetes, and later desktops — rides the same Noise-tunneled, policy-brokered, hash-chain-audited rails, with no standing credentials and no standing access. The next year turns a strong Linux/macOS SSH-brokering core into (1) a zero-install, browser-reachable platform that humans and CI can share, replay, and just-in-time request, and (2) an HA, off-box-audited, compliance-grade control plane an enterprise will trust as the only door to prod. The wedge that nobody else combines: tokenless machine identity + continuous authorization + typed multi-protocol brokering on one relay-or-direct data path.

## North-star metric

Percentage of an org's production access sessions (human and machine, across all protocols) brokered through Geneza with a per-identity, tamper-evident audit record and zero standing credentials — i.e., "share of prod access that is identity-bound and recorded." Counter-metrics: median session setup latency and new-session availability (to keep HA and direct-path work honest).

## NOW — next quarter (4)

### OpenSSH ProxyCommand stdio bridge (geneza proxy)  ·  effort M
*Depends on:* Noise tunnel + x/crypto/ssh session protocol; client login/cert/grant flow (both present)

Highest-impact, highest-feasibility item (5.0/4.5) and nearly free per ARCH section 6 since phases 1-2 are done. Instantly unlocks scp, rsync, git-over-ssh, Ansible transport, and IDE Remote-SSH on the existing SSH-inside-the-tunnel data path — turning Geneza from a bespoke CLI into a drop-in for every operator's existing toolchain. Ship the ssh-config stanza + --install + match-exec.

### HA state store (Postgres) + leader-only reconcile  ·  effort XL
*Depends on:* Store interface extraction (store.go); leader election (advisory lock/etcd lease)

The bbolt controller is the single point of failure for ALL new sessions, rollout, and CA reconcile, yet ARCH section 4/13 demand HA from day one. Factor Store behind an interface, add a pgx Postgres backend, run N stateless controllers behind an LB, and make reconcile loops leader-only via a Postgres advisory lock. This is the hard structural prerequisite for SaaS, multi-tenancy, and quotas — do the surgery now while the schema is small. (Merges the two HA-store proposals; off-box audit is split out below.)

### Metrics + alerting (promhttp + Grafana)  ·  effort M
*Depends on:* none

ARCH section 13 signals are currently unobservable; you cannot run HA, health-gated rollouts, or relay failover blind. Low effort, high feasibility (4.0/4.0), zero dependencies, and it is the named prerequisite for auto-halting rollouts. Land it alongside the HA work so the new multi-instance tier is observable from the first deploy.

### Agent-side re-validation of controller session bounds  ·  effort S
*Depends on:* HostPolicy push (ApplyPolicy); grant schema bump

Smallest item on the board (S, 4.5 feasibility) and an explicit security GATE for the web proxy: clamp MaxSessionTTL to a node-policy ceiling, add RequireNative to refuse web sessions on native-only targets, refuse near-expiry node certs, re-read ForbidDetach. Closes the audit's agent-side re-validation finding (a bad controller over-granting) and must land before any browser path or sharing exists. Pull it forward into now precisely because it unblocks the entire web phase.

## NEXT — 2–3 quarters (14)

### Web access path MVP: headless session proxy + xterm.js SPA  ·  effort L
*Depends on:* Agent require-native re-validation (now); controller HTTPS httpHandler(); internal/client headless; session host Attach stream

The largest unbuilt phase (section 7/14 ph7) and the single biggest unblocker on the board: it is the on-ramp for sharing/co-watch, JIT-from-browser, the replay viewer, the admin console, and browser RDP/VNC. Build the proxy as a headless CLI reusing attachproto: terminate WSS, auth via existing OIDC, mint a per-session cert, call the same CreateSession broker, bridge one WebSocket to one attach channel, tag ClientPath=web. Everything downstream depends on this seam.

### Stable admin REST/Connect API + Go and TS SDK  ·  effort M
*Depends on:* existing proto + interceptors; a service-account/API-token identity kind

Expose AdminAPI/UserAPI over Connect (gRPC, gRPC-Web, HTTP/JSON from one definition) behind a service-account/API-token identity kind. This is the shared substrate the admin console, Terraform provider, and CI scripting all need, and it is the foundation for workload identity. Doing it before the console prevents a throwaway facade. ARCH section 6 already names ConnectRPC.

### GitOps policy: lint, test, dry-run, versioned apply with provenance  ·  effort M
*Depends on:* policy.Engine/Static; AdminAPI ReloadPolicy; hash-chained audit; admin Connect API

Policy is one host-local YAML the controller trusts (an explicit audit finding); operators edit RBAC/ABAC blind. Add genezactl policy {lint,test,diff,apply --from-stdin --dry-run} shipping the body over AdminAPI (not a host path), stored content-addressed with author/sha/diff in the hash-chained audit, plus a sample GitHub Action. Closes the host-writable-state trust gap and is a precondition for trusting require_approval and continuous-authz decisions.

### Just-in-time access + approval flows (with break-glass)  ·  effort M
*Depends on:* policy engine require_approval; pending-request store; audit chain; notification seam; GitOps policy (for safe rollout of approval rules)

Standing prod access is the finding every security team raises and the headline differentiator buyers will pay for. Add require_approval to the policy engine + a pending-request store; geneza request/approve mints auto-expiring node+window-scoped grants via webhook/Slack/email seam; break-glass via a loudly-audited self-approve emergency role; every transition audited. Merges the standalone JIT proposal with the JIT half of the sharing item — they are the same require-approval policy outcome ARCH section 5 already calls for but never built.

### Off-box tamper-evident audit sink (signed, sequenced, S3 Object-Lock/SIEM)  ·  effort L
*Depends on:* types.Signed; bbolt/Postgres store; S3 Object-Lock/SIEM target

audit.go is an unkeyed SHA-256 chain a compromised controller can truncate or re-forge while ChainOk still passes (Finding 2 HIGH). Sign records with an ed25519 controller key + monotonic seq, cross-check count in bbolt/Postgres, and stream append-only to S3 Object-Lock/SIEM. This is the compliance bedrock that makes JIT, replay, and continuous-authz records trustworthy to an auditor — and it is the off-box half split out of the HA item and merged with the standalone tamper-evident-sink and the audit half of auto-halting rollouts.

### Identity-aware DB and HTTP brokering (typed Target registry)  ·  effort L
*Depends on:* serveForward/ActionForward; policy action extension; audit chain; target registry (new)

DBs and internal web apps today mean VPN + shared creds with no per-user audit. Introduce a typed Target registry (tcp/postgres/mysql/http) pinned to agent+upstream+labels and a connect-to-target policy action; MVP reuses serveForward with ForwardTarget locked, layer 2 parses the DB login packet for user+database and records HTTP method/host/path. This is the keystone abstraction that later unblocks bastion mode, Kubernetes, and workload identity — building it now compounds across four later bets.

### Admin console: fleet/session dashboard + audit search + replay viewer  ·  effort L
*Depends on:* Web access path MVP; admin Connect API; off-box audit sink; OIDC login; stored asciicast recordings

Everything is CLI-only and recordings are write-only asciicast with no viewer. A TS/React SPA over the new Connect facade: fleet table from GetFleetStatus, live sessions from ListSessions with kill-session, audit search over QueryAudit with the chain-OK indicator, and an embedded asciinema-player. Merges the standalone replay-viewer/recording-hardening proposal: the console IS the replay surface, and hardening (object-lock casts + integrity digest in audit) rides the off-box-sink work.

### Live session sharing / co-watch  ·  effort M
*Depends on:* Web access path MVP; multi-reader attach (present); share-grant policy

Pair-debug and over-the-shoulder review need a second human on the buffer, impossible today (section 7). Owner mints a scoped, time-boxed share grant; a second viewer's WebSocket attaches read-only to the same snapshot+delta buffer (section 8 already supports multiple readers). High differentiation (4.0) and strategic fit (5.0). The JIT half of this proposal is merged into the JIT item above; what remains is pure multi-reader attach on the web path.

### Access graph + continuous authorization  ·  effort M
*Depends on:* policy evaluation; persistent control channel + registry.Broadcast; re-auth-on-reattach extended to heartbeat; audit chain

Operators cannot answer who-can-reach-what-and-why, and a live session ignores policy changes and IdP group removals until TTL. Build (a) genezactl access-graph computing principal-to-role-to-target reachability + inverse with a diff on policy reload, and (b) agent heartbeat re-evaluation extending re-auth-on-reattach: on now-deny the agent tears down and the controller pushes an explicit revoke over the control channel. This is the live enforcement that makes JIT expiry and group-removal real-time rather than eventual — a genuine differentiator versus static bastions.

### Tokenless boot-time cloud enrollment  ·  effort L
*Depends on:* EnrollProvider seam; controller reach to cloud metadata/IdP; label-to-policy mapping

openstackMetadataProvider returns Unimplemented; per-node join tokens leak and enroll rogue nodes, acute under autoscaling. Finish the OpenStack EnrollProvider (verify meta_data/vendordata sig or Keystone/Nova on uuid+project_id, derive labels, allow-list projects/images, UUID anti-replay), then add AWS PKCS7, GCP JWT, Azure IMDS. Closes the anti-replay gap and is the machine-identity story (ARCH section 5) that underpins the SaaS/enterprise pitch.

### Signed-update anti-rollback floor  ·  effort M
*Depends on:* bootstrap State; geneza-sign

Bootstrap installs any signed manifest of a different version, so a compromised controller can silently downgrade workers to a vulnerable build (Finding 1 HIGH). Persist a monotonic version high-water-mark, reject non-newer manifests, add a signed version registry with yank. Self-contained, and a prerequisite for trusting the auto-halting rollout pipeline and the Windows Authenticode work.

### Auto-halting cohort rollouts (health-gated, cordon/drain)  ·  effort M
*Depends on:* Metrics + alerting (now); signed-update anti-rollback floor

Rollout is manual with no auto-halt or drain. Add cohort rollout with a health gate, auto-halt, and cordon/drain. Now feasible because metrics + alerting and the anti-rollback floor land first; the off-box-audit half of the original proposal is merged into the audit-sink item. Keeps the now-multi-instance fleet safe to update.

### Multi-relay selection + health-based failover  ·  effort M
*Depends on:* relay health channel to controller; CreateSessionResponse relay-list change; metrics

Broker hard-codes relayAddrs[0] with no fallback (broker.go/relay.go), contradicting section 13. Controller returns the full relay set with health in CreateSessionResponse; client+agent RTT-probe and rendezvous on the lowest-latency reachable relay with fallback; dead relays drop on health check-in; relay stays payload-blind. Merges the two identical relay proposals. This seam is the explicit prerequisite for the P2P direct path.

### Agentless bastion mode + M2M/CI workload identity  ·  effort L
*Depends on:* typed-target registry + serveForward (DB/HTTP brokering item); policy bindings by subject/claim; OIDC verification extended to CI issuers; non-interactive CLI login; short-TTL cert issuance

Fleets have endpoints that cannot run the agent (appliances, managed DBs, legacy SSH), making Geneza all-or-nothing; and CI/service accounts still carry long-lived human creds in secrets. Bastion: an enrolled agent advertises downstream targets and brokers via serveForward + typed target with a short-lived SSH cert. Workload: geneza login --workload exchanges a CI OIDC id-token (GitHub/GitLab/Buildkite) for a minutes-TTL service-principal cert (no PTY, record always). Both ride the typed-target registry and generalize toward SPIFFE/SVID.

## LATER (5)

### Multi-tenancy + quotas  ·  effort L
Flat namespace, no tenant concept, no quotas (audit flagged unbounded sessions). Thread a tenant id through identity/policy/Store, add broker match and per-tenant token-bucket limits and session quotas. Strictly gated on the HA Postgres store and the stable Connect API; it is the commercial unlock for true multi-tenant SaaS but premature until the control plane is HA and the admin surface is stable.

### Windows agent (ConPTY, SCM, running-exe update, Authenticode, Wintun)  ·  effort XL
Much of the enterprise fleet is Windows and buyers will not adopt a part-estate tool, but section 11 already isolated the OS landmines behind interfaces, so this is a backend not a rewrite. Implement Pty via ConPTY, ServiceManager via SCM, Updater via rename-the-running-.exe, KeyStore via CNG/TPM PCP+DPAPI; sign with cosign AND Authenticode (EV cert in HSM); bootstrap verifies both. XL and gated on the anti-rollback floor; it is also the hard prerequisite for RDP since most RDP targets are Windows.

### RDP/VNC desktop access as a byte-proxied channel  ·  effort L
Access is SSH-only; the tagline promises remote desktop on the same rails (section 6/14 ph10). MVP proxy-only: an Action=desktop grant + a new SSH-inside-the-tunnel channel type the agent connects to a local RDP/VNC endpoint, with the web client rendering via a JS canvas over the same WebSocket bridge. Lowest feasibility on the board (2.5) and double-gated on the web path AND the Windows agent — high-ceiling differentiation, but only after both unblockers land.

### Kubernetes access broker  ·  effort L
kubectl to private clusters means long-lived SA tokens or cluster-admin certs with no human-identity tie. In-cluster agent registers the API server as an http target; geneza kube writes a kubeconfig to a brokered listener; agent injects a short-TTL impersonation/SA credential; policy gates clusters/namespaces/verbs and audits verb+resource+namespace. Builds directly on typed-target + HTTP-audit, but lowest strategic-fit (3.5) and feasibility (2.0), so it follows once the brokering primitive is proven in production.

### Direct peer-to-peer data path with NAT traversal  ·  effort XL
Every session traverses a relay today, carrying all bandwidth and a latency hop even when peers could connect directly (section 4/6 promise direct-first). Use the multi-relay side channel to exchange endpoint candidates and UDP hole-punch, move the Noise/WireGuard tunnel onto a wireguard-go direct path on success, keep relay warm as fallback. XL and strictly gated on multi-relay selection; a performance/cost win best taken once relay traffic volume justifies it.

## Bold bets (highest-differentiation spikes)

- Continuous authorization with live revoke: a heartbeat that re-evaluates every in-flight session against current policy and IdP group membership and tears it down on now-deny over the control channel. Static bastions enforce only at session start; real-time revocation on group removal or policy change is a category-defining claim worth a dedicated spike.
- Tokenless machine identity across every cloud: no join tokens anywhere — OpenStack/AWS/GCP/Azure nodes prove themselves via signed metadata at boot, with UUID anti-replay. Combined with CI workload identity (OIDC id-token to minutes-TTL SVID), this is the SPIFFE-grade story that eliminates the stolen-long-lived-secret threat for the whole automation plane, not just human shells.
- One identity-aware data path for every protocol: the typed-target registry turning the same Noise tunnel into per-user-audited Postgres, HTTP, Kubernetes, and bastion brokering. Owning shells + DBs + internal web + k8s on one policy-and-audit fabric is the integration no single-protocol competitor can match — spike the registry abstraction hard so DB packet parsing, k8s impersonation, and HTTP method/path audit all fall out of one seam.
- Browser-native shared and replayable sessions: zero-install co-watch and break-glass with a second human attaching read-only to a live buffer, plus signed-URL asciinema replay. The web proxy makes pair-debug, over-the-shoulder approval, and incident replay a product feature rather than a screen-share workaround.

## Sequencing rationale

Three independent unblock chains drive the order. (1) The WEB chain: agent-side re-validation (pulled into now as the cheapest item and the named security gate) precedes the Web access path MVP, which is the largest dependency hub on the board — it unblocks sharing/co-watch, the replay viewer, the admin console, browser-initiated JIT, and eventually the RDP/VNC canvas. Nothing browser-facing can land before the proxy and its require-native guard exist. (2) The CONTROL-PLANE chain: the HA Postgres store is structural surgery best done now while the schema is small; it is the hard prerequisite for multi-tenancy + quotas (later) and the SaaS tier. Metrics + alerting lands alongside it because HA, health-gated rollouts, and relay failover are unrunnable blind. Off-box tamper-evident audit then makes every downstream record (JIT, replay, continuous-authz) trustworthy to an auditor — so it precedes the compliance-sensitive features rather than trailing them. (3) The BROKERING chain: the typed-target registry (DB/HTTP brokering) is the keystone primitive that compounds across bastion mode, workload identity, and the later Kubernetes broker — building it once in next pays off four times. The Connect/REST API + SDK is sequenced before the admin console and before workload identity because both consume it; doing it first avoids a throwaway facade, and GitOps policy is sequenced before JIT because trustworthy require-approval rules depend on validated, provenance-tracked policy. Multi-relay selection precedes the XL P2P direct path (its explicit side channel), and the Windows agent precedes RDP (most RDP targets are Windows) — both pushed to later behind the anti-rollback floor. Merges applied: the two HA-store proposals collapse into one Postgres swap with off-box audit split out and unified with the standalone tamper-evident sink and the audit half of auto-halting rollouts; the two relay proposals are one; the standalone JIT and the JIT half of the sharing item are one require-approval feature; and the recording-hardening/replay-viewer proposal is absorbed into the admin console.

## Cross-cutting themes

- Reach: zero-install browser access and drop-in OpenSSH/IDE/CI compatibility on the existing rails
- No standing access, no standing credentials: JIT with approval, break-glass, and continuous live-revoke authorization
- One identity-aware data path for every protocol: typed-target brokering for SSH, DB, HTTP, bastion, and Kubernetes
- Enterprise-grade control plane: HA Postgres store, off-box tamper-evident audit, signed anti-rollback, health-gated rollouts, multi-tenancy
- Tokenless machine and workload identity across every cloud and CI provider (SPIFFE-bound)
- Operability and trust surface: metrics, admin console, session sharing, signed-URL replay, and GitOps policy with provenance

## All scored features (by composite)

| Composite | Feature | Effort | Category | Impact | Feasibility | Differentiation | Fit |
|---|---|---|---|---|---|---|---|
| 4.3 | Live session sharing/co-watch + JIT access with approval | L | differentiation | 4.5 | 3.5 | 4 | 5 |
| 4.13 | OpenSSH ProxyCommand stdio bridge (geneza proxy) | M | devex | 5 | 4.5 | 2 | 5 |
| 4.08 | Access graph plus continuous authorization | M | differentiation | 4.5 | 3 | 3.5 | 5 |
| 3.97 | Identity-aware DB and HTTP brokering | L | differentiation | 4.5 | 3 | 3.5 | 4.5 |
| 3.97 | Just-in-time access with approval flows | M | enterprise | 5 | 3.5 | 2.5 | 4.5 |
| 3.96 | GitOps policy: validate, dry-run, versioned apply with provenance | M | devex | 4 | 4 | 3 | 5 |
| 3.91 | Tokenless boot-time cloud enrollment | L | differentiation | 4 | 3 | 3.5 | 5 |
| 3.86 | RDP/VNC access as a byte-proxied channel type | L | differentiation | 4.5 | 2.5 | 3 | 5 |
| 3.86 | HA store | XL | enterprise | 5 | 3 | 2 | 5 |
| 3.76 | Admin console: fleet/session dashboard plus audit and replay viewer | L | devex | 4.5 | 4 | 2 | 4.5 |
| 3.75 | Agent-side re-validation of controller session bounds | S | security | 3.5 | 4.5 | 2.5 | 5 |
| 3.7 | Stable admin REST/Connect API plus Go and TS SDK | M | devex | 4 | 4 | 2 | 5 |
| 3.69 | Web access path MVP: web session proxy + xterm.js SPA | L | roadmap | 4.5 | 3 | 2 | 5 |
| 3.64 | HA state store (Postgres) + leader reconcile + off-box audit | L | enterprise | 5 | 2.5 | 1.5 | 5 |
| 3.61 | Signed-update anti-rollback floor | M | security | 4 | 3.5 | 2 | 5 |
| 3.58 | Windows agent (ConPTY, SCM, running-exe update, Authenticode, Wintun) | XL | enterprise | 4.5 | 3 | 2 | 4.5 |
| 3.56 | Agentless bastion mode plus M2M/CI workload identity | L | differentiation | 4 | 3 | 3 | 4 |
| 3.54 | Auto-halting rollouts + off-box audit | L | roadmap | 4 | 3 | 2.5 | 4.5 |
| 3.5 | Recording pipeline hardening + asciinema replay viewer | M | roadmap | 4 | 3.5 | 2 | 4.5 |
| 3.48 | Metrics + alerting | M | enterprise | 4 | 4 | 2 | 4 |
| 3.48 | Relay geo-selection + failover | M | enterprise | 4 | 4 | 2 | 4 |
| 3.41 | Off-box tamper-evident audit sink | L | security | 4 | 3 | 2 | 4.5 |
| 3.27 | Kubernetes access broker | L | differentiation | 4 | 2 | 3 | 3.5 |
| 3.22 | Multi-relay selection + health-based failover | M | roadmap | 3.5 | 3.5 | 2 | 4 |
| 3.21 | Direct peer-to-peer data path with NAT traversal | XL | roadmap | 4 | 2.5 | 2 | 4 |
| 3.04 | Multi-tenancy + quotas | L | enterprise | 3.5 | 2.5 | 2 | 4 |

---
*Effort: S<1wk · M~weeks · L~1–2mo · XL~quarter+. Scores are 1–5 averages of two independent judges.*
