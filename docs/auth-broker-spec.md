# Geneza Auth-Broker Redesign — Final Architecture Spec & Phased Build Plan

**Status:** Buildable. Greenfield (drop & recreate `state.db`; no migrations).
**Scope:** R1 (unified web login form across keystone/oidc/local), R2 (keystone access plane + auto-provision + first-user=ws-admin), R3 (multi-provider coexistence in one workspace), R4 (token-in-URL elimination on trusted_dashboard), R5 (RFC 8628 device grant replacing CLI OIDC/ROPC/local).
**Lead decision:** Adopt **Design 2 (security-first)** as the spine for F1–F5 (judge consensus 9/9/9 across all three panels), with three deliberate borrows from Design 1 noted inline, and **all 26 red-team mitigations folded in as MUSTs**. Design 3's server-side OIDC code exchange and `first-user=['admin','ws-admin']` are **rejected** (unanimous wrong-choice flags: unproven IdP egress + cluster-admin escalation).

---

## 1. Architecture Overview — the identity-broker model in one diagram-in-words

The controller becomes **one identity broker** with exactly two credential carriers and one role source.

```
                          ┌────────────────────────────────────────────────┐
   UPSTREAM IdPs          │                 GENEZA CONTROLLER                   │
                          │              (single identity broker)           │
  Keystone (per cloud) ──▶│  validate/mint ─┐                               │
  OIDC (Keycloak)      ──▶│  verify id_token┤                               │
  local_users (bcrypt) ──▶│  bcrypt        ─┤                               │
                          │                 ▼                               │
                          │   establishSession(provider, source, subject,   │
                          │       groups, upstreamExp, requestedWS)         │
                          │     1. workspacesForUserStore(provider,user)  ──┼─▶ store membership ∪ config
                          │     2. resolveAccessWorkspace (keystone only):  │   (per-ws `members` child bucket,
                          │          binding-or-auto-provision +            │    key=<provider>:<username>)
                          │          UpsertFirstAdmin (atomic)            ──┼─▶ first-user = ws-admin (txn)
                          │     3. rolesForMember = strip(store ∪ policy) ──┼─▶ ONE role source
                          │     4. mint AuthSession, ExpiresUnix capped     │
                          │          by upstreamExp  (#16)                  │
                          │            │                    │               │
                          │   ┌────────▼────────┐   ┌────────▼──────────┐   │
                          │   │ BROWSER CARRIER │   │  CLI CARRIER       │  │
                          │   │ opaque session  │   │ mTLS user cert     │  │
                          │   │ (sha256-at-rest)│   │ (RFC 8628 device   │  │
                          │   │ Bearer header   │   │  grant; CSR up      │  │
                          │   │ + WS one-time   │   │  front; cert issued │  │
                          │   │   ticket        │   │  INSIDE redeem txn) │  │
                          │   └────────┬────────┘   └────────┬───────────┘  │
                          └────────────┼─────────────────────┼─────────────┘
                                       │                      │
                       SPA (/api/* JSON, Bearer)       gRPC plane (mTLS, cert URI
                       + web-shell WS (?ticket=)        is SOLE authority; workspace
                       + /openstack/{svc} websso        server-derived; interceptor
                         form-POST → 303 → handoff       UNTOUCHED)
```

**Invariants preserved (untouched):** mTLS cert is the **sole** gRPC authority; workspace is **server-derived** from the cert URI / session record (never client-supplied); the agent's independent continuous grant re-verification still bounds every live session; fail-closed cross-tenant isolation (members live under `ws/<id>/`, a cross-tenant read is structurally `NotFound`).

**What changes:** (a) the console stops re-verifying upstream tokens per request — it trusts its own opaque session; (b) membership moves from config-only to a store-backed per-workspace bucket so keystone/oidc/local users coexist and survive restart; (c) the CLI loses all OIDC/ROPC/local code and gains only the device flow; (d) keystone becomes a first-class browser provider (password login form + Horizon websso handoff); (e) one role-resolution function feeds **both** the cert and the session.

**Two carriers, two trust stories, one role source:** the cert carries roles for gRPC; the session carries roles for the console; both come from `rolesForMember(ws, provider, user, groups)`; both pass `stripReservedRoles`.

---

## 2. Decisions F1–F5

### F1 — Session model: controller-minted OPAQUE token, sha256-hashed at rest, Bearer carrier

**Chosen (Design 2).** Opaque 256-bit token from `types.NewToken()`, persisted in bbolt keyed by `sha256(token)` hex, server-side revocable, TTL capped by upstream expiry.
**Justification:** mirrors the proven `TokenRecord`/`UseToken`/`OSMintOnce` primitive (free revocation = delete row); a JWT buys nothing (still needs a denylist) and leaks claims. Hashing at rest is the decisive edge — a DB/backup leak cannot resurrect a live session. Bearer-from-`sessionStorage` (not a cookie) means **zero CSRF surface** on the JSON API and keeps the web-shell `?…=` carrier path intact. (Rejected Design 1's cookie+double-submit-CSRF; rejected Design 3's dual cookie+Bearer.)

**Session record** (new GLOBAL bucket `sessions_auth`, key = `sha256(token)` hex):

```go
type AuthSession struct {
    TokenHash    string   // sha256(token) hex — bucket key; raw token only ever in the browser
    User         string   // canonical username (normalized; see RT-F12)
    Provider     string   // "keystone" | "oidc" | "local"
    Source       string   // keystone svc-uid; oidc issuer; "" for local
    Subject      string   // STABLE provider subject id (keystone user-id / oidc sub) — authz key
    Workspace    string   // resolved server-side; SOLE console authority; NEVER client-trusted
    Roles        []string // stripReservedRoles(resolved) at mint; frozen + re-resolved on probe
    Groups       []string // IdP/keystone groups (re-resolution + audit)
    Admin        bool     // contains(Roles, roleWSAdmin) || contains(Roles, roleAdmin)
    KSTokenHash  string   // keystone only: sha256 of the validated token (for the revocation reaper)
    CreatedUnix  int64
    ExpiresUnix  int64    // min(now+ConsoleSessionTTL, UpstreamExp)  ← #16 cap, computed server-side
    UpstreamExp  int64    // keystone expires_at / oidc id_token exp / 0 for local
    LastSeenUnix int64    // sliding-idle reaper (shrinks stolen-token replay window — RT-F4)
    UserAgent    string   // soft fingerprint, audited on mismatch (RT-F4)
    Revoked      bool
}
```

**TTL policy:** `ConsoleSessionTTL` default 8h. `ExpiresUnix = min(now+TTL, UpstreamExp)` when `UpstreamExp>0`. For keystone `UpstreamExp = osCaller.ExpiresAt` (#16); oidc = id_token exp; local = `now+TTL`. No silent refresh — re-login at expiry.

**Validation algorithm** (replaces `authenticateToken`): `h := sha256hex(bearer); rec := store.GetAuthSession(h); if err||rec.Revoked||now>rec.ExpiresUnix → 401 (delete on expiry)`. Build `consoleUser{Name, Workspace=rec.Workspace, Roles=rec.Roles, Admin=rec.Admin}` — **Workspace, Roles, Admin come ONLY from the record** (kills the `Workspace=defaultWorkspace` hardcode and the default-policy role lookup — RT-F19).

**Revocation:** `DeleteAuthSession` (logout/admin kick). `RevokeUser` fans out to **both** all of a user's auth-sessions **and** their cert serials (uniform web+CLI revocation — RT-F15).

### F2 — Web auth unification: keep browser-PKCE, exchange id_token ONCE

**Chosen (Design 1/2, identical).** SPA keeps browser-PKCE for OIDC, but on callback **POSTs the id_token once** to `/api/v1/session/oidc` and discards it; controller verifies with the existing hand-rolled `oidcVerifier` and returns the opaque session.
**Justification:** minimal new code, no OIDC client secret on the controller, **no IdP `token_endpoint` egress requirement**. (Rejected Design 3's server-side code exchange — unanimous wrong-choice: unproven egress from the nginx-fronted console + a large new untested OAuth machine against the "don't reinvent OAuth" constraint, extending the deliberately hand-rolled verifier that only resolves `jwks_uri`.)

**Three sibling endpoints** (all on `consoleAPI.handler()`, plain-HTTP behind nginx, all return the **same** body `{token, expiresUnix, user, workspace, roles, admin, availableWorkspaces?}`):

| Endpoint | Body | Pipeline |
|---|---|---|
| `POST /api/v1/session/local` | `{username, password, workspace?}` | `authenticateLocal` (constant-time bcrypt) → `establishSession(local)` |
| `POST /api/v1/session/oidc` | `{idToken, workspace?}` | `authenticateOIDC` (existing verify) → discard token → `establishSession(oidc)` |
| `POST /api/v1/session/keystone` | `{cloud, username, password, domain?, projectId?\|projectName?, workspace?}` | `clouds[cloud].PasswordLogin` (gophercloud `tokens.Create`, project-scoped) → guards #9/#10 → `resolveAccessWorkspace` → role_map → `establishSession(keystone, upstreamExp=ExpiresAt)` |
| `GET /api/v1/session` | — | current session (replaces `/me`, SPA bootstrap probe; re-resolves roles so demotions apply) |
| `DELETE /api/v1/session` | — | logout: `DeleteAuthSession` + clear in-memory state |

**Shared core** `establishSession(provider, source, subject, groups, upstreamExp, requestedWS)`:
1. `cands := workspacesForUserStore(provider, user, groups)` (config ∪ store membership).
2. Resolve ws: requested validated against `cands` (0→403; 1→use; n→200 with `availableWorkspaces` and **no token**). **A client-supplied `workspace` is permitted ONLY as a choice among validated candidates** (RT-F18).
3. `roles := stripReservedRoles(rolesForMember(ws, provider, user, groups))`; if empty → 403.
4. Persist/refresh `MemberRecord`; mint `AuthSession` capped by `upstreamExp`; audit `login_success`.

**Workspace switcher:** session is bound to ONE workspace (isolation). Switching = re-POST the provider endpoint with `workspace=<other>` (re-prompt for keystone/local; re-run PKCE for oidc). No mutable session.

### F3 — Membership & roles: store-backed `members` child bucket, union role resolution, `admin` reserved

**Chosen (Design 2)**, with the **critical RT-F10 hardening**: `admin` (the cluster fleet role) is made a **reserved role on every tenant-derived path**, exactly like `platform-admin`.
**Justification:** per-ws child bucket keyed by `<provider>:<username>` gives R3 coexistence for free and structural cross-tenant isolation. The judge-selected invariant — **ws-admin is tenant-scoped and does NOT satisfy the cluster `AdminAPI` gRPC gate** — only holds if `admin` can never be emitted by a tenant role path. (Rejected Design 3's `first-user=['admin','ws-admin']`.)

**Member record** (per-ws child sub-bucket `childMembers="members"` under `ws/<wsID>/`, reuses `wsChildW`/`wsChildR` + `putJSONB`/`getJSONB`):

```go
type MemberRecord struct {
    Provider    string   // keystone|oidc|local
    Username    string   // canonical display username (normalized; no ':' — RT-F12)
    Subject     string   // STABLE provider subject id (keystone user-id / oidc sub) — authz key
    SourceUID   string   // keystone svc-uid (binds principal to one cloud)
    Roles       []string // geneza roles IN THIS WS (ws-admin|ws-member|ws-viewer); NEVER admin/platform-admin
    Groups      []string
    AddedBy     string   // "auto:keystone:first-user" | "auto:keystone:role_map" | "admin:<name>"
    CreatedUnix int64
    UpdatedUnix int64
}
```
Key = `<provider>:<subject>` (use the **stable subject id**, not the mutable display name — renaming an IdP account cannot hijack another row — RT-F12).

**Store methods:** `PutMember`, `GetMember`, `ListMembers`, `DeleteMember`, `ListMemberWorkspaces(provider,subject)`, and **`UpsertFirstAdmin(ws, key, rec)`** — single bbolt `Update`: writes `rec` as `ws-admin` **only if** the members bucket is empty, else maps via `role_map` (race-free — RT-F11).

**Role resolution** (`rolesForMember(ws, provider, subject, groups)`, the SOLE role source for sessions AND cert issuance):
1. store roles: `GetMember(ws, provider+":"+subject).Roles`.
2. policy roles: `policyFor(ws).RolesFor(subject, groups)` — **provider-qualified** (the union applies the policy path only to the matching provider, so a bare-username config binding cannot leak across providers — RT-F12).
3. `roles := stripReservedRoles(union(1, 2))` — `stripReservedRoles` now strips **both `platform-admin` AND `admin`** (RT-F10). Deny if empty.

**`workspacesForUserStore(provider, subject, groups)`:** existing config scan (`open()`/`Members`/`MemberGroups`) UNION `store.ListMemberWorkspaces(provider, subject)`. Optional `member_index` (subject→[]ws) bucket is a drop-in if workspace count grows (O(W) probe is fine at lab scale — RT-noted).

**Cert reconciliation:** the device-approval issuance path calls the **same** `rolesForMember`, so the CLI cert and the browser session carry identical roles, both `stripReservedRoles`'d, both unable to carry `admin`.

**Admin gate split (structural):** console `authAdmin` requires `Admin = contains(roles, "ws-admin") || contains(roles, "admin")` — **per-workspace**, keyed on `rec.Workspace`. The gRPC `AdminAPI` gate (`auth.go` `hasRole(ident, "admin")`) still requires the cluster `admin` role, which is **now unreachable from any login/membership/role_map/policy path** (RT-F10). Break-glass cert issuance remains the only `admin` grant.

### F4 — Device code: RFC 8628 over HTTP/JSON, cert issued INSIDE the redeem txn

**Chosen (Design 2)** with three red-team hardenings. HTTP/JSON on the console listener **AND** mirrored on the main `:7402` HTTPS listener (so CLI login works with the web console disabled — RT-F23). gRPC variant (Design 1) rejected: keeps the cert-less gRPC allowlist Enrollment-only and lets `UserAPI.Login` be deleted.
**Justification:** faithful RFC 8628; CSR captured up front; cert bound to the **approving** human's identity+workspace+roles (CLI asserts only a public key); transactional redeem-once cloning `OSMintOnce`.

**Device-grant store** (new GLOBAL bucket `device_codes`, key = `sha256(device_code)` hex; `UserCodeHash`→`DeviceHash` index for approval lookup):

```go
type DeviceGrant struct {
    DeviceHash       string  // sha256(device_code) — key; raw device_code only on the polling CLI
    UserCodeHash     string  // sha256(normalized user_code); user_code shown to human
    CSRPem           []byte  // CLI's CSR captured up front (PUBLIC material only)
    ClientName       string
    State            string  // "pending" | "approved" | "denied" | "redeemed"
    ApprovedSubject  string  // bound at approval, from the approving AuthSession (server-side)
    ApprovedProvider string
    ApprovedWS       string
    ApprovedRoles    []string
    UpstreamExp      int64   // approving session's cap → bounds cert TTL (#16 → CLI — RT-F26)
    SourceIP         string  // shown on confirmation screen (RT-F8/RT-F24)
    CreatedUnix      int64
    ExpiresUnix      int64   // device_code TTL (default 10m)
    Interval         int32   // poll interval (default 5s); server bumps on slow_down
    LastPollUnix     int64
    PollCount        int32
}
```
**No `CertPem` field** — the cert is **never persisted**; it is issued **inside** the redeem `Update` txn from the stored CSR + frozen approval tuple (RT-F3: a DB leak yields nothing signable; tightens redeem-once).

**Endpoints** (HTTP/JSON, on console listener + `:7402`):

| Endpoint | Auth | Behavior |
|---|---|---|
| `POST /api/v1/device/authorize` | anon | `{csrPem, clientName}` → mint `device_code` (256-bit) + `user_code` (8-char Crockford base32, no ambiguous chars, `XXXX-XXXX`) → store `DeviceGrant{pending, SourceIP}` → `{deviceCode, userCode, verificationUri:<ext>/activate, verificationUriComplete, interval, expiresIn}`. Rate-limited per IP + global pending cap (RT-F25). |
| `POST /api/v1/device/token` | anon | `{deviceCode}` → **single `Update`**: expired→`expired_token`+delete; polled faster than `Interval`→`slow_down`+`Interval+=5`; `pending`→`authorization_pending`; `denied`→`access_denied`+delete; `approved`→**redeem-once**: verify `approved && !redeemed && !expired`, flip to `redeemed`, **`ca.IssueFromCSR` inside this txn** (TTL `min(CertTTL.User, until(UpstreamExp))` — RT-F26), return `{userCertPem, caRootsPem, user, workspace, roles, expiresUnix}`. |
| `GET /api/v1/device/{userCode}` | session | bound to the approving browser session (the user must have fetched this code's activate page — RT-F24). Returns `{clientName, sourceIP, requestedAt}`. |
| `POST /api/v1/device/approve` | session | **human MUST TYPE the user_code** (Approve disabled until manually entered — no one-click from `verificationUriComplete`, RT-F8/RT-F22). Bind grant to the approving session: `ApprovedSubject/Provider/UpstreamExp` from the session; **recompute** `ApprovedWS` + `ApprovedRoles` server-side via `rolesForMember(pickedWS, …)` and **assert `pickedWS ∈ workspacesForUserStore(approver)`** — reject otherwise (RT-F16). Audit `{approver, clientName, sourceIP}`. Rate-limit/lockout per session+IP (RT-F25). |
| `POST /api/v1/device/deny` | session | `State=denied`. |

**Anti-abuse summary:** `user_code` 40-bit + server `slow_down` + 10m TTL + single-use + lockout-after-N; cert bound to approver (phish yields only the victim's **own** access, named loudly with workspace+roles+source IP); device-issued certs are **shortest viable TTL**, enumerable in a console "active CLI credentials" view with one-click revoke (RT-F22). `establishCATrust` (TOFU/pin) **MUST** precede `/device/authorize` (all device HTTP rides the pinned-CA client). RFC 8628 §3.3.1 explicit-interaction requirement enforced (no auto-approve).

### F5 — Trusted dashboard: websso form-POST only, 303 to a hashed single-use handoff code

**Chosen (Design 2/3 tie, Design 2 mechanics).** Horizon websso delivers via **form-POST** to `POST /openstack/{svc-uid}`; the controller 303s to a clean URL carrying only a **30s single-use 256-bit handoff code**. (Rejected Design 1's default cross-site `SameSite=Lax` cookie-set on the POST→303 — fragile across origin/proxy topologies.)
**Justification:** structurally token-in-URL-free; the keystone token is consumed server-side and never reflected; the SPA swaps the handoff code for the real Bearer and `replaceState`s the URL clean.

**Endpoint** `POST /openstack/{svc-uid}` (form `token=<keystone token>`, anonymous):
1. `svc-uid` routes to `s.clouds[uid]` (404 routing-only on unknown).
2. **Refuse to read any `token` from the query string EVER** — accept only the POST form field; on GET or no-form-token, return 400 without parsing/logging/echoing a query `token` (RT-F5).
3. `Validate(token)` → `osCaller`. **Assert the token's issuing keystone matches the svc-uid's configured `KeystoneURL`** (svc-uid confused-deputy — RT-F13).
4. **Guard #9** (reject service token): reject if `ProjectID == serviceProjectID` (resolved UUID, **not** name — RT-F20) OR token is system/domain-scoped OR carries the Keystone `service` role OR `UserName` ∈ service-user denylist (defense-in-depth). **Fail closed** if the validation response lacks fields to prove a human project-scoped token.
5. **Guard #10** (require project scope): reject if scope type is not strictly `project` (not merely `ProjectID != ""` — RT-F21).
6. `resolveAccessWorkspace(uid, ProjectID)` via the **same** `osProjectBindingKey(uid, projectID)` the enrollment plane uses → bound ws, OR (if `allow_human_auto_provision` — a **separate** per-cloud flag, default false, distinct from VM-enrollment `auto_provision` — RT-F14) `ensureWorkspace`+`PutSourceBinding`+`registerDynamicWorkspaceAuto`+`UpsertFirstAdmin`; else 403 (no empty-cloud-init fallback for humans — RT-F14).
7. Mint `AuthSession` capped by `ExpiresAt` (#16); persist membership.
8. **303 to `<ext>/?handoff=<code>`** (256-bit, single-use, 30s, sha256-hashed at rest in `handoff_codes`); `Cache-Control: no-store`; `Referrer-Policy: no-referrer` on this response; set a one-time `HttpOnly+Secure+SameSite=Strict` companion cookie bound to the handoff code (double-secret — a leaked code in logs/Referer is useless without the cookie — RT-F2). SPA detects `?handoff=`, **`history.replaceState` clean as the FIRST synchronous action**, then `POST /api/v1/session/handoff {code}` (sends cookie) → real Bearer.

`POST /api/v1/session/handoff` (anon): single-`Update` transactional redeem (verify cookie+code, unredeemed, unexpired) → returns the already-minted session. Replay → `expired_token` (RT-F17).

**Guards summary:** #9 service-token reject, #10 strict-project-scope, #16 TTL cap, token-in-URL structurally impossible, svc-uid pinned to validating verifier.

---

## 3. Config surface (`controller.yaml` sketch)

Strict unmarshal (`KnownFields`): every key is a declared struct field.

```yaml
console:
  listen: ":7406"
  static_dir: "/opt/geneza/console"   # built console SPA (web/apps/console/dist)
  external_url: "https://geneza.lab.osie.cloud"     # cookie/redirect origin = public console origin
  auth:
    keystone_enabled: true        # REQUIRED true if any clouds[] entry exists (validated)
    oidc_enabled: true            # uses top-level oidc:; console no longer HARD-requires it
    local_enabled: true           # uses top-level local_users:
    session_ttl: "8h"             # ConsoleSessionTTL; effective = min(this, upstream exp)  (#16)
    device_code_ttl: "10m"
    device_poll_interval: "5s"
    handoff_code_ttl: "30s"
    keystone:                     # clouds exposed to the login form (svc-uid + label)
      - cloud: kolla1
        label: "Kolla1 OpenStack"
        default_domain: "Default"
    trusted_dashboard:
      - cloud: kolla1
  auto_provision_policy_file: "/etc/geneza/policy-autoprovision.yaml"  # role-NAME policy (F3/§6)
  csp: "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'"
                                  # connect-src widened to the OIDC issuer origin if discovery is browser-side (RT-F4)
  trusted_dashboard_origins: ["https://horizon.kolla1.lab.osie.cloud"]  # Referer/Origin allowlist (defense-in-depth)

oidc:                             # OPTIONAL now (console works without it); browser-PKCE relying party
  issuer: "https://keycloak.lab.osie.cloud/realms/geneza"
  client_id: "geneza"
  username_claim: "preferred_username"
  groups_claim: "groups"
  subject_claim: "sub"            # STABLE subject for the member key (RT-F12)

local_users:                      # OPTIONAL
  - username: "admin"
    password_bcrypt: "$2a$10$..."
    groups: ["geneza-admins"]

clouds:                           # access plane now LIVE (was enrollment-only)
  kolla1:
    kind: openstack
    keystone_url: "https://kolla1.lab.osie.cloud:5000/v3"
    auto_provision: true                  # VM ENROLLMENT plane (unchanged semantics)
    allow_human_auto_provision: false     # SEPARATE human access-plane switch, default false (RT-F14)
    allow_password_login: true            # gate the login-form keystone password path (RT-noted)
    allow_trusted_dashboard: true
    auto_approve: false
    service_project: "service"            # resolved to serviceProjectID UUID at load (RT-F20)
    default_domain: "Default"
    role_map:                             # LIVE on access plane; LEAST-PRIVILEGE default (RT-F21)
      admin: ws-admin                     # NEVER 'admin'/'platform-admin'; HARD-FAIL at load if it is (RT-F10)
      member: ws-viewer                   # DEFAULT floor = ws-viewer (NOT session:* — RT-F21)
      # operators map a deliberate keystone role (e.g. geneza-operator) → ws-member for interactive shell
    default_role: ws-viewer
    ca_file: "/etc/geneza/kolla-ca.pem"

cert_ttl:
  user: "8h"                              # device certs further capped by min(this, until(UpstreamExp))
```

**Validation (`validate()`):** `len(clouds)>0 ⇒ keystone_enabled`; `oidc_enabled ⇒ oidc block`; `local_enabled ⇒ local_users`; **≥1 mechanism enabled when `console.listen` set** (fail-closed — no unauthenticated console); every `console.auth.keystone[].cloud` ∈ `clouds`; **every `role_map` value HARD-FAILS if it is `admin` or `platform-admin`** (RT-F10); `default_role`/`role_map` floor defaults to `ws-viewer`.

---

## 4. Proto + store + CA changes

### Proto (`api/proto/geneza/v1/control.proto`)
- **DELETE `UserAPI.Login`** (rpc + `LoginRequest` + `LoginResponse`). Its issuance core moves into `issueUserCert(ctx, provider, subject, groups, ws, csrPEM)`, called by the device-approve/redeem path. This is the **only** cert-less `UserAPI` rpc; removing it shrinks the cert-less gRPC allowlist to **Enrollment-only** and removes the `UserAPI/Login` special-case from `auth.go` `authorize()`.
- **No new gRPC** for device/session/keystone — all are HTTP/JSON on the console listener (+ device mirrored on `:7402`). Keeps the proto minimal and the mTLS interceptor untouched.
- **AdminAPI:** extend `RevokeUser` server impl to also `DeleteAuthSession` for the subject AND denylist device-cert serials (no proto change). Optional `RevokeAuthSession(user, idHash)` for parity.
- Cert format / `WhoAmIResponse` / `OIDRolesExt` **unchanged** — device-issued certs are byte-identical in shape to former Login certs.

### Store (`internal/controller/store.go`)
- **New GLOBAL buckets** in `OpenStore`'s create loop: `sessions_auth` (key `sha256(token)`), `device_codes` (key `sha256(device_code)` + `UserCodeHash`→`DeviceHash` index), `handoff_codes` (key `sha256(code)`).
- **New per-ws child** `childMembers="members"`.
- **Types:** `AuthSession`, `MemberRecord`, `DeviceGrant`, handoff record.
- **Methods:** `PutAuthSession`/`GetAuthSession`(byHash)/`DeleteAuthSession`/`ListAuthSessions`/`RevokeAuthSessionsForUser`/`SweepExpiredAuthSessions`; `PutMember`/`GetMember`/`ListMembers`/`DeleteMember`/`ListMemberWorkspaces`/**`UpsertFirstAdmin`** (atomic); device `PutDeviceGrant`/`GetDeviceGrantByUserCode`(constant-time)/`ApproveDeviceGrant`/**`RedeemDeviceGrant`** (single `Update`, issues cert inside txn); handoff `PutHandoffCode`/`RedeemHandoffCode` (single `Update`, single-use).
- **One `hashKey()` helper; never persist cleartext** (grep test in e2e — RT-noted).

### OpenStack (`internal/controller/openstack.go`)
- **`PasswordLogin(ctx, username, password, domainName, project)`** on `openstackClient` + `cloudVerifier`: gophercloud `tokens.Create`, project-scoped, returns `osCaller{UserName, ProjectID, ProjectName, Roles, ExpiresAt, ScopeType, IssuerHost}`.
- **Extend `osCaller`** to surface **scope type** (`project`/`domain`/`system`), service-ness (the Keystone `service` role / app-cred flag), and the **issuing keystone host** — currently discarded (needed for #9/#10/#13/#20).
- **`validateHumanKeystoneToken(osCaller, cl)`** helper: #9 (reject `ProjectID==serviceProjectID` / system-domain scope / service role / service-user denylist) + #10 (strict project scope) + issuer-host == svc-uid `KeystoneURL`. Fail closed. Used by **both** the login form and trusted_dashboard.

### CA (`internal/ca`)
- **Unchanged signing path.** `ca.IssueFromCSR(csr, Profile{Kind:user, Workspace, Name:subject, TTL:min(CertTTL.User, until(UpstreamExp)), Claims{Roles:stripReservedRoles(...), Provider:"device:"+provider}})` is called inside the device-redeem txn.
- **Cert URI:** bake the provider + stable subject into the URI name (`geneza://user/<ws>/<provider>:<subject>`) and add a provider claim, so the gRPC plane and session-ownership checks distinguish `keystone:alice` from `oidc:alice` (RT-F12).

---

## 5. Security requirements checklist (every red-team mitigation as a MUST)

**Numbered guards (carried forward):**
- **#9 — Service-token reject (MUST):** gate on **resolved `serviceProjectID` (UUID), not project name**; also reject system/domain-scoped tokens, the Keystone `service` role, and known service usernames; **fail closed** if scope/service fields are absent. (RT-F20). One `validateHumanKeystoneToken` helper for login form + trusted_dashboard.
- **#10 — Require project scope (MUST):** assert **strict `project` scope type** from the validation response, not merely `ProjectID != ""`. (RT-F21).
- **#16 — TTL cap + revocation propagation (MUST):** `ExpiresUnix = min(now+TTL, upstreamExp)` **and** device-cert TTL `= min(CertTTL.User, until(UpstreamExp))` for **all** providers (RT-F26). **MUST** run a **keystone-revocation reaper** in the continuous-authz sweep: re-validate each keystone-provider session's stored `KSTokenHash`(or app-cred) against Keystone; on 401/404/role-loss → `DeleteAuthSession` + `RevokeCert(serial)` (RT-F1/RT-F25-sweep). The static cap is the floor; live revocation is the ceiling.

**New structural MUSTs (red-team RT-F1…RT-F26):**

| # | MUST |
|---|---|
| RT-F1 | Web-shell WS **MUST NOT** carry the session bearer in `?token=`. Mint a 30–60s **single-use, node+user-scoped WS ticket** via `POST /api/v1/nodes/{id}/shell-ticket` (Bearer-authed); WS URL carries `?ticket=`; `handleShell` redeems it in one `Update`. Plus nginx `log_format` masking `token=`/`ticket=` query + `Cache-Control: no-store`. |
| RT-F2 | Trusted_dashboard handoff: `Referrer-Policy: no-referrer` on the `/?handoff=` response; bind the code to a one-time `HttpOnly+Secure+SameSite=Strict` cookie (both required at `/session/handoff`); `Cache-Control: no-store`; SPA `replaceState` clean **first synchronous action**. |
| RT-F3 | Device grant **MUST NOT** persist `CertPem`. Issue the cert **inside** the redeem `Update` txn from CSR + frozen approval tuple. |
| RT-F4 | Ship CSP `default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'` (widen `connect-src` only to the OIDC issuer if discovery is browser-side). Verify the Vite bundle is self-contained. Sliding idle TTL (`LastSeenUnix`); soft UA fingerprint audit; **WS `CheckOrigin` MUST validate origin** (currently `true`). |
| RT-F5 | `/openstack/{svc-uid}` **MUST refuse to read/parse/log/echo any `token` query param**; POST form field only. |
| RT-F6 | Web shell **MUST be revocation-aware**: the `runWebShell` goroutine re-reads the `AuthSession` every 15–30s and closes the WS on `Revoked`/expiry/`UpstreamExp` lapse; wired into the continuous-authz sweep. |
| RT-F7/F22 | Device approval **MUST require the human to TYPE the `user_code`** (no one-click from `verificationUriComplete`); show client_name + source IP + timestamp; rate-limit `/device/authorize` per IP + global; audit every approve/deny; `user_code` TTL ≤10m. |
| RT-F8 | Cert bound to the **approving** session (CLI supplies only CSR); confirmation screen names workspace + roles + source IP loudly; device certs get shortest viable TTL + enumerable "active CLI credentials" view with one-click revoke. |
| RT-F9 | JSON `/api/*` **MUST stay Bearer-only** (no cookie honored as ambient authority). The trusted_dashboard POST landing **MUST show who you're logged in as** (login-CSRF visibility); handoff cookie consumed **only** at `/session/handoff`, never as an `/api` carrier. |
| **RT-F10** | **`stripReservedRoles` MUST strip BOTH `platform-admin` AND `admin`** on every tenant-derived path (resolveRoles/rolesForMember/role_map/keystone-first-user). Introduce `roleWSAdmin="ws-admin"` accepted by console `authAdmin` but **structurally absent** from the gRPC `AdminAPI` switch. **HARD-FAIL config load** if any `role_map` value is `admin`/`platform-admin`. Regression test: a device cert from a keystone-first-user approval **never** carries `admin` and is rejected by the `AdminAPI` gate. *(CRITICAL)* |
| RT-F11 | First-user=ws-admin **MUST** be the atomic `UpsertFirstAdmin` (single `Update`, check-empty-and-write). Fold create-ws + put-binding + first-admin into one logical/ idempotent transaction. |
| RT-F12 | Member key + cert URI + session authz **MUST** use the **stable provider subject id**, not the display name; carry provider into the URI (`<provider>:<subject>`); policy bindings provider-qualified; **reject usernames containing `:`** at `authenticate()` (fail closed). |
| RT-F13 | Trusted_dashboard **MUST** assert the validated token's **issuing keystone == the svc-uid's `KeystoneURL`**; config-load **MUST** forbid two cloud entries sharing `KeystoneURL`+`service_project` unless deliberately namespaced. |
| RT-F14 | Human auto-provision **MUST** be gated behind `allow_human_auto_provision` (default false), **distinct** from VM-enrollment `auto_provision`. No empty-cloud-init fallback for humans (403). Audit every human auto-join. |
| RT-F15 | `RevokeUser` **MUST** fan out to **both** auth-sessions **and** cert serials. |
| RT-F16 | `/device/approve` **MUST** ignore client-supplied workspace/roles; recompute via `rolesForMember(pickedWS, …)` and assert `pickedWS ∈ workspacesForUserStore(approver)`; cap cert TTL by `UpstreamExp`. |
| RT-F17 | Handoff + device redeem-once **MUST** be a single bbolt `Update` (read-check-write atomic); codes hashed at rest; handoff code 256-bit (not the 40-bit user_code). |
| RT-F18 | `AuthSession.Workspace` **MUST** be set only from server resolution; a client `workspace` selector is permitted **only** as a choice among validated candidates; test: foreign workspace → 403. |
| RT-F19 | **MUST** resolve roles strictly against `rec.Workspace`'s policy/membership, **never** `s.policy()`/`defaultWorkspace`; delete the default-policy/hardcode path; `Admin` means ws-admin-in-THIS-workspace; test: ws-admin in A → 403 on any mutation resolving to B. |
| RT-F23 | Device endpoints **MUST** be mounted on the main `:7402` HTTPS listener too (CLI login works with console disabled). |
| RT-F24/F25 | `/device/{userCode}` lookup + `/device/approve` **MUST** be rate-limited/locked per session+IP (not just the CLI poll); `GetDeviceGrantByUserCode` constant-time + single-active-per-issuer; approval bound to the session that fetched the activate page. |
| RT-DoS | Device flow on HTTP/JSON (not new cert-less gRPC); per-IP + global pending-grant caps; cheap format pre-checks before hitting Keystone; server-enforced `slow_down` in the same `Update`. |

---

## 6. Default keystone→geneza role map + auto-provisioned default policy + first-user=ws-admin

**Default keystone→geneza role map** (`mapKeystoneRoles`, applied when `role_map` omits an entry; **LEAST PRIVILEGE** — RT-F21):

```
keystone "admin"   -> ws-admin    (workspace admin; satisfies console authAdmin; NEVER the cluster gRPC admin)
keystone "member"  -> ws-viewer   (DEFAULT FLOOR: read-only; interactive shell requires an explicit
                                    operator mapping of a deliberate keystone role -> ws-member)
keystone "reader"  -> ws-viewer
default_role (no mapped role)      -> ws-viewer
```
`admin`/`platform-admin` are **never** emitted; `stripReservedRoles` enforces this structurally even on misconfig (RT-F10). `session:*` (interactive shell) is **never** granted by the blanket keystone `member` role — operators must opt a deliberate role into `ws-member`.

**First-user=ws-admin rule (R2):** in `resolveAccessWorkspace`, when the project is **unbound** and `allow_human_auto_provision=true`: `ensureWorkspace` + `PutSourceBinding(osProjectBindingKey(svc, projectID))` + `registerDynamicWorkspaceAuto` + **`UpsertFirstAdmin`** (atomic). The first human becomes `MemberRecord{Roles:["ws-admin"], AddedBy:"auto:keystone:first-user"}` — **`ws-admin` only, never `admin`**. Every subsequent user maps via `role_map`. A loser of the race reads non-empty → mapped normally. Bound projects map all logins via `role_map` (no auto-admin). Symmetric with VM enrollment (which auto-provisions the tenant but adds no human).

**Default auto-provisioned-workspace policy** (`auto_provision_policy_file`, role-NAME granting, **NO bindings** — works because `policy.Static.Evaluate` honors `in.Roles` directly when non-empty, verified `policy.go:180-183`). **Use the schema-correct YAML shape** (`actions`/`node_labels`/`service_kinds` — Design 1's verified form, the panels' explicit correction over Designs 2/3's illustrative non-schema strings):

```yaml
roles:
  ws-admin:
    allow:
      - actions: ["*"]
        node_labels: {"*": "*"}
      - service_kinds: [http, subnet-route]
        node_labels: {"*": "*"}
  ws-member:
    allow:
      - actions: [shell, exec, attach, connect, vpn]
        node_labels: {"*": "*"}
        max_session_ttl: 8h
      - service_kinds: [http, subnet-route]
        node_labels: {"*": "*"}
  ws-viewer:
    allow:
      - actions: [attach]                # read-only reattach/observe; NO new shells
        node_labels: {"*": "*"}
        max_session_ttl: 1h
bindings: []                             # roles come from store membership (Input.Roles), not bindings
```
`registerDynamicWorkspaceAuto` loads **this** file (not `cfg.PolicyFile` — fixes the verified `server.go:308` bug where auto-provisioned workspaces loaded the wrong binding policy). `platform-admin` and `admin` are never present here; even if mis-added, `stripReservedRoles` removes them before any cert/session use.

---

## 7. PHASED BUILD PLAN

Ordered so the **riskiest foundation lands first** (store-backed membership + opaque session model + reserved-`admin`), each phase is independently committable and e2e-testable, and every later phase builds on green. `state.db` is dropped at Phase 0 (greenfield). Each phase lists exact files + the e2e assertion that proves it.

> **Branch discipline:** work on `wip` (per memory: empty `main`, no AI/Co-Authored-By annotations on Geneza commits). Keep `scripts/e2e.sh` (35 checks) and `openstack-e2e.sh` green at every phase boundary — they are the lab-green contract.

### Phase 0 — Greenfield reset + reserved-`admin` (the critical security floor)
**Why first:** RT-F10 (critical) is a one-line-conceptual but load-bearing change; landing it before any tenant role path exists guarantees no path can ever emit `admin`.
**Files:** `internal/controller/auth.go` (extend `stripReservedRoles` to strip `roleAdmin` + `platform-admin`; add `roleWSAdmin="ws-admin"` const), `internal/controller/config.go` (HARD-FAIL load if any `role_map` value is `admin`/`platform-admin`; forbid duplicate `KeystoneURL`+`service_project`), drop `state.db`.
**E2E assertion:** unit test — `stripReservedRoles(["admin","ws-admin","platform-admin","ws-member"]) == ["ws-admin","ws-member"]`; config-load test — a `role_map: {admin: admin}` cloud **fails to start** with a clear error. `scripts/e2e.sh` still green (no behavior change to existing paths).

### Phase 1 — Store-backed membership (the data foundation)
**Why second:** everything resolves roles/workspaces through this; it must be correct and atomic before any login path consumes it.
**Files:** `internal/controller/store.go` (`childMembers` bucket; `MemberRecord`; `PutMember`/`GetMember`/`ListMembers`/`DeleteMember`/`ListMemberWorkspaces`/**`UpsertFirstAdmin`**), `internal/controller/server.go` (`workspacesForUserStore(provider,subject,groups)` = config ∪ store; `rolesForMember(ws,provider,subject,groups)` = `stripReservedRoles(store ∪ policy)`, provider-qualified — RT-F12).
**E2E assertion:** store unit test — two concurrent `UpsertFirstAdmin` on an empty members bucket yield **exactly one** `ws-admin`, the loser is `role_map`-mapped (RT-F11); `keystone:alice` and `oidc:alice` coexist as distinct rows with independent roles (R3); cross-tenant `GetMember` returns `NotFound`. `rolesForMember` never returns `admin`.

### Phase 2 — Opaque session model + console carrier swap
**Why third:** replaces per-request id_token verification with the bbolt session; unblocks all three login endpoints.
**Files:** `internal/controller/store.go` (`sessions_auth` bucket, `AuthSession`, `Put/Get(byHash)/Delete/List/RevokeForUser/SweepExpired`, `hashKey()`), `internal/controller/console.go` (delete OIDC hard-require + single-verifier field; rewrite `authenticate`/`authenticateToken` → hash bearer → `GetAuthSession` → build `consoleUser` from record only, **no `defaultWorkspace`/`s.policy()`** — RT-F19; add CSP header — RT-F4), `internal/controller/server.go` (session-sweep goroutine; `RevokeUser` fans out to sessions + cert serials — RT-F15).
**E2E assertion:** a minted `AuthSession` authenticates `/api/v1/session`; `DeleteAuthSession` → next call 401; the bbolt row key is `sha256(token)` (grep test: no cleartext token in the DB — RT-noted); a ws-admin in workspace A gets **403** mutating a target in B (RT-F19); expired session swept.

### Phase 3 — Local + OIDC login endpoints (browser unification, no keystone yet)
**Why fourth:** proves `establishSession` + the SPA login form end-to-end on the two providers that need no new OpenStack code.
**Files:** `internal/controller/console_session.go` (NEW: `POST /session/{local,oidc}`, `GET`/`DELETE /session`; shared `establishSession` + `mintAuthSession`; workspace selector validated against candidates — RT-F18), `internal/controller/identity.go` (export `authenticateLocal`/`authenticateOIDC`), `web/src/auth.ts` (keep PKCE to OBTAIN id_token; POST once to `/session/oidc`, discard; carrier = opaque session in sessionStorage Bearer), `web/src/api.ts` (Bearer from `getToken`; 401 → login), `web/src/pages/login.tsx` (conditional render from `/api/v1/config`), `web/src/components/auth-gate.tsx` (probe `/session` bootstrap), `web/src/types.ts`.
**E2E assertion:** browser-driven (or curl) — local login → session cookie-less Bearer → `/api/v1/config` 200; OIDC PKCE callback → POST id_token → session; logout → 401; posting a **foreign workspace** → 403 (RT-F18). `scripts/e2e.sh` updated for cookie-less Bearer console + green.

### Phase 4 — Keystone access plane (PasswordLogin + guards #9/#10 + auto-provision)
**Why fifth:** the highest-risk new surface; lands on a green session+membership base.
**Files:** `internal/controller/openstack.go` (`PasswordLogin`; extend `osCaller` with scope type/service-ness/issuer host; `validateHumanKeystoneToken` — #9 on `serviceProjectID` UUID/scope/service-role/fail-closed RT-F20, #10 strict project scope RT-F21), `internal/controller/access.go` (NEW: `resolveAccessWorkspace` — binding-or-auto-provision gated by `allow_human_auto_provision` RT-F14, `UpsertFirstAdmin` writes **ws-admin only**), `internal/controller/server.go` (`registerDynamicWorkspaceAuto` loads `auto_provision_policy_file` — fixes `server.go:308`), `internal/controller/console_session.go` (`POST /session/keystone`), `config.go`/`web` login form keystone card, ship `policy-autoprovision.yaml`.
**E2E assertion (on kolla1):** keystone password login → project-scoped session; a **service token** (project=`service`/system-scoped/service-role) → **403** even if the service project is renamed (RT-F20); an unscoped/domain token → 403 (RT-F21); first human into an unbound project under `allow_human_auto_provision=true` → new workspace, that user is **ws-admin** (and `ws-admin` is **rejected** by the gRPC `AdminAPI` gate — RT-F10); with the flag **false**, an unbound project → 403 (RT-F14).

### Phase 5 — RFC 8628 device grant (CLI rewrite)
**Why sixth:** depends on `rolesForMember` + membership (Phase 1/4) for the approver's roles; replaces the CLI credential middle.
**Files:** `internal/controller/store.go` (`device_codes` bucket; `PutDeviceGrant`/`GetDeviceGrantByUserCode`(constant-time)/`ApproveDeviceGrant`/`RedeemDeviceGrant` — cert issued **inside** redeem txn, no `CertPem` at rest RT-F3), `internal/controller/console_device.go` (NEW: `/device/{authorize,token,approve,deny}`, `/device/{userCode}`; type-the-code RT-F7, recompute+assert workspace RT-F16, rate-limit/lockout RT-F24/F25, mounted on `:7402` too RT-F23), `internal/controller/server.go` (`issueUserCert` extracted from `handleLogin`; TTL `min(CertTTL.User, until(UpstreamExp))` RT-F26), **proto: delete `UserAPI.Login`**, `auth.go` (drop the cert-less `Login` special-case → Enrollment-only), `cmd/geneza/login.go` (device flow; keep CA-trust head + CSR + cert/profile tail; drop `--provider`/`--user`/`--password-*`/`--manual`), **DELETE `internal/client/oidc.go`**, `internal/client/device.go` (NEW), `web/src/pages/activate.tsx` (NEW eager route).
**E2E assertion:** `geneza login` → device code → human approves in console (typing the code) → CLI receives a cert whose URI carries `<provider>:<subject>` and `ws-admin`/`ws-member` (never `admin`); the cert authenticates the gRPC plane; a **second** `/device/token` poll on a redeemed code → `expired_token` (RT-F17); a DB read between approve and redeem yields **no cert** (RT-F3); approving for a workspace the approver isn't a member of → rejected (RT-F16); console-disabled deployment still logs in via `:7402` (RT-F23). `openstack-e2e.sh` updated to drive the device flow + green.

### Phase 6 — Trusted dashboard handoff (R4)
**Why seventh:** depends on Phase 4's keystone guards + Phase 2's session + handoff store.
**Files:** `internal/controller/store.go` (`handoff_codes` bucket, single-use redeem RT-F17), `internal/controller/console_trusted_dashboard.go` (NEW: `POST /openstack/{svc-uid}` form-POST only RT-F5, `validateHumanKeystoneToken` #9/#10, issuer-host==svc-uid RT-F13, 303 to `?handoff=` with `no-referrer`+`no-store`+bound `SameSite=Strict` cookie RT-F2, `POST /session/handoff`), `web/src/components/auth-gate.tsx` (`?handoff=` → `replaceState` first → POST handoff; landing shows logged-in identity RT-F9).
**E2E assertion (Horizon websso on kolla1):** websso form-POST → 303 to clean `/?handoff=<code>` (keystone token **never** in any URL/log/Referer — RT-F5/F2); the SPA swaps the code for a Bearer and the URL is clean; a replayed handoff code → `expired_token` (RT-F17); a token whose issuing keystone ≠ svc-uid's → rejected (RT-F13); a `GET …?token=` is refused without parsing/logging (RT-F5).

### Phase 7 — Live-revocation hardening (close the long-lived-tunnel + keystone-deboard gaps)
**Why last:** correctness-completing layer over a fully green broker; touches the continuous-authz sweep that every prior phase relies on.
**Files:** `internal/controller/console_shell.go` (revocation-aware `runWebShell`: re-read `AuthSession` every 15–30s, close WS on revoke/expiry/`UpstreamExp` lapse RT-F6; `CheckOrigin` validates origin RT-F4; **WS one-time ticket**: `POST /api/v1/nodes/{id}/shell-ticket`, `?ticket=` redeemed transactionally RT-F1), `internal/controller/continuousauthz.go` (**keystone-revocation reaper**: re-validate `KSTokenHash` against Keystone on the reauth tick → `DeleteAuthSession` + `RevokeCert(serial)` on 401/404/role-loss — completes #16's "propagate" half RT-F1/F26), nginx `geneza-console.conf` (`log_format` masks `token=`/`ticket=`/`?token`; `no-store`).
**E2E assertion:** open a web shell, admin `RevokeUser` → the **live shell closes within 30s** (RT-F6) and the CLI cert serial is denylisted (RT-F15); deboard a keystone user at Keystone → their Geneza session **and** device cert are killed on the next reauth tick (RT-F1); nginx access log of a shell-open contains **no** session token (RT-F1); the WS rejects a cross-origin upgrade (RT-F4).

---

**Net surface:** ~6 new backend files (`console_session.go`, `console_device.go`, `console_trusted_dashboard.go`, `access.go`, + store/openstack extensions), edits to `console.go`/`server.go`/`identity.go`/`auth.go`/`config.go`/`openstack.go`/`continuousauthz.go`/`console_shell.go`, proto regeneration (delete `UserAPI.Login`), 3 new bbolt global buckets + 1 per-ws child, the SPA login/activate/auth-gate changes, the CLI device rewrite (`oidc.go` deleted), and the two e2e scripts updated. Every phase boundary is green, committable, and proves a named red-team mitigation.