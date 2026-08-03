# Hosted-UI launch — design spec

**Status:** IMPLEMENTED (2026-08-02), unit-tested, not yet validated against a
real Horizon. It extends the access plane (`docs/openstack-integration.md` §13,
`docs/auth-broker-spec.md`), which is built and live — Horizon websso already
hands a human a *full workspace* console session via `POST /openstack/{svc}` →
single-use handoff code → `POST /api/v1/session/handoff`
(`internal/controller/{console_trusted_dashboard,handoff}.go`).

Operator wiring is in [`hosted-ui-launch-guide.md`](hosted-ui-launch-guide.md);
a working Horizon panel is in
[`deploy/openstack/horizon-geneza-console/`](../deploy/openstack/horizon-geneza-console/README.md).
§14 records where the build deviates from the design below.

**The gap this closes.** A cloud provider wants a **Console** button next to each
VM in its own tenant portal: one click, live shell on *that* VM, no Geneza login,
no install. Today the only launch we have is all-or-nothing — it lands the tenant
in the whole console with every role their project maps to. A per-VM button built
on that would be a privilege escalation dressed as a convenience.

The one-line version: **a launch is authenticated by the tenant's own upstream
credential, and the scope it yields is pinned server-side at mint time.**

---

## 1. Two launch kinds, one mechanism

| Launch | Authenticated with | Yields | UI |
|---|---|---|---|
| **Project** (exists today) | project-scoped Keystone token | workspace session, role-mapped | full console |
| **Instance** (this spec) | same token **+** instance UUID | **node-scoped** session | embed shell only |

This is the "depending on how the hosted UI was authenticated" axis, made
explicit. The invariant that makes it safe:

> **Scope narrows, never widens.** Effective authority = policy(user's roles) ∩
> scope. The scope lives in the server-side session record, never in the URL, so
> the browser cannot edit it. A launch can only ever be *less* than what the same
> human gets by logging into the console directly.

---

## 2. Rule zero: the portal is a presenter, never an authority

The obvious API — "provider POSTs `{user: alice, instance: i-123}` with its own
API key" — is rejected. It would make every provider portal a fleet-wide
impersonation oracle: one leaked key mints a shell as any tenant on any VM, at
any time, with no upstream credential involved and nothing to expire.

Instead the launch call carries **the tenant's own Keystone token**, validated by
the same per-cloud verifier the trusted-dashboard path uses
(`c.s.clouds[svcUID].Validate`). The portal can therefore only launch for users
who are *currently signed in to it* — which is authority it already has. A
compromised portal gains nothing it did not already hold, and the blast radius is
bounded by Keystone's own token TTL.

This also means no new credential type, no key distribution, no key rotation
story, and no config knob whose default is dangerous.

---

## 3. Flow (instance launch)

```
Tenant portal (Horizon panel)                 Geneza controller
  │ user clicks "Console" on VM i-123
  │ POST /openstack/{svc}/launch  ───────────▶ validate keystone token (that cloud)
  │   {token, instance_id, action:"shell"}     validateHumanKeystoneToken (#9/#10)
  │   (server-to-server, TLS, token in body)   resolveAccessWorkspace → ws + roles
  │                                            resolve instance → node (§4)
  │                                            policy dry-run (advisory, §5)
  │ ◀─── {launch_url, expires_unix} ────────── mint LaunchTicket (single-use, 60s)
  │
  │ renders <a target=_blank> (default)
  │     or  <iframe src=…>       (opt-in, §7)
  ▼
Browser ──▶ GET /embed/shell#lc=<code>       (fragment: never in Referer or a log)
  │ SPA POSTs the code
  │ POST /api/v1/session/launch ────────────▶ RedeemLaunch: atomic, single-use
  │ ◀─── {token, scope} ────────────────────  mint AuthSession{Kind:"launch", Scope}
  │ token held in a JS variable — never localStorage, never a cookie
  ▼
  existing POST /nodes/{id}/shell-ticket → GET /nodes/{id}/shell (WS) → unchanged
```

Everything downstream of the redeem is the console's existing web-shell path:
`CreateSessionWeb` with `client_path=web`, Noise tunnel via `client.DialSession`,
PTY bridged to xterm, agent-side policy re-check, agent-side recording. **The
agent is unchanged and does not know a launch happened.**

### Two secrets where the browser allows it, one where it does not

The existing trusted-dashboard handoff pairs the code with an `HttpOnly` cookie:
a double secret, so a leaked URL is useless alone. **The top-level launch keeps
that property**, via a two-stage flow — the portal's URL points at
`GET /launch?lt=<code1>`, which burns `code1` and hands the browser a *fresh*
code in the fragment plus its companion cookie, minted together. Stage one is
single-use, so `code1` appearing in an access log is spent by the time anyone
reads it.

The **embed** path cannot do this. A framed page is a third-party context, where
the cookie write is blocked outright by Safari's ITP and Chrome's phase-out —
requiring one would not harden the flow, it would break it. So embed launches
carry a single secret, compensated by:

- the code lives in the **URL fragment** — not sent to any server, absent from
  the controller's access log, the portal's proxy log, and every `Referer`;
- **single-use** with a ≤60s TTL, burned on *any* redeem attempt (the existing
  `RedeemHandoff` already deletes on a failed-secret redeem — same semantics);
- the redeem is a **POST** with an `Origin` matching the console's own origin;
- the minted session is **scoped** (§6), so even a successful theft yields a
  terminal on one VM the thief's victim already controls, for one short session,
  fully audited and killable.

### On CSRF specifically

A cookie is not the CSRF defence here, and adding one for that purpose would be
a regression. CSRF exists *because* cookies are ambient — the browser attaches
them to any request an attacker's page can cause. The session token is a Bearer
header held in a JavaScript variable, so a foreign page can make the browser
issue a request to the console origin but cannot make it carry a header it does
not know. There is nothing to forge. The console made this choice deliberately
(`session.go`: "sessionStorage, not a cookie → no CSRF surface"), and the launch
plane keeps it: `geneza_launch` is consumed once at redeem and is never, at any
point, sufficient to authenticate a request on its own.

So the cookie's job is narrow and worth stating exactly: it makes the fragment
code insufficient by itself, which defends the leak paths a fragment still has —
browser history, a screenshot, a shared session recording of the tenant's own
screen. It does not defend against script running in the framing page, which
can drive the authenticated frame directly whatever the cookie policy is.

---

## 4. Resolving an instance UUID to a node — two independent checks

The portal names a **Nova instance UUID**; Geneza addresses **nodes**. The
mapping already exists: `vendordata.go:304` stamps the trusted labels
`os:project` and `os:instance` at enrollment (namespaced per §7/#7 — tenant hints
live under `os.claim:` and can never reach this path).

Resolve requires **both** to hold, and fails closed:

1. a node in the **resolved workspace** whose `os:instance` == the requested
   instance UUID; **and**
2. that node's `os:project` == the **token's** authoritative project ID.

Check 2 is not redundant with check 1. Workspaces may bind many projects (§6 of
the integration spec), so "in my workspace" is strictly weaker than "in my
project" — without it, one project's tenant could open a shell on a co-bound
project's VM. A node with no `os:instance` label (enrolled outside the OpenStack
plane) is not launchable, by construction.

---

## 5. Mint-time policy dry-run (advisory)

Before returning a URL, evaluate the broker's policy for
(identity, node, `shell`, `client_path=web`) and 403 the *mint* if it would be
denied. This is a UX property, not a security one — it lets the portal grey out
the button instead of handing the tenant a link that dies three seconds later.

It is explicitly **advisory**: the authoritative checks stay where they are — the
broker at session creation and the **agent** at session honor. A `require_native`
rule, a quarantined node, or a suspension landing between mint and redeem still
denies. Never let the dry-run become the decision.

---

## 6. The scoped session — where containment actually lives

New session kind alongside `tenant`/`cluster` (`internal/controller/session.go:92`):

```go
sessionKindLaunch = "launch"

// SessionScope pins a launch session to exactly what the launch authorized.
// Empty NodeID means workspace-wide (the existing project launch).
type SessionScope struct {
    NodeID  string   `json:"node_id,omitempty"`
    Actions []string `json:"actions,omitempty"` // ["shell"]; later "agent"
    Embed   bool     `json:"embed,omitempty"`   // served framed; §7 applies
    Origins []string `json:"origins,omitempty"` // allowed frame-ancestors
}
```

Three enforcement layers, each independently sufficient for its own failure mode:

1. **Route allowlist, inverted into the default gate.** Rather than keep a list
   of permitted paths, the ordinary `auth()` middleware *refuses* any session
   carrying a scope, and a separate `authScoped()` wrapper is applied to the few
   routes an embedded shell needs (`GET|DELETE /api/v1/session`,
   `POST /nodes/{id}/shell-ticket`; the shell WebSocket authenticates by ticket
   and re-checks the scope itself). Everything else 403s, *including endpoints
   the user's own roles would permit*. This is the allowlist property without a
   list to maintain: a route added next year inherits `auth()` and is therefore
   denied to launch sessions until someone deliberately opts it in.
2. **Node pin.** Every `{id}` on an admitted route must equal `Scope.NodeID`.
   (`handleShellTicket` already scopes its WS ticket to a node — this pins the
   ticket-mint itself one step earlier.)
3. **Action pin.** The broker call may only carry an action in `Scope.Actions`.

Plus, unconditionally: `Admin` is forced **false** on a launch session, even for a
ws-admin. The user keeps their roles for policy evaluation on the one node they
were launched into, and gets zero console mutation authority. **A one-click VM
console must not be a back door into the workspace** — that is the whole point of
the kind.

### Lifetime: an idle window under an absolute ceiling

A single fixed TTL is wrong for a shell. Too short and a tenant is cut off
mid-debug; too long and an abandoned tab holds a live session all night. So a
launch session has two bounds:

- **Idle window** — `launch.max_session_ttl` (default 15m). The embed UI calls
  `POST /api/v1/session/renew` on a timer while the shell is attached, sliding
  the expiry forward. An attended session keeps going; an abandoned one lapses
  one window after the browser stops asking.
- **Absolute ceiling** — `launch.absolute_ttl` (default 8h), stamped onto the
  session at mint as `MaxExpiresUnix` and *already folded together with the
  Keystone token's expiry*, so renewal arithmetic cannot get it wrong later.
  Renewal clamps to it and never passes it.

Renewal is a **re-authorization, not a rubber stamp**: `renewSession` re-reads
the record and re-checks revocation, expiry, and suspension before extending, so
a kicked or suspended principal's timer stops immediately. When the ceiling is
reached the tenant re-launches from the portal — which re-validates their
Keystone token and re-runs policy, which is the point of having a ceiling at all.

Renewability is gated on `MaxExpiresUnix != 0`, which only a scoped mint sets.
An ordinary console session is therefore structurally non-renewable — this
endpoint cannot become a way to hold a full console open forever.

---

## 7. Embedding — opt-in, per cloud

Today `secHeaders` (`console.go:154`) sets `X-Frame-Options: DENY` globally. That
stays for the entire console. Only the `/embed/*` routes are framable, only when
the cloud opts in, and only from named origins:

- `Content-Security-Policy: frame-ancestors <exact origins>` on `/embed/*`, with
  `X-Frame-Options` omitted for those routes only (the two headers conflict; CSP
  is the one with a source list).
- Origins are **exact** scheme+host[:port]. No wildcards, no bare hosts, no `*`.
  Config load rejects anything else — this is the entire anti-clickjacking story
  and it must not be softenable by a typo.
- The WS `checkShellOrigin` pin (`console_shell.go:36`) is unchanged and still
  correct: the framed document *is* console-origin, so it passes, while an
  arbitrary page still cannot open a shell socket.
- **Top-level (`target="_blank"`) is the default and the recommendation.** It is
  first-party, immune to framing questions entirely, and shows the tenant a real
  origin in a real address bar — which is worth more than the visual polish of an
  inline panel. Embedding is for providers who insist.

The embed UI is a new SPA route (`/embed/shell`, outside `AuthGate`) rendering
the existing `<WebShell>` component with no nav, no workspace switcher, no links
out — a terminal and a status line.

Note what that does and does not buy: the framed page renders no console UI and
its session is refused by every console API, but the SPA still ships as one
bundle, so the console's *code* is present in the frame. The containment is
server-side and does not depend on what the browser downloaded. Code-splitting
the embed route is a worthwhile follow-up for load time; it is not a security
boundary and should not be described as one.

**Where the CSP list comes from.** `frame-ancestors` must be on the *document*
response, but the launch code is in the fragment and therefore invisible to the
server at that moment. So the launch URL carries a `?cloud=<svc-uid>` query: a
routing hint that selects which allow-list to serve and authenticates nothing —
the same routing≠auth split the `svc-uid` path already uses. An unknown cloud, a
cloud with embedding off, or a missing hint all fail closed to
`frame-ancestors 'none'` plus `X-Frame-Options: DENY`.

---

## 8. Revocation, expiry, audit

A launch session is an ordinary `AuthSession`, so everything already built
applies with no new code: `geneza kick` deletes it, suspension is caught on the
next check, and the 15s web-shell watchdog (`console_shell.go:151`) tears down
the **live PTY** on revoke / expiry / suspension / stale presence. Keystone token
expiry caps the session. Node quarantine, `require_native`, and agent-side policy
all deny independently.

New audit events (workspace-scoped, hash-chained like the rest):

- `launch_mint` — cloud, project, instance, node, action, scope, portal source IP
- `launch_redeem` — + user agent, framing origin
- then the existing `web_shell` event, unchanged

Session recording is unaffected: it happens **at the agent**, so a launched shell
records exactly like a console shell, and the record does not depend on trusting
either the proxy or the portal.

---

## 9. Threat analysis

| Adversary | Outcome |
|---|---|
| **Compromised tenant portal** | Can launch only for users whose Keystone tokens it currently holds — authority it already had. No standing credential to steal, nothing to replay after token expiry. This is rule zero (§2) doing its job; an impersonation API would instead have made it fleet-wide and permanent. |
| **Launch URL leaks** (screenshot, chat, shoulder) | Single-use, short-lived, already burned by the tenant's own tab, redeemable only from the console origin — and on the top-level flow the fragment code also needs its `HttpOnly` companion cookie. |
| **Attacker holds a live scoped session** | Bounded by the absolute ceiling as well as the idle window, and each renewal re-checks revocation and suspension — so a kick ends it at the next renewal, not at the next hour. |
| **Tenant edits the URL** to another instance UUID | Nothing to edit — the scope is server-side; `{id}` is compared to `Scope.NodeID`. |
| **Tenant re-points the launch at another cloud's `svc-uid`** | Routing ≠ auth (existing property): the token does not validate against that Keystone. |
| **Cross-project VM access** inside a shared workspace | Blocked by the second check in §4 (`os:project` == token's project). |
| **Scope escalation** — using a node-scoped session against the console API | Route allowlist + node pin + `Admin:false`, all three independent. |
| **Malicious framing page** | `frame-ancestors` allowlist (opt-in, exact origins) + WS origin pin. |
| **Stolen scoped session token** | One node, one action, ≤15m, killable by `kick`, recorded at the agent. |
| **Compromised web proxy** | Unchanged from ARCHITECTURE §6/§11 — agent re-enforces policy, records independently, and `require_native` reserves sensitive targets. |

**One honest caveat.** A tenant-facing, one-click surface widens *who* uses the
web path — from a handful of operators to every tenant with a VM. The proxy's
plaintext exposure is per-session and already inside the trust boundary, but the
volume through it goes up. The mitigation is policy, not architecture: providers
should keep sensitive workloads out of launch scope with a `require_native` rule
on the relevant labels. Say this in the operator guide rather than burying it.

---

## 10. Config surface

```yaml
clouds:
  kolla1:
    kind: openstack
    keystone_url: https://kc:5000/v3
    # ... existing fields ...
    launch:
      allow: true                # default FALSE — opt-in, like allow_trusted_dashboard
      actions: [shell]           # allow-list; "agent" arrives later
      ticket_ttl: 2m             # redemption window ONLY (cap 15m at load)
      max_session_ttl: 15m       # IDLE window; renewal slides it forward
      absolute_ttl: 8h           # ceiling renewal can never pass (cap 7d)
      embed:
        allow: false             # iframe embedding, separately opt-in
        frame_ancestors:         # exact origins only; validated at load
          - https://horizon.example.com
```

Both gates default false and are independent: a provider can ship the launch
button in a new tab without ever allowing their portal to frame Geneza.

---

## 11. Beyond OpenStack

The launch endpoint is per-cloud-verifier, so it rides the same seam §14 of the
integration spec defines for multi-cloud: any credential Geneza already validates
(Keystone today; a signed instance identity or an OIDC id_token under the same
interface) can authorize a launch. The instance→node resolution generalizes with
it — `os:instance` becomes `<kind>:instance` against the same trusted-label rule.

An OIDC-authenticated launch is the same object with a different verifier, which
is what makes this mechanism the answer for "a hosted UI, authenticated however
the provider authenticates" rather than an OpenStack-only feature.

---

## 12. Forward: the agentic session

The same ticket with `action: "agent"` and `Scope.Actions: ["agent"]`; the embed
route swaps xterm for the agent pane. One thing to decide **before** building it:

> `agent` must be its own policy action, never folded into `shell`.

A human at a prompt and an LLM driving that prompt are different risks and belong
to different grants. Getting the action split right now costs one enum value;
retrofitting it after providers have written policy costs a migration.

---

## 13. Deviations from this design, as built

Three, all recorded because they change how you read the sections above.

**The ticket reuses the handoff store, discriminated by scope.** §6 implied a new
`LaunchTicket` table. Instead a launch ticket is a `HandoffRecord` in the
existing `handoff_codes` bucket/table — no schema change, no migration, and the
atomic single-use redeem is already proven there.

What keeps the three redeem paths apart is the **scope**, not the cookie. That
distinction is load-bearing and was a real trap: once the top-level flow gained
a companion cookie, a bound launch ticket looks exactly like a trusted-dashboard
handoff to any cookie-based test — and `RedeemHandoff` mints an *unscoped*
session, so letting one through would silently promote a one-node launch to a
full workspace console. `RedeemHandoff` therefore refuses any record with a
scope; `RedeemLaunch` and `RedeemLaunchBind` refuse any without one, and split
the remainder on whether the cookie leg is present. Tested in
`TestHandoffAndLaunchTicketsAreDisjoint`, including that exact escalation.

**The route allowlist is inverted** into the default gate — see §6.1.

**The mint-time policy dry-run reports the engine's generic reason.** A
`require_native` rule does not *match* on the web path rather than matching and
then denying, so a reserved target's denial reads "no rule in roles […] allows
shell on node X", not "this target requires the native client". The deny is
correct and fails closed; only the message is less specific than an operator
would like. Improving it means touching the policy engine's non-match
accounting, which is out of scope here.

## 14. Build order

All six slices are built.

| | Slice | Landed in |
|---|---|---|
| R1 | `SessionScope` + `sessionKindLaunch` + the three-way ticket redeem + renewal | `session.go`, `handoff.go`, `sqlstore.go`, `store_iface.go` |
| R2 | `POST /openstack/{svc}/launch` — validate, resolve, dry-run, mint | `console_launch.go`, `config.go` |
| R3 | scoped-session default-deny + node/action pins + `POST /api/v1/session/launch` | `console.go`, `console_shell.go` |
| R4 | `/embed/shell` SPA route + per-cloud CSP `frame-ancestors` | `console.go`, `web/apps/console/{App.tsx,auth.ts,pages/embed-shell.tsx}` |
| R5 | Horizon panel sample + operator guide | `deploy/openstack/horizon-geneza-console/`, `hosted-ui-launch-guide.md` |
| R6 | Tests | `console_launch_test.go` |

The tests that back the claims above (`console_launch_test.go`): a launch
session is refused on twelve representative console routes; it cannot address a
second node; a ws-admin's launch session has `Admin == false`; a ticket cannot
be redeemed twice and cannot be redeemed cross-origin; an instance in a co-bound
project fails to resolve; the three ticket kinds refuse each other (including
the bound-launch-as-handoff escalation); a policy-denied target fails at mint;
the top-level flow needs both the fragment code and the cookie, and its bind
stage is single-use; an embed launch works cookieless; renewal extends, clamps
at the ceiling, and stops for a suspended principal, while an ordinary console
session is structurally non-renewable; `frame-ancestors` is emitted only for an
opted-in cloud and falls back to `'none'` + `DENY` otherwise; and ten config-load
gates reject a too-permissive launch block (each asserting the *launch* block is
what failed, so the case cannot pass on an unrelated error).

**Not yet done:** validation against a real Horizon + Keystone (the enrollment
plane got this in the kolla1 lab; the launch plane has not). Until then treat the
Horizon panel in `deploy/` as a reference, not a tested artifact.
