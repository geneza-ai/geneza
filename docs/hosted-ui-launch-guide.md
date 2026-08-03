# Hosted-UI launch — operator guide

How a cloud provider gives its tenants one-click access to a Geneza shell from
its own portal. The design and threat model are in
[`hosted-ui-launch-spec.md`](hosted-ui-launch-spec.md); this is the wiring.

---

## 1. What you are turning on

A **Console** button next to each VM in your tenant portal. One click opens a
live shell on that VM — no Geneza login, no install, no credential handed to
the tenant.

The button is authorized by the tenant's **own Keystone token**, which your
portal already holds because they are signed in to it. You never configure a
Geneza API key for the portal, because there isn't one: a portal that could
assert *"this request is for user alice"* would be an impersonation oracle, so
Geneza does not accept such an assertion from anyone.

---

## 2. Enable it

On the controller, per cloud in the clouds registry:

```yaml
clouds:
  kolla1:
    kind: openstack
    keystone_url: https://keystone.example.com/v3
    # ... existing enrollment / access-plane settings ...
    launch:
      allow: true              # default false
      actions: [shell]         # the only launchable action today
      ticket_ttl: 2m           # how long the URL stays spendable (max 15m)
      max_session_ttl: 15m     # IDLE window — renewal slides this forward
      absolute_ttl: 8h         # hard ceiling renewal can never pass (max 7d)
```

Both `launch.allow` and `launch.embed.allow` default to **false** and are
independent — you can ship the button as a new tab without ever allowing your
portal to frame Geneza.

The config loader rejects a launch block that would be quietly too permissive:
a non-launchable action, a ticket TTL over 5 minutes, `embed.allow` without an
explicit `frame_ancestors`, or a frame ancestor that is not an exact
`https://host[:port]` origin. These fail the **load**, not the request — this
surface is tenant-facing, so a typo must be loud.

---

## 3. Wire the portal

Your portal's backend makes one server-to-server call per click:

```http
POST /openstack/<svc-uid>/launch
Content-Type: application/json

{"token": "<the tenant's keystone token>", "instance_id": "<nova uuid>", "action": "shell"}
```

```json
{
  "launch_url": "https://geneza.example.com/embed/shell?cloud=kolla1#lc=<code>",
  "expires_unix": 1785000060,
  "node_id": "n-8f21…", "node_name": "web-01",
  "action": "shell", "online": true
}
```

Redirect the browser to `launch_url` (or set it as an `<iframe src>` in embed
mode). A working Horizon panel is in
[`deploy/openstack/horizon-geneza-console/`](../deploy/openstack/horizon-geneza-console/README.md).

**Handling of `launch_url`:** treat it as a password for that VM.

It is a **bearer credential**: it is not tied to the tenant who requested it, so
anyone holding it can spend it. What bounds that is single use — the tenant's own
click burns it, so a copy shared afterwards is dead — plus a ~2m life, one node,
one action, and an audited redeem that records the user agent and origin. In the
normal flow the code is spent milliseconds after minting, because your portal
redirects to it immediately.

This is the same model as `nova get-vnc-console` and every password-reset link,
and a tenant deliberately sharing their own URL is not an escalation — they could
equally share their screen or their Keystone password. The risk it does carry is
**accidental** exposure, so: redirect to it, and do not log it, email it, put it
in a job queue, or render it into a page. Mint on click, never on page render — a
URL sitting in your DOM is a credential you are storing.

For a top-level launch the URL points at the controller's bind endpoint, which
burns that code and hands the browser a fresh one in the fragment plus an
`HttpOnly` companion cookie — so from the tenant's address bar onward it takes
*two* secrets to replay the launch, and neither is enough alone. Mint on click
and redirect immediately; a URL minted at page render and left sitting in the
DOM is a credential you are storing.

**Error handling:** a non-200 carries a human `error` string that is safe to
show the tenant — a policy denial, an unbound project, an instance that is not
a Geneza node. Render it rather than a generic failure; it is usually
actionable ("your project is not bound to a Geneza workspace").

---

## 4. Embedding in the portal page

Default to a **new tab**. It is first-party, immune to framing questions, and
shows the tenant a real origin in a real address bar.

If you want the terminal inline, opt in on both sides — `"embed": true` in the
launch call, and the exact portal origin allow-listed:

```yaml
    launch:
      allow: true
      embed:
        allow: true
        frame_ancestors:
          - https://horizon.example.com
```

The controller then serves `/embed/*` with
`Content-Security-Policy: frame-ancestors https://horizon.example.com` and no
`X-Frame-Options`. Every other console path keeps `X-Frame-Options: DENY` — the
full console is never framable.

No cookies are used on this path, so third-party cookie blocking (Safari ITP,
Chrome's phase-out) cannot break it, and there is no ambient credential to
CSRF. The session token lives in a JavaScript variable in the frame and dies
with it.

---

## 5. What a launched tenant can and cannot do

| | |
|---|---|
| Can | Open a shell on **the one instance** the launch named, for `launch.actions` |
| Cannot | List other nodes, read audit, change policy, mint tokens, reach any other console API — **even if the same human is a workspace admin** |
| Lasts | An **idle window** (`max_session_ttl`, renewed automatically while the shell is open) under a **hard ceiling** (`absolute_ttl`), never past their Keystone token's expiry |
| Dies on | `geneza kick`, suspension, session revoke, token expiry, node quarantine |

The scope is stored server-side on the session record, so it cannot be widened
by editing the URL. A launch session is refused by every console route that has
not explicitly opted in, which means a console endpoint added in a future
release is denied to launch sessions by default.

---

## 6. How long a session lasts

Two bounds, not one:

- **Idle window** (`max_session_ttl`, default 15m). The embedded UI renews on a
  timer while the shell is open, so an attended session keeps working
  indefinitely. Nothing to configure on your side.
- **Absolute ceiling** (`absolute_ttl`, default 8h). Renewal can never pass it.
  When it approaches, the UI warns the tenant; when it lands, they re-launch
  from your portal — which re-validates their Keystone token and re-runs policy.
  That re-check is the reason the ceiling exists, so raising it to days trades
  away most of its value.

Both stay under the tenant's Keystone token expiry, which is folded into the
ceiling at mint. Renewal re-checks revocation and suspension every time, so
`geneza kick` and a suspension both stop the timer immediately rather than
waiting for the current window to run out.

If tenants report being dropped at exactly `max_session_ttl`, the renewal call
is not reaching the controller — check that your portal is not framing the
console with a CSP that blocks its own `fetch`, and that `/api/v1/session/renew`
is not being stripped by a proxy in front of the controller.

## 7. Operational notes

**Keep sensitive workloads off the launch path.** A one-click, tenant-facing
button widens *who* uses the web path — from a handful of operators to every
tenant with a VM. The web path terminates the tunnel on the session proxy,
which is inside the trust boundary (ARCHITECTURE §6). That exposure is per
session and unchanged, but the volume through it goes up. Reserve the targets
you care most about for the native client:

```yaml
# workspace policy
rules:
  - roles: [ws-admin]
    actions: [shell]
    node_labels: {tier: prod}
    require_native: true     # denies the web path, and therefore every launch
```

**Audit.** Each launch writes `launch_mint` (cloud, project, instance, node,
action, portal IP) and `launch_redeem` (framing origin, user agent) to the
workspace's hash-chained audit log, followed by the usual `web_shell` event. A
denied mint writes `launch_denied` with the reason. Session recording is
unaffected: it happens at the **agent**, so a launched shell records exactly
like a console shell and does not depend on trusting the portal or the proxy.

**Rate.** Every mint validates a token against your Keystone. A portal that
mints on page render rather than on click will multiply that load — mint on
click.

**Auto-provisioning.** The launch path joins the human to the workspace exactly
like the other access-plane entrypoints, honouring `allow_human_auto_provision`.
If a tenant's project is unbound and auto-provision is off, the mint returns 403
with that reason rather than silently creating a workspace.
