# Horizon panel — one-click Geneza console

A minimal Horizon (OpenStack dashboard) integration that adds a **Console**
action to each instance in *Project → Compute → Instances*. Clicking it opens a
live Geneza shell on that VM.

This is a working reference, not a packaged plugin: it is small enough to read
in one sitting, which matters more than being pip-installable, because you are
wiring a tenant-facing shell into your own portal.

## How it works

```
tenant clicks "Console"
  → Horizon view (server-side, holds the signed-in user's Keystone token)
  → POST https://<geneza>/openstack/<svc-uid>/launch   {token, instance_id}
  → Geneza validates the token against YOUR Keystone, resolves the workspace,
    checks the instance is in the caller's project, dry-runs policy
  ← {launch_url, expires_unix, ...}
  → Horizon redirects the browser to launch_url (new tab)
```

The tenant's own Keystone token is what authorizes the launch. Horizon never
holds a Geneza credential, so there is no API key to distribute, rotate, or
leak — and a compromised Horizon can only act for users whose tokens it already
has. See §2 of [`docs/hosted-ui-launch-spec.md`](../../../docs/hosted-ui-launch-spec.md).

**The launch URL is a single-use bearer credential with a ~60s TTL.** Redirect
to it; never log it, never email it, never store it.

## Install

1. Copy `geneza_console.py` into your Horizon deployment, e.g.
   `openstack_dashboard/dashboards/project/instances/geneza_console.py`.
2. Register the row action in that panel's `tables.py`:

   ```python
   from .geneza_console import GenezaConsoleAction, GenezaConsoleView

   class InstancesTable(tables.DataTable):
       class Meta:
           row_actions = (..., GenezaConsoleAction)
   ```

3. Add the view to the panel's `urls.py`:

   ```python
   from .geneza_console import GenezaConsoleView

   urlpatterns = [
       ...,
       url(r'^(?P<instance_id>[^/]+)/geneza-console/$',
           GenezaConsoleView.as_view(), name='geneza_console'),
   ]
   ```

4. Set the endpoint in `local_settings.py`:

   ```python
   GENEZA_CONTROLLER_URL = "https://geneza.example.com"
   GENEZA_SERVICE_UID = "kolla1"     # the clouds-registry key for THIS cloud
   GENEZA_VERIFY_TLS = True          # a CA bundle path also works
   ```

5. On the Geneza controller, enable the launch plane for that cloud:

   ```yaml
   clouds:
     kolla1:
       kind: openstack
       keystone_url: https://keystone.example.com/v3
       launch:
         allow: true
         actions: [shell]
   ```

Restart Horizon and the controller. The action appears for every instance; it
fails closed (with the controller's reason) for instances the tenant's policy
does not permit.

## Embedding it in the page instead of a new tab

The default and the recommendation is a new tab: it is first-party, immune to
framing questions, and shows the tenant a real origin in a real address bar.

If you want the terminal inline, opt in on both sides — pass `embed: true` in
the launch call and allow-list your Horizon origin exactly:

```yaml
      launch:
        allow: true
        embed:
          allow: true
          frame_ancestors: ["https://horizon.example.com"]
```

then render `launch_url` as an `<iframe src=…>`. The controller serves the embed
document with `Content-Security-Policy: frame-ancestors <your origins>`; every
other console path stays `X-Frame-Options: DENY`. No cookies are involved, so
third-party cookie blocking does not break it.

## What the tenant gets

A session scoped to **that one instance**, for one action (`shell`), lasting at
most `launch.max_session_ttl` (default 15m) and never longer than their Keystone
token. It cannot list other nodes, read audit, or change policy — even if the
same human is a workspace admin. Revocation (`geneza kick`), suspension, policy,
and agent-side recording all apply unchanged.
