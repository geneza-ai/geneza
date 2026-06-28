# deploy/

Everything to **build and run** Geneza.

- **[`compose/`](compose/)** — the **installer**: `curl | sudo bash` renders a
  Compose stack for a controller, controller+relay, or relay node and brings it up
  (idempotent — re-run to upgrade). **Start here** →
  [`compose/README.md`](compose/README.md).
- **[`ha/`](ha/)** — configuration reference for running Geneza in high
  availability (shared Postgres, leaderless controllers, relay fleet). Reference
  only; you build an HA fleet by running the installer per node.
- **[`docker/`](docker/)** — Dockerfiles for the controller and relay images
  (`ghcr.io/geneza-ai/geneza-{controller,relay}`), built by
  [`.github/workflows/docker.yml`](../.github/workflows/docker.yml).
- **[`install/`](install/)** — one-line installers:
  [`install-agent.sh`](install/install-agent.sh) (enroll a machine) and
  [`install-relay.sh`](install/install-relay.sh) (add a relay).
- **[`release/`](release/)** — per-platform binary archives and offline signing
  ([`build-archive.sh`](release/build-archive.sh) + the release-root key).

New here? The [install tutorial](../INSTALL.md) walks the whole flow end to end —
control plane, enrolling machines, and OpenStack zero-touch enrollment.
