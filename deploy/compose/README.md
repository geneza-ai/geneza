# compose — the Geneza installer

One script stands up (or upgrades) a Geneza node with Docker Compose. It asks a
few questions, renders `docker-compose.yml` + configs under `/opt/geneza`, and
brings the stack up.

```sh
curl -fsSL https://raw.githubusercontent.com/geneza-ai/geneza/main/deploy/compose/install.sh \
  | sudo bash
```

## Roles

You pick one when prompted (or with `--role`):

| Role | Services it runs | Use it for |
|---|---|---|
| `controller+relay` | controller · postgres · victoriametrics · caddy · relay | the single-host default — everything on one box |
| `controller` | controller · postgres · victoriametrics · caddy | a control plane you'll add relays to elsewhere |
| `relay` | relay | a relay that joins a remote controller |

`caddy` terminates a browser-trusted TLS cert (Let's Encrypt when you give a
`--site` FQDN) and reverse-proxies the console/login/enroll endpoints to the
controller. `victoriametrics` is published on loopback only.

## Upgrades

Re-run the installer. It pulls newer images, re-renders from your saved answers
(`/opt/geneza/answers.env`) and secrets (`secrets.env`, generated once and
reused), and `docker compose up -d`. Nothing rotates; a live fleet is undisturbed.

```sh
curl -fsSL .../install.sh | sudo bash -s -- --image-tag v1.4.0   # pin a version
```

## How a relay gets updated

This matters and is easy to get wrong. A **compose relay is a container**, so its
update unit is the **image** — you upgrade it by pulling a new image (re-run this
installer, or `docker compose pull && up -d`, or a Watchtower sidecar). The
controller does **not** reach into your Docker daemon to swap a container's binary.

If you want a relay the **controller auto-updates** — signed staged rollout with a
health-gated automatic rollback — install it as a **host binary** instead, with
[`../install/install-relay.sh`](../install/install-relay.sh). That relay runs
under the `geneza-bootstrap` supervisor, which is what applies controller-pushed
updates. Same relay, two operating models:

| | update unit | who applies it | rollback |
|---|---|---|---|
| compose relay (here) | image | you (`install.sh` / `compose pull`) | recreate with the old tag |
| host relay (`install/`) | binary | the controller, via `geneza-bootstrap` | automatic, health-gated |

Agents are always host binaries, so agents always get controller-driven auto-update.

## Relay join (role=relay)

A standalone relay needs an mTLS cert. On the controller host:

```sh
geneza-controller issue-relay-cert --name <relay-id> --config /etc/geneza/controller.yaml --out-dir /tmp/relay
```

Hand the three files to the installer; it self-registers to the controller
(`--controller HOST:7401`) and **auto-joins the signed fleet map** — no manual map
edit, and it fails over across controllers on its own:

```sh
curl -fsSL .../install.sh | sudo bash -s -- \
  --role relay --controller gw.example.com:7401 \
  --cert /tmp/relay/relay.crt --key /tmp/relay/relay.key --ca /tmp/relay/ca-roots.pem \
  --public-ip 203.0.113.20 --shared-secret <controller relay_shared_secret>
```

## Unattended install

Every prompt has a flag — see `install.sh --help`. Example single-host control
plane with a real cert:

```sh
sudo ./install.sh --role controller+relay \
  --site geneza.example.com --public-ip 203.0.113.10 \
  --acme-email ops@example.com --admin-password "$ADMIN_PW" --yes
```

## Files it writes (`/opt/geneza`)

```
docker-compose.yml     rendered for your role
config/                controller.yaml · relay.yaml · policy.yaml · Caddyfile
generated/             admin identity + the live controller.yaml (with the admin hash)
data/                  postgres · controller CA/state · relay tls · caddy certs · metrics
secrets.env            generated relay secret + postgres password (chmod 600)
answers.env            your non-secret answers, replayed on upgrade
```

## Uninstall

```sh
sudo ./install.sh --uninstall      # stops the stack; leaves ./data so you can purge by hand
```

## High availability

Run this same installer per node against **shared external backends**
(`--postgres-dsn`, `--metrics-url`, a unique `--controller-id`). The topology, the
backend requirements, and the full config reference are in
[`../ha/`](../ha/README.md).
