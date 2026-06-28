# Deploying the Geneza controller on Kubernetes

This guide deploys the Geneza **controller** (control plane / CA / session broker)
on Kubernetes with the [`deploy/helm/geneza-controller`](../deploy/helm/geneza-controller)
chart. It meets four constraints by design:

1. **External database** — the controller's durable state lives in an external SQL
   server (PostgreSQL here), supplied via an existing Secret. No database ships in
   the chart.
2. **HA cert/key material** — every piece of control-plane key material lives in a
   replicated Kubernetes Secret mounted into all replicas. No single local node
   path.
3. **HA Postgres with automated backups** — provided by [CloudNativePG](https://cloudnative-pg.io)
   (CNPG): a 3-instance cluster with continuous WAL archiving to object storage.
4. **Kubernetes Gateway API** (not Ingress) — for both web consoles *and* the mTLS
   gRPC port.

> **Honesty note on requirement 2.** The shipped controller image is static
> (`CGO_ENABLED=0`, distroless) and reads its CA key, grant key and serving TLS
> keypair as files at startup (`internal/controller/server.go`). The PKCS#11/HSM
> backend that exists in the config is CGO-only and cannot surface the Ed25519
> grant key, so it is unusable in the shipped image. The HA-correct answer is
> therefore a **replicated Kubernetes Secret** (etcd-backed, available to every
> pod on every node) mounted read-only into all replicas — *no single local path*,
> but **a Secret, not an HSM**. If you require HSM-held keys, you must build a CGO
> controller image; that is out of scope here.

---

## Architecture

```
                         Kubernetes Gateway (Gateway API)
   ┌──────────────────────────────────────────────────────────────────┐
   │  :443  HTTPS  console.example.com   → HTTPRoute   (TLS terminate) │
   │  :7401 TLS    controller.example.com→ TLSRoute    (TLS passthrough)│
   │  :7402 TLS    controller.example.com→ TLSRoute    (TLS passthrough)│
   │  :7407 TLS    cluster.example.com   → TLSRoute    (TLS passthrough)│
   └──────────────────────────────────────────────────────────────────┘
                                   │
                 ┌─────────────────┴─────────────────┐
                 │  Deployment: geneza-controller     │   replicas: 2 (router=pg)
                 │  ├─ initContainer: assemble config │   ← keys Secret + DSN Secret
                 │  └─ controller (serve)             │
                 │       7401 gRPC mTLS  7402 HTTPS    │
                 │       7406 console    7407 cluster  │
                 └───────────┬─────────────┬───────────┘
                             │             │
                  ┌──────────▼──┐    ┌─────▼──────────┐
                  │ CNPG Postgres│    │ S3 object store│  (blobs + PG backups)
                  │ 3 instances  │    │                │
                  │ + backups    │    └────────────────┘
                  └──────────────┘
```

Why the gRPC/HTTPS ports are **TLS passthrough**, not terminated:

- **7401 (gRPC)** does mutual TLS — agents and relays present certs the controller's
  own CA issued, and the controller authorizes by the verified client cert
  (`internal/controller/auth.go`). A proxy that terminated TLS would strip the
  client cert and make every caller anonymous.
- **7402 (HTTPS)** serves `/v1/ca-roots` and the installer that new nodes
  **fingerprint-pin against the Geneza CA**. Terminating it with a public/Let's
  Encrypt cert would break first-boot enrollment trust.

So only the **operator console (7406)** terminates TLS at the Gateway with a normal
public cert; the gRPC, HTTPS-API and cluster-console listeners pass TLS straight
through to the controller, which presents its own Geneza-CA-signed certificate.

---

## Prerequisites

- A Kubernetes cluster (1.29+) on which you can install a **GatewayClass that
  supports `TLSRoute`** (TLS passthrough). This is *not* universal — known-good
  classes: **Cilium**, **Istio**, **Envoy Gateway**. The NGINX Gateway Fabric and
  many cloud default classes do **not** implement `TLSRoute` yet.
- The Gateway API CRDs including the `v1alpha2` `TLSRoute`:
  ```sh
  kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/experimental-install.yaml
  ```
  (The *experimental* channel is required — `TLSRoute` is not in the standard
  channel.)
- `helm` 3.x, `kubectl`, and an S3-compatible object store (AWS S3, MinIO, Ceph
  RGW) reachable from the cluster — used for both Postgres backups and Geneza blobs.
- The controller image `ghcr.io/geneza-ai/geneza-controller` (built from
  `deploy/docker/Dockerfile.controller`; it bakes the controller binary, both web
  consoles, and a fallback agent stack).

---

## Step 1 — HA Postgres with CloudNativePG (short)

Install the CNPG operator, then declare a 3-instance cluster with continuous
backups. This is the entire HA-database + automated-backup story.

```sh
kubectl apply --server-side -f \
  https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.24/releases/cnpg-1.24.0.yaml
kubectl -n cnpg-system rollout status deploy/cnpg-controller-manager
```

```yaml
# geneza-pg.yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: geneza-pg
  namespace: geneza
spec:
  instances: 3 # 1 primary + 2 hot standbys, synchronous-capable
  storage:
    size: 20Gi
  bootstrap:
    initdb:
      database: geneza
      owner: geneza
  # Automated backups: continuous WAL archiving + scheduled base backups to S3.
  backup:
    barmanObjectStore:
      destinationPath: s3://geneza-backups/pg
      endpointURL: https://s3.example.com
      s3Credentials:
        accessKeyId:
          name: geneza-s3
          key: access_key_id
        secretAccessKey:
          name: geneza-s3
          key: secret_access_key
    retentionPolicy: "30d"
---
apiVersion: postgresql.cnpg.io/v1
kind: ScheduledBackup
metadata:
  name: geneza-pg-daily
  namespace: geneza
spec:
  schedule: "0 0 3 * * *" # 03:00 daily
  cluster:
    name: geneza-pg
  backupOwnerReference: self
```

```sh
kubectl create namespace geneza
kubectl -n geneza create secret generic geneza-s3 \
  --from-literal=access_key_id=AKIA... \
  --from-literal=secret_access_key=...
kubectl apply -f geneza-pg.yaml
kubectl -n geneza wait --for=condition=Ready cluster/geneza-pg --timeout=300s
```

CNPG publishes a Secret `geneza-pg-app` with the connection parameters. Build the
DSN Secret the chart expects (note `sslmode=verify-full` — CNPG serves TLS):

```sh
PGPASS=$(kubectl -n geneza get secret geneza-pg-app -o jsonpath='{.data.password}' | base64 -d)
kubectl -n geneza create secret generic geneza-db-dsn --from-literal=dsn=\
"postgres://geneza:${PGPASS}@geneza-pg-rw.geneza.svc:5432/geneza?sslmode=require"
```

> For full `verify-full`, mount CNPG's CA and point `sslrootcert` at it; `require`
> is the short path here.

---

## Step 2 — Initialize the control-plane keys (one-time)

The CA, grant key and serving TLS certs are generated **once** for the whole
cluster by `geneza-controller init`, then sealed into a Secret that every replica
mounts. Run init in a throwaway pod against an `emptyDir`, copy the result out,
remove the offline root key, and seal the rest.

```sh
# The init config MUST point at the SQL store: `init` generates the CA/grant/TLS
# files AND writes the controller's signed cluster config into the store. If init
# runs against the default bbolt store, the cluster config lands in a local
# state.db the controller never reads (it would crash with "no signed cluster
# config in store"). policy_file is also required (init validates the config).
cat > init-config.yaml <<'EOF'
data_dir: /var/lib/geneza/data
cluster_name: prod
policy_file: /cfg/policy.yaml
store: postgres
store_dsn: REPLACED_AT_RUNTIME
advertise:
  dns_names: [controller.example.com, geneza.example.com]
  ips: []
EOF
DSN=$(kubectl -n geneza get secret geneza-db-dsn -o jsonpath='{.data.dsn}' | base64 -d)
sed -i "s#REPLACED_AT_RUNTIME#${DSN}#" init-config.yaml
kubectl -n geneza create configmap geneza-init \
  --from-file=controller.yaml=init-config.yaml \
  --from-literal=policy.yaml="roles: {ws-admin: {allow: [{actions: ['*'], node_labels: {'*': '*'}}]}}
bindings: [{role: ws-admin, groups: [admins]}]"

# Run init in a pod whose initContainer writes the data_dir on an emptyDir and
# whose sidecar holds it so you can copy it out (a one-shot pod terminates before
# you can `kubectl cp`).
kubectl -n geneza apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata: { name: geneza-keygen, namespace: geneza }
spec:
  restartPolicy: Never
  initContainers:
    - name: init
      image: ghcr.io/geneza-ai/geneza-controller:latest
      args: ["init", "--config", "/cfg/controller.yaml"]
      volumeMounts:
        - { name: cfg, mountPath: /cfg }
        - { name: data, mountPath: /var/lib/geneza/data }
  containers:
    - name: hold
      image: busybox:1.36
      command: ["sleep", "600"]
      volumeMounts: [{ name: data, mountPath: /data }]
  volumes:
    - { name: cfg, configMap: { name: geneza-init } }
    - { name: data, emptyDir: {} }
EOF
kubectl -n geneza wait --for=condition=Ready pod/geneza-keygen --timeout=90s

# Copy the file material out, then DROP the offline root key (vault it — it is only
# needed to rotate the CA and must never live in the cluster) and the local bbolt.
mkdir -p keys && kubectl -n geneza cp geneza-keygen:/data ./keys -c hold
mv keys/ca/offline-root/root-ca.key ./root-ca.key.VAULT-THIS
rm -rf keys/ca/offline-root keys/state.db

# Seal the flat bundle the chart expects (the Deployment maps these to subpaths).
# audit.key is intentionally omitted: each replica generates its own (the durable
# audit copy is the audit_sink); set keysSecret.includeAuditKey + add it here only
# if you want one shared chain.
kubectl -n geneza create secret generic geneza-controller-keys \
  --from-file=issuing-ca.key=keys/ca/issuing-ca.key \
  --from-file=issuing-ca.crt=keys/ca/issuing-ca.crt \
  --from-file=root-ca.crt=keys/ca/root-ca.crt \
  --from-file=ca-roots.pem=keys/ca/ca-roots.pem \
  --from-file=grant.key=keys/grant.key \
  --from-file=grant.keyid=keys/grant.keyid \
  --from-file=controller.crt=keys/tls/controller.crt \
  --from-file=controller.key=keys/tls/controller.key \
  --from-file=relay.crt=keys/tls/relay.crt \
  --from-file=relay.key=keys/tls/relay.key

kubectl -n geneza delete pod geneza-keygen
rm -rf keys init-config.yaml   # leave nothing on your workstation
```

This single Secret is the shared control-plane identity. Mounted into every
replica, it is what makes the deployment HA: any replica can issue certs and sign
grants that every other replica (and every agent) validates. The signed cluster
config the controller serves to agents lives in Postgres (written by init).

---

## Step 3 — The remaining Secrets

```sh
# Break-glass console admin password (bcrypt). Generate the hash with the image:
HASH=$(kubectl -n geneza run hashpw --rm -i --restart=Never -q \
  --image=ghcr.io/geneza-ai/geneza-controller:latest -- hash-password <<<'choose-a-strong-pw')
kubectl -n geneza create secret generic geneza-local-admin --from-literal=password_bcrypt="$HASH"

# Relay shared secret (must match the relay's config).
kubectl -n geneza create secret generic geneza-relay-secret \
  --from-literal=shared_secret=$(openssl rand -hex 32)

# geneza-s3 already exists from Step 1 (reused for Geneza blobs).
```

---

## Step 4 — Install the chart

```yaml
# values-prod.yaml
replicaCount: 2

database:
  backend: postgres
  router: pg
  dsnSecret: { name: geneza-db-dsn, key: dsn }

keysSecret:
  name: geneza-controller-keys

localAdmin:
  username: admin
  groups: "geneza-admins"
  bcryptSecret: { name: geneza-local-admin, key: password_bcrypt }

relaySecret: { name: geneza-relay-secret, key: shared_secret }

storage:
  enabled: true
  endpoint: https://s3.example.com
  region: us-east-1
  bucket: geneza-blobs
  prefix: "geneza/"
  accessKeyId: AKIA...        # or set accessKeyIdSecret
  secretAccessKeySecret: { name: geneza-s3, key: secret_access_key }

audit:
  sink: { type: http, url: https://siem.example.com/audit }

gateway:
  className: cilium            # a class that supports TLSRoute
  consoleHostname: geneza.example.com
  grpcHostname: controller.example.com
  httpsApiHostname: controller.example.com
  clusterConsoleHostname: cluster.example.com
  consoleTLS:
    certManager:
      enabled: true
      issuerName: letsencrypt-prod
      issuerKind: ClusterIssuer

config:
  cluster_name: prod
  advertise:
    dns_names: [controller.example.com, geneza.example.com]   # MUST match the SANs you init'd
    ips: []
  relay_addrs: ["controller.example.com:7403"]
  relay_data_addrs: ["controller.example.com:7404"]
  oidc:
    issuer: https://idp.example.com/realms/geneza
    client_id: geneza-cli
  console:
    external_url: https://geneza.example.com
    auth: { oidc_enabled: true, local_enabled: true }
  cluster_console:
    external_url: https://cluster.example.com

# Bootstrap policy = the one-time SEED each workspace gets. Tenant admins edit
# their own policy in the console afterwards (it persists to the HA store).
bootstrapPolicy:
  roles:
    admin:    { allow: [ { actions: ["*"], node_labels: { "*": "*" }, record: true } ] }
    ws-admin: { allow: [ { actions: ["*"], node_labels: { "*": "*" }, record: true } ] }
  bindings:
    - { role: ws-admin, users: [admin], groups: [geneza-admins] }
```

```sh
# From the published OCI chart (recommended):
helm -n geneza install geneza oci://ghcr.io/geneza-ai/charts/geneza-controller \
  --version <chart-version> -f values-prod.yaml
# ...or from the source tree:
helm -n geneza install geneza deploy/helm/geneza-controller -f values-prod.yaml

kubectl -n geneza rollout status deploy/geneza-geneza-controller
```

> **The `advertise` SANs must include every hostname/IP clients reach the
> passthrough listeners on** (the Gateway addresses for 7401/7402/7407). They are
> baked into the controller cert at init time. If they change, re-run init's TLS
> step (`geneza-controller reissue-tls`) and re-seal `controller.{crt,key}` into
> the keys Secret.

---

## Step 5 — Gateway address & DNS

```sh
kubectl -n geneza get gateway geneza-geneza-controller \
  -o jsonpath='{.status.addresses[0].value}{"\n"}'
```

Point DNS at that address:

| Hostname | Port | Purpose |
|----------|------|---------|
| `geneza.example.com` | 443 | operator console (TLS terminated at Gateway) |
| `controller.example.com` | 7401 | agent/user gRPC mTLS (passthrough) |
| `controller.example.com` | 7402 | enroll / updates / `/healthz` (passthrough) |
| `cluster.example.com` | 7407 | cluster-operator console (passthrough) |

---

## Step 6 — Day-0: break-glass admin cert

The reserved cluster `admin` role is reachable only by a break-glass cert, never by
login — your offline escape hatch independent of OIDC/console:

```sh
kubectl -n geneza exec deploy/geneza-geneza-controller -c controller -- \
  geneza-controller issue-user-cert --config /run/geneza/controller.yaml \
  --name breakglass --roles admin,platform-admin --ttl 24h
```

Pull `user.crt`, `user.key`, `ca.pem` into a vaulted `~/.geneza/admin` profile and
drive the fleet with `genezactl --profile admin ...`.

---

## Policy is per-tenant and managed in the console

Authorization policy is **per workspace**, and its source of truth is the
controller's HA store — not a file the cluster operator owns. The chart's
`bootstrapPolicy` is only the one-time **seed** the controller writes into the
store the first time a workspace has no policy yet; after that, a **workspace
admin edits their own policy from the console** (Policy page), which validates
live against the controller's real parser, persists to the store, and hot-reloads
across all replicas. So the cluster operator sets a sane starting point once, and
each tenant diverges its own policy without touching the chart, files, or the
cluster. The reserved `admin` cluster role can never be granted from the console.

## High availability — what is and isn't shared

| Concern | HA mechanism |
|---------|--------------|
| Durable state (nodes, sessions, tokens, bindings, audit index) | **CNPG Postgres**, `store: postgres` + `router: pg` (LISTEN/NOTIFY bus for cross-replica session routing). SERIALIZABLE + advisory locks make multi-writer safe. |
| CA / grant / TLS keys | One **replicated Secret** mounted into every replica — same signing identity everywhere. |
| Recordings / artifacts (blobs) | **S3** (`storage.backend: s3`) — read-many across replicas. |
| Postgres durability | CNPG 3 instances + continuous WAL archiving + scheduled backups to S3. |
| Per-replica identity | `controller_id` stamped from the pod name (init container); the LISTEN/NOTIFY channel stays ≤63 bytes. |

**Audit log caveat.** The hash-chained audit log is written per-replica on local
disk and is *not* in the DB. With ≥2 replicas, set `audit.sink` to a SIEM (or S3
Object-Lock intake) for the single durable, tamper-evident copy; the on-pod file
is a per-replica scratch chain.

---

## Migrating an existing single-node (bbolt) controller

If you are moving an existing controller off its local bbolt store, run the
one-time migration with the controller stopped, then install pointing at the SQL
DSN:

```sh
helm -n geneza install geneza deploy/helm/geneza-controller -f values-prod.yaml \
  --set migrate.enabled=true --set migrate.bboltPVC=<pvc-holding-old-data_dir>
```

The `migrate-store` Job (`geneza-controller migrate-store --to-dsn ... --to-backend
postgres`) copies every record into Postgres before the controller rolls out.

---

## Troubleshooting

- **Pods crashloop on config**: the controller parses YAML strictly (`KnownFields`).
  `kubectl logs` shows the exact offending key. The init container assembles the
  final file at `/run/geneza/controller.yaml`; `kubectl exec ... -- cat` it.
- **`no signed cluster config in store: run init first`**: `init` was run against
  the default bbolt store, not Postgres, so the signed cluster config never
  reached the DB the controller reads. Re-run init with `store: postgres` +
  `store_dsn` in its config (Step 2).
- **Agents fail mTLS through the Gateway**: the listener must be `mode: Passthrough`
  and the controller cert SANs (`advertise`) must include the SNI hostname clients
  use. A terminated listener strips the client cert.
- **`TLSRoute` not accepted**: your GatewayClass does not implement it. Switch to
  Cilium/Istio/Envoy Gateway, or expose 7401/7402/7407 with a per-port
  `Service type: LoadBalancer` as a fallback (set `gateway.enabled=false`).
- **Console 404/blank**: the SPA is baked into the image at
  `/var/lib/geneza/console-web`; `config.console.static_dir` must point there
  (the chart default does).
