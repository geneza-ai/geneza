# Update trust (TUF-lite, native ed25519)

How Geneza decides a binary is safe to run. Goal: **maintainers sign upstream,
agents auto-update from any channel (GitHub / controller mirror / sneakernet),
operators sign nothing and manage no keys, and a leaked signing key is
recoverable without re-touching nodes.** Trust is the signature, never the
channel — `internal/update`: *"binary trust does not come from TLS at all."*

## The two signed documents

```
  ROOT KEY  (offline, air-gapped, touched ~never)          ← PUBLIC half pinned on every node
       │ signs
       ▼
  root-keys.json   (types.RootKeys)
     { version (monotonic), keys: [signing pubkeys], expires_at }
       │ authorizes the CURRENT signing-key set (overlap allowed during rotation)
       ▼
  RELEASE-SIGNING KEYS  (in CI / HSM, rotatable)
       │ signs
       ▼
  <signed manifest>   (types.Manifest in a types.Signed)
     { product, os, arch, version, sha256, size, created_at }
       │ describes
       ▼
  binary blob  (served from GitHub / controller mirror / imported bundle)
```

## What the agent verifies (`types.VerifyArtifactChain`)

1. `root-keys.json` is signed by the **pinned root key**, its `version` ≥ the
   highest accepted (rollback), and not past `expires_at` (freeze).
2. Derive the **signing-key set** from `root-keys.json`.
3. The manifest is signed by **a key in that set** (NOT the root — role
   separation: the root authorizes signers but cannot itself sign a release).
4. `Installer`: product/os/arch match, `created_at` ≥ the anti-rollback floor
   (no binary downgrade), `sha256`/`size` of the downloaded blob match, then
   atomic `rename()` into `versions/<version>/geneza-agent`.

Domain separation (`geneza:<context>:`) prevents a signature for one document
(grant / cluster-config / manifest / root-keys) being replayed as another.

## Properties (proven in `internal/types/rootkeys_test.go`)

- foreign / unauthorized signing key → **rejected**
- root key signing a manifest directly → **rejected** (role separation)
- root-keys signed by a non-pinned root → **rejected**
- key rotation: rotate-in trusted, **retired key rejected**, **rollback refused**
- expired root-keys → **rejected** (anti-freeze)
- tampered manifest payload → **rejected**
- overlap window: both old+new keys verify during migration

## Maintainer flow (`geneza-sign`)

```bash
geneza-sign keygen   --out-dir secrets --name root        # offline root (rare)
geneza-sign keygen   --out-dir secrets --name signer1     # CI signing key
geneza-sign root-keys --root-key root.key --signer-pub signer1.pub \
                      --version 1 --expires-days 365 --out root-keys.json
geneza-sign manifest --key signer1.key --binary geneza-agent --version X --out m.json
geneza-sign verify-chain --root-pub root.pub --root-keys root-keys.json \
                         --manifest m.json --binary geneza-agent   # == what the agent does
```
Rotate a signing key: `keygen --name signer2`, then re-run `root-keys
--version 2 --signer-pub signer2.pub` (optionally list both for an overlap
window). Nodes pick up v2 and drop the old key — no node is re-touched.

## Distribution (channel is untrusted)

- **online controller** → background mirror pulls maintainer-signed artifacts from
  upstream and serves them to (air-gapped) agents.
- **offline site** → `genezactl import <bundle>` verifies the maintainer
  signature and stores it (an *import*, not a sign — operators never sign).
- agents download only from the controller; the controller holds no private key, so a
  compromised controller can serve stale-or-junk bytes but **cannot forge** an
  artifact the root never authorized.

## Wiring (end to end)

```
maintainer (offline)            controller (no private key)        agent (pins ROOT)
  geneza-sign root-keys  ──────► root_keys_file ──► GET ───────► bootstrap.json
    (root.key)                   (re-read per req)  /v1/updates    root_pub_file
  geneza-sign manifest           served verbatim     /desired      VerifyRootKeys
    (signerN.key)        ────► release publish ──► SignedManifest   -> signing set
                                  (publishTrustSet  + SignedRootKeys -> Installer.Trusted
                                   = pin ∪ root-keys                 -> manifest verify
                                   signers; rotation- -> floor + blob -> swap
                                   safe defense-in-depth)
```

- **controller** (`internal/controller`): `root_keys_file` is attached to every
  `/v1/updates/desired` response as `signed_root_keys` (read per-request → a file
  swap rotates fleet trust with no restart). `publishTrustSet()` makes the
  publish-time gate rotation-safe (accepts the single pin OR any signer the local
  root-keys lists). The controller holds no signing key — failing to read the file
  only foregoes rotation, it never forges trust.
- **bootstrap** (`cmd/geneza-bootstrap`): `root_pub_file` pins the root. When
  set, `establishTrust` REQUIRES a valid `signed_root_keys` before any install
  (fail-closed; missing/rolled-back/foreign-root ⇒ no update, never a silent
  fall back to single-key trust), derives `Installer.Trusted`, and persists
  `RootKeysVersion` (anti-rollback). Empty `root_pub_file` ⇒ legacy single-key.
- **Installer** (`internal/update`): zero-tolerance anti-rollback — both the
  manifest `CreatedAt` and the floor are offline-signer-clock, so there is no
  skew to tolerate and the downgrade window is closed.

## Status

- DONE + proven on the lab VMs (`labs/geneza1/scripts/tuf-proof.sh`): the two
  signed docs, chain verifier, anti-rollback + expiry + role separation, the
  `geneza-sign` tooling, the `Installer` consuming the root-anchored signing
  set, and the full controller↔bootstrap wiring. The lab proof drives a live
  controller+node through: normal update via the chain, **binary downgrade refused**
  (floor), **key rotation** (signer1→signer2), **retired/foreign signer rejected
  by the agent**, **rolled-back root-keys refused** (cannot revive the retired
  signer), **foreign-root-signed root-keys refused**, and a foreign manifest
  **rejected at publish**. Backward compatible: nodes without `root_pub_file`
  keep the single-pinned-key path (legacy e2e update test still passes).
- Remaining (optional): controller mirror-from-upstream + `genezactl import` for
  fully air-gapped sites; GoReleaser + cosign-keyless transparency receipt in CI.
