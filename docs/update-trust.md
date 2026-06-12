# Update trust (TUF-lite, native ed25519)

How Geneza decides a binary is safe to run. Goal: **maintainers sign upstream,
agents auto-update from any channel (GitHub / gateway mirror / sneakernet),
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
  binary blob  (served from GitHub / gateway mirror / imported bundle)
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

- **online gateway** → background mirror pulls maintainer-signed artifacts from
  upstream and serves them to (air-gapped) agents.
- **offline site** → `geneza admin import <bundle>` verifies the maintainer
  signature and stores it (an *import*, not a sign — operators never sign).
- agents download only from the gateway; the gateway holds no private key, so a
  compromised gateway can serve stale-or-junk bytes but **cannot forge** an
  artifact the root never authorized.

## Status

- DONE + proven: the two signed docs, the chain verifier, anti-rollback +
  expiry + role separation, the `geneza-sign` tooling, and the `Installer`
  consuming the root-anchored signing set (falls back to a single pinned key for
  backward compatibility).
- Remaining wiring: gateway serves `root-keys.json`; bootstrap pins the root +
  loads/caches `root-keys.json` + builds the signing set; gateway mirror +
  `geneza admin import`; GoReleaser + cosign-keyless transparency receipt in CI;
  air-gapped lab demo.
