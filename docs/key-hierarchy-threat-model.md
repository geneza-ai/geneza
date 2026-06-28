# Geneza key hierarchy & threat model

The canonical reference for every key in Geneza: what it is, where it lives, what its
theft yields, and how it should be protected. The guiding lens is the zero-trust
**assume-breach** tenet — for each key, the question is not "is it secret" but "what
does an attacker get when they have it, and how do we bound that."

## What "zero trust" means here (and what it doesn't)

Zero trust does **not** mean no component is trusted. It means: distrust the network
and location, authenticate and authorize every access, least privilege, assume breach.
Geneza, like every zero-trust architecture, has a **trusted policy-decision-point and
identity issuer** — the controller. The controller is what *enforces* zero trust for everyone
else, so it is necessarily trusted; the design goal is that even its breach yields as
little as possible.

The zero-trust guarantees are properties of specific components, and they **survive a
controller compromise**:

- **Relay** — payload-blind; forwards opaque ciphertext, holds nothing, can read no session.
- **Data path** — E2E (Noise / WireGuard), forward-secret, and never traverses the controller.
- **Recordings** — encrypted at the agent to an audit key the controller does not hold.
- **Network** — untrusted; everything authenticated + encrypted.
- **Identities** — continuously re-verified (revocation, suspension, fail-closed lease).

The decisive property: **a controller compromise breaks authentication/authorization
*integrity going forward* (it can mint identities, forge grants, sign a malicious map,
and actively MITM *new* sessions) — but it does NOT break the *confidentiality* of past
sessions or recordings.** Forward secrecy means past traffic is unreadable; the separate
audit key means recordings are unreadable; the off-path E2E tunnel means in-flight
legitimate sessions are unreadable. That separation is the whole payoff: even when the
trusted issuer falls, what users actually did stays sealed.

## The key inventory

| Key | Type | Lives | Signs / does | Frequency | Theft blast radius | Protect with |
|---|---|---|---|---|---|---|
| **Root CA** | ECDSA P-256 | **offline** (off every controller) | signs intermediates | ~never | mint new intermediates → total, permanent | offline + HSM (cheap YubiKey) |
| **Issuing CA (intermediate)** | ECDSA P-256, behind `crypto.Signer` | controller | signs node/user leaf certs at enrollment | rare | mint a leaf for **any** identity → fleet-wide impersonation + active MITM of new sessions | **HSM / KMS sign-in-place** |
| **Grant key** | ed25519 | controller | signs the **signed map** (`ClusterConfig`) **and** session grants | per session-broker + per config change | forge a malicious map (redirect, swap audit recipient, rewrite trust set, loosen policy) + authorize sessions | **HSM / KMS** (same class as the CA key) |
| **Controller TLS leaf** | ECDSA P-256 | controller (memory) | per-handshake CertificateVerify | per connection (hot) | impersonate **one** controller; revocable, short-lived | memory; rotate often; TPM only as optional defense-in-depth |
| **Node identity key** | ECDSA P-256 | node disk `0600` (`fileNodeKey`) | mTLS to controller + signs recording manifests | per connection + per recording | impersonate **one** node until revoked | `0600` + revocation; TPM-bind for hostile nodes |
| **Noise static key** | Curve25519 | node disk `0600` (`fileNoise`) | E2E session conduit (client↔agent) | per session handshake | be that node's tunnel endpoint going forward; **no** decrypt of past traffic (FS) | `0600`; TPM-bind for hostile nodes |
| **WireGuard static key** | Curve25519 | node disk `0600` (`fileWG`) | per-Network overlay data plane | per handshake | act as that node's WG peer going forward; **no** decrypt of past traffic (FS) | `0600`; TPM-bind for hostile nodes |
| **Audit recipient (public)** | age X25519 | signed `ClusterConfig` (public) | agents encrypt recordings to it | — | none (public) | n/a |
| **Audit identity (private)** | age X25519 | **offline / auditor** (default `offline` mode) | decrypt recordings for replay | per replay | read **future** recordings sealed to it; **not** past (FS of nothing — it's the same key, so it reads anything sealed to it that the holder can fetch) | offline file in a vault; HSM/YubiKey; multi-recipient to a break-glass escrow |
| **Ephemeral session keys** | ChaCha20-Poly1305 (Noise/WG-derived) | memory only | encrypt session bytes | per handshake/rekey | nothing — gone on rekey/close | never stored; forward-secret by construction |

The governing rule for hardware protection: **HSM-protect by (value × longevity) ÷
signing-frequency.** High-value, long-lived, low-frequency keys (root, intermediate,
grant) → HSM. Low-value, short-lived, high-frequency keys (TLS leaves, ephemeral session
keys) → memory. You have scarce HSM throughput; spend it on the keys whose theft is
catastrophic, not the ones doing thousands of handshakes.

## The three fleet-wide crown jewels

Three keys, if stolen, have fleet-wide impact. All three deserve the same protection;
two are online on the controller and one is offline.

1. **Root CA** — already offline by design (the bootstrap explicitly warns to move
   `offline-root/` off the host and delete it). Signs only to rotate intermediates, so a
   cheap YubiKey in a safe is ideal. A controller compromise does **not** reach it, which is
   what makes intermediate rotation a viable recovery.
2. **Issuing CA (intermediate)** — online on the controller, behind `crypto.Signer`, so an
   HSM/KMS is a drop-in. Theft → mint any identity. **#1 hardening priority** because its
   blast radius is fleet-wide and permanent if exfiltrated.
3. **Grant key** — online on the controller. Theft → sign a malicious map and forge grants.
   **Same class as the issuing CA key**; it must get the same HSM/KMS treatment. (Easy to
   overlook because "it just signs config," but the config *is* the trust + routing map.)

The reason **KMS / HSM sign-in-place** matters specifically: a mounted secret or Vault
hands the controller the raw key bytes, so a controller compromise **exfiltrates** the key →
fleet-wide minting/signing **forever, from anywhere**. An HSM/KMS **signs without ever
exporting the key** → an attacker can sign only **while resident** on the controller with
HSM access → you detect, revoke the credential, and rotate, and their power ends with
their access. That converts "steal once, abuse forever" into "must maintain presence,"
which is the entire point of assume-breach.

## Revocation: how a leaf is made untrusted

Geneza does **not** use CRLs or OCSP. It uses a **denylist enforced at the
policy-decision-point**, which is immediate and unbypassable:

1. **Operator** calls `AdminAPI.RevokeCert(serial)`, which writes the leaf serial to the
   **`revoked_certs`** table in the strong store (fail-closed).
2. **`checkNotRevoked`** runs on **every** authenticated RPC (unary + stream
   interceptors): it extracts the leaf serial from the TLS-verified chain and checks the
   denylist via the deny cache; a hit → `PermissionDenied`. The cert still chains to the
   CA and may be unexpired — it is rejected anyway.
3. **Fleet-wide in ≤ the deny-cache TTL (~3s)**, via the revoke doorbell (`NOTIFY`) or the
   MySQL poll; the SQL store fails closed on a read error.
4. **Live connections are torn**, not just new ones: the continuous-authz `reauthSweep`
   re-evaluates active/detached sessions each tick and pushes `SendRevoke` to cut the
   revoked ones server-side; the fail-closed session lease also starves them.

This is stronger than web-PKI revocation: no responder to run, no soft-fail, no stale
list — the controller is the relying party and holds the denylist locally. Because leaves are
short-lived, the denylist only needs to hold *un-expired* revoked serials, so it stays
bounded.

Authorization revocation (suspension) is a **separate** layer: a principal can be
suspended (`suspensions` table, checked alongside `checkNotRevoked`) even with a
cryptographically-valid, unrevoked cert — revoking *authorization* without touching
*authentication*.

## The signed map and the open trust-anchoring gap

The "signed map" is the **`ClusterConfig`**: `ControllerEndpoints`, the relay/DERP map,
`CARootsPEM`, the trusted `GrantKeys` set, `AuditRecipient`, and `AgentPolicy`. It is
signed by a **grant key** (ed25519) and accepted by nodes/relays if signed by a key in
their **trusted GrantKeys set** AND its `ConfigVersion` is not lower than what they hold.

A stolen grant key **can** sign a malicious map. Three things bound this, and one is a
real open item:

- **Rollback is blocked** — the monotonic `ConfigVersion` stops replay/downgrade (but not
  a forward forgery at version N+1).
- **A forged map alone is bounded** — redirecting clients to a rogue endpoint still
  requires that endpoint to present valid certs + grants to broker, and **no map forgery
  decrypts past traffic or recordings** (forward secrecy + the prior audit key). It is an
  attack on *new* sessions, not on history.
- **OPEN: the trust set is circularly self-signed.** Today an online grant key signs a
  config that *declares which grant keys and CA roots are trusted* — so a single
  compromised online key can rewrite *who is trusted* (add an attacker's key to the set).
  The fix is to **split the config**:
  - **routine map** (endpoints, presence, relay list) — online-signed by the grant key;
    forging it only causes detectable redirection, low stakes;
  - **trust anchors** (the `GrantKeys` / `CARoots` set — *who* is trusted) — signed by an
    **offline or N-of-M threshold key**, so no single online compromise can rewrite the
    trust anchors.
  This is the headline structural hardening still owed in the design.

## CA distribution & HA scaling

The authoritative, tested HA model (`docs/ha.md`, proven in `docs/ha-2controller-proof.md`,
`labs/geneza1/ha-p3/scripts/chaos-2gw.sh`, 15 checks green) is a **flat pool of identical,
stateless controllers** that **share one issuing CA key and one grant key** and a single
Postgres. They are interchangeable *because* they share the keys.

- **Scaling** is `replicas: N`: launch another controller process with the same keys + the
  same `store_dsn`; it self-registers into the `controllers` table, appears in the signed
  `ClusterConfig.ControllerEndpoints`, and takes work. No human-in-the-loop, no per-node
  minting.
- **One issuing CA** is generated once at cluster init (root → one intermediate); every
  replica runs on it. There are **no per-controller intermediates** in the flat model.
- **The real engineering question is distributing the one shared key to each replica.**
  Options, weakest to strongest: DB (envelope-encrypted, external KEK — bootstrap only,
  broad attack surface) < mounted secret / Vault (software boundary) < **KMS / HSM
  sign-in-place** (no replica ever holds the bytes). A network KMS (Vault Transit /
  OpenBao / cloud KMS) fits the flat shared-key model; per-host hardware (TPM) fits a
  per-controller-intermediate model instead. They are coupled choices.

(The superseded `ha-architecture-spec.md` proposed **per-controller intermediates** under a
shared offline root with compartmentalized blast radius. That is a valid alternative
topology — stronger isolation, more provisioning — but it is **not** what is built or
tested. Do not conflate the two.)

## Cheap KMS / HSM options

Signing volume for the high-value keys is tiny (per-enrollment / per-config), so cheap,
slow signers are fine; cost is dominated by the flat per-key fee.

| Option | Cost | Real HW boundary | Fits |
|---|---|---|---|
| TPM 2.0 (already on the host) | $0 | yes | per-controller intermediate (binds to one machine) |
| OpenBao / Vault OSS — Transit | $0 self-host | software | flat shared key (network-reachable) |
| YubiKey 5 (PIV) | ~$50 | yes | **the offline root** (signs ~never) |
| YubiHSM 2 | ~$650 | yes | shared online issuing key over the network |
| AWS/GCP/Azure KMS (ECC P-256 sign) | ~$1/key/mo | yes | flat shared key, if already in that cloud |
| SoftHSM2 | $0 | no | dev/test of the PKCS#11 code path only |

**Cheapest high-leverage move:** a ~$50 YubiKey for the **offline root**, regardless of
everything else.

## Recommended priority order

1. **HSM/KMS-back the issuing CA key** (`crypto.Signer` seam already exists). #1, because
   its theft is fleet-wide and permanent if exfiltrated.
2. **HSM/KMS-back the grant key** — same class as the CA key; do not leave it as a file.
3. **Offline root on a YubiKey** — cheap, removes the rotate-the-CA recovery path from
   software.
4. **Anchor the config trust set in an offline/threshold key** — close the circular
   self-signing gap (split routine map from trust anchors).
5. **Audit private keys** — keep `offline` (controller-blind), back them up via age
   multi-recipient (security key + vault escrow), graduate to HSM for high assurance.
6. **TPM-bind node identity keys** for hostile/ephemeral nodes — converts "steal the key,
   impersonate later/elsewhere" into "must stay resident on the box," paired with fast
   revocation.

All of these slot behind a single `KeySource` / `crypto.Signer` abstraction, defaulting to
the file-based key (today) and swappable to TPM / Vault / KMS / HSM by config — so the data
path and the controller code are identical regardless of which backend an operator chooses.
