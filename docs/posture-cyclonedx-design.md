# Open, CycloneDX-native fleet security posture

## Why

Today Geneza answers one question — "is this machine affected by a CVE?" — by
collecting an SBOM and matching it against an OSV feed. Three things should grow
out of that without a rewrite:

1. **CycloneDX as the contract**, so the scanner, the detector, and the feed are
   each pluggable behind a stable format rather than wired to one tool.
2. **One scanning engine** (embedded osv-scalibr) for host *and* container images,
   dropping the external trivy/syft requirement as a hard dependency.
3. **Posture beyond CVEs** — exposed secrets and weak credentials — feeding the
   same risk view, and (the part only an access plane can do) **gating access**.

The through-line: stop treating "vulnerabilities" as a CVE-only, scanner-coupled
feature, and make it an open, CycloneDX-native **fleet posture** system whose
output drives the zero-trust access decision.

## The pipeline (every layer swappable)

```
scanner ──▶ CycloneDX SBOM ──▶ detector/matcher ──▶ findings (+ VEX) ──▶ posture ──▶ access policy
(scalibr,     (the contract)    (OSV today;          (CVE | secret |     (per-node    (continuous-authz
 trivy,                          grype/commercial     weak-cred …)        risk score)   + admission gate)
 external CI,                    later)
 registry)
```

We are already CycloneDX-internal: `internal/sbom` encodes the agent inventory to
CycloneDX and the controller decodes it (`Encode`/`Extract`, zstd-framed); trivy/syft
output is parsed through the same `Extract`; OpenVEX (`go-vex`) already drives
suppression. What is missing is making the format **open at the edges** and the
**detector/scanner layers pluggable**.

## 1. CycloneDX as a first-class, bidirectional contract

- **Ingest (open input).** `POST /api/v1/nodes/{id}/sbom` (and an image variant)
  accepts a CycloneDX document from any source — our scalibr agent, trivy in a CI
  job, a registry webhook, a commercial scanner — and runs it through the existing
  match/store path. The agent's own report becomes just one producer. Auth: a
  node's own enrollment cert for its own SBOM; an operator for any.
- **Export (open output).** `GET /api/v1/nodes/{id}/sbom` and
  `GET /api/v1/cves/{cve}/vex` emit the stored SBOM as CycloneDX and findings as
  OpenVEX, so external vuln tooling, auditors, or an existing pipeline can consume
  Geneza's fleet inventory. The cluster console's risk view is then one consumer
  among many.
- **Canonical schema handling.** Keep the single spec-version normalization already
  added (`clampSpecVersion`) so a newer producer (trivy 1.7, a future 1.8) is read,
  not rejected. PURL + ecosystem stay the join key.

This decoupling means: a customer who already runs Snyk/Trivy/Grype feeds their
CycloneDX in; a customer who wants Geneza's data in their SIEM pulls CycloneDX out.
We are an integration point, not a silo.

## 2. One scanning engine — embedded scalibr default

osv-scalibr now scans container images **in-process** (layer unpack + the same
filesystem extractors we already use for the host — the path OSV-Scanner uses).
Measured cost to embed it: **+1.5 MB (+5%)** on the agent (29.8 → 31.3 MB), pulling
the `go-containerregistry` + OCI image-spec cluster as indirect deps. In exchange:

- No ~100–150 MB trivy / ~80 MB syft install required on a node — the agent stays a
  single self-contained binary.
- Kills the exec/CycloneDX fragility class (the digest-ref, `--output -`, and
  spec-1.7 bugs were all trivy-plumbing).
- Uniform PURL/ecosystem semantics across host and container (one engine).
- `FromRemoteName` enables **registry scan-by-digest in-process** — a known image is
  scanned from its manifest with no local pull and no external tool.

Decision: **embedded scalibr is the default producer; trivy/syft become optional**
accelerators behind the CycloneDX contract (if installed, exec them; otherwise scan
in-process). Because everything downstream consumes CycloneDX, swapping producers is
invisible to the matcher.

## 3. Posture beyond CVEs (payload-blind)

scalibr has grown a `detector` framework and the `veles` secret engine. Add, ranked
by value to an access plane:

1. **Exposed secrets / leaked credentials** — hardcoded cloud keys, private keys,
   world-readable `.env`/token files. A live risk, not a maybe-someday CVE.
2. **Weak / default credentials** — weak shadow hashes, default passwords, weak SSH
   keys.
3. **EOL / unsupported software** — nearly free from the version data we already have.
4. **Misconfig / CIS** — real but noisy and more CSPM-product than access-control;
   deferred.

**Hard rule — payload-blind.** The agent reports the *finding* — type, path, a
fingerprint/hash, severity — and **never the secret value**. The controller must never
hold a leaked key, the same discipline as the encrypted recordings. A finding is a
new kind of CycloneDX/VEX-expressible record alongside a CVE verdict, stored and
queried the same way.

**Noise control.** Secret scanners are false-positive machines; reuse the VEX-style
suppression already built for CVEs, applied to findings, so an operator can mark a
finding not-applicable and have it stay suppressed.

## 4. Posture-gated access — the part only Geneza can do

A standalone scanner only reports. Geneza is the access plane, so posture becomes an
**input to the access decision**:

- The per-node risk score (outdated + KEV/critical CVE + critical exposed secret +
  weak creds) is already surfaced in the cluster console risk view.
- Wire it into the existing **continuous-authz + admission gate**: a node that fails
  a configurable posture threshold (e.g. an unsuppressed critical secret, or a
  KEV-flagged CVE) can be **auto-quarantined or access-restricted** — the same
  mechanism that already revokes a live session and denies a pending one.
- This is policy, not a hard block: "deny shell to any node leaking a cloud key" is a
  rule the operator opts into, with break-glass override.

That is the feature — not "we also scan for secrets," but "access follows posture."

## Phasing

- **P1 — CycloneDX open edges.** Ingest + export endpoints; findings/VEX export. No
  new scanner. Makes the system pluggable immediately.
- **P2 — Embedded scalibr container scanning.** Default to in-process image scanning;
  demote trivy/syft to optional. Measure final dep weight; gate behind the existing
  inventory module setting.
- **P3 — Posture detectors.** Secrets + weak-creds via scalibr detectors/veles, as
  payload-blind findings; VEX suppression; surface in the risk view.
- **P4 — Posture-gated access.** A posture threshold feeds continuous-authz +
  admission; operator-configured, break-glass override.

## Constraints (non-negotiable)

- **Payload-blind**: findings carry fingerprints/locations, never secret values.
- **Dependency weight**: each producer/detector measured before it lands; CycloneDX
  keeps producers swappable so weight is a choice, not a lock-in.
- **Noise**: VEX suppression applies to all finding classes, not just CVEs.
- **Open**: CycloneDX in and out at the edges so Geneza composes with, rather than
  replaces, a customer's existing security tooling.
