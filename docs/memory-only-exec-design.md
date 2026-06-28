# Memory-only binary execution — feasibility & design

Status: design note (not built). Question it answers: can Geneza push a signed
binary to an endpoint and execute it "memory-only" (fileless), the way
[triage.io](https://triage.io/use-cases/) advertises ("Push signed binaries to
endpoints. Memory-only execution with sandboxing. No staging servers needed." /
IR timeline: "exec → forensic-collector.exe (memory-only), 2.1MB deployed,
sandboxed execution")? How is it actually done?

## Short answer

Yes — and Geneza is unusually well-positioned, because triage.io is essentially
our architectural twin (self-hosted, E2E, outbound-HTTPS-only, no exposed ports,
shell/RDP + session recording, multi-tenant hub-per-client, HSM-backed,
sovereign). The trust, transport, policy, and audit seams already exist.

But **"memory-only execution" is platform-asymmetric and the marketing oversells
it**: it is clean and truly fileless on Linux, a compromise on Windows, and
effectively unavailable on macOS. Build to that reality, not the brochure.

The one genuinely net-new primitive is **fileless execution itself**. There is
currently zero `memfd`/`fexecve` anywhere in the tree, and all binary streams
flow *toward* the controller today — nothing pushes an executable *to* the agent.
So this is "reuse the trust scaffolding, build the exec core," not "wire up
existing parts."

## How memory-only execution actually works, per OS

### Linux — the only place it is truly fileless (and it is clean)

- `memfd_create(2)` returns an fd backed by anonymous RAM (tmpfs page cache,
  never a filesystem path). Write the ELF into it, optionally seal it (`fcntl`
  `F_SEAL_WRITE`/`F_SEAL_SHRINK`), then execute via `fexecve(3)` / `execveat(2)`
  with `AT_EMPTY_PATH`, or exec `/proc/self/fd/N`.
- The running image has **no path**: `/proc/<pid>/exe` resolves to
  `memfd:NAME (deleted)`. Verified empirically on the lab host (Linux 7.0.2,
  Go 1.26, `golang.org/x/sys/unix.MemfdCreate`).
- It runs as **its own forked process**, so blast-radius containment is free
  (unlike Windows reflective loading) — a crashing forensic tool can't take the
  agent down.
- **Static-link the pushed tool** (musl / CGO-free). A dynamically-linked binary
  still needs the loader + shared libs resolvable on the target; static is the
  portable-collector path.

### Windows — no kernel equivalent; pick your compromise

- No `memfd`/`fexecve` analog for native EXEs. Running a native binary "from
  memory" means **reflective PE mapping**, which loads the tool *inside the
  agent's own address space* — losing process isolation, forfeiting Authenticode
  validation, and lighting up EDR (ETW Threat-Intelligence + kernel
  thread-create callbacks flag RX/RWX in unbacked memory). Poor fit for a
  *signed* fleet tool.
- The genuinely-fileless-and-clean path on Windows is **managed**:
  `Assembly.Load(byte[])` / hosted-CLR for a .NET collector. No file, signature
  semantics intact.
- The honest fallback for native tools — and what several "memory-only" products
  actually ship — is **write to a RAM/temp location, exec, immediately unlink**.
  Not fileless; "minimal-footprint."

### macOS — effectively cannot do true fileless native exec (confirmed, high confidence)

- `execve`/`posix_spawn` require a **vnode** (a real file); AMFI validates the
  on-disk code signature against vnode-backed pages, and on Apple Silicon an
  unsigned image is killed at exec. `NSCreateObjectFileImageFromMemory` is
  dyld-only and (since dyld3) actually `mkstemp`s a temp file under the hood —
  the opposite of fileless, with a known IOC filename.
- The only true in-memory route is a custom dyld loader needing posture-breaking
  entitlements (`com.apple.security.cs.allow-unsigned-executable-memory`) —
  offensive tradecraft, deprecated, not a product.
- **Honest macOS behavior: temp-file-then-`unlink`, with the tool's own
  notarization/signature preserved.** There is no general writable tmpfs like
  Linux `/dev/shm`; the temp file lands on APFS in `$TMPDIR`.

## "Memory-only" ≠ invisible (and that is fine for DFIR)

It defeats **on-disk AV scanning and path-based allowlisting** — that is the real
value. It is **not** stealth: Linux auditd/eBPF/Falco ships an explicit
fileless-`memfd` rule; Windows ETW-TI + kernel callbacks see the unbacked-memory
thread starts; macOS EndpointSecurity emits `NOTIFY_EXEC`. (Correction worth
carrying: do not attribute native RWX/thread-start detection to **AMSI** — AMSI
scans script/.NET *content*, not memory protections.) For a forensic tool this is
a feature: you want every run logged and the output captured for evidence
integrity. Never market it as undetectable.

## Sandboxing the run

- **Linux:** `unshare` namespaces (user/pid/mount/net) + seccomp-bpf syscall
  filter + cgroup v2 resource caps + Landlock FS restriction +
  `PR_SET_NO_NEW_PRIVS`. Pairs naturally with the memfd fork.
- **Windows:** Job Objects / AppContainer.
- **macOS:** `sandbox_init` profile / spawn limits.

Optional for v1; an independent layer over the exec core.

## Mapping to Geneza — reusable vs net-new

Reuse as-is (no new trust infrastructure needed):

| Need | Existing seam |
|---|---|
| Sign the tool offline, verify before exec | `internal/types/{signed,rootkeys,manifest}.go`, `internal/releasetrust`, `geneza-sign`; pinned ed25519 root + grant-key set |
| Push live to a chosen agent | `internal/agentd/module.go` + `ControllerMsg` oneof over the mTLS control stream |
| Chunked blob transfer | `internal/agentd/upload.go` (64 KB chunks, manifest on first+eof) — **but reverse its direction** |
| Gate the action, revoke mid-run | `internal/policy/policy.go` actions, `internal/types/grant.go`, `internal/controller/continuousauthz.go` (kill-on-revoke) |
| Tamper-evident record | `internal/controller/audit.go` (HMAC-SHA256 prev-linked chain, verify-on-open) |

Net-new (the core):

1. The **fileless exec primitive** — absent today (no `memfd`/`fexecve`/
   `/dev/shm` exec anywhere).
2. A **reverse-direction controller→agent binary push** — today binary streams only
   flow up (`UploadRecording`, `PublishArtifact`); the only thing pushed down is
   age-sealed config, not an executable. New `ControllerMsg` arm (`BinaryPush`:
   name, signed manifest, size, chunks).
3. A new **`exec-binary` action** + a policy condition pinning an **approved
   manifest SHA-256** (restrict to specific signed tools), a new **audit event
   type**, and a **kill-on-revoke** hook for a live run.

**Structural caveat:** the signed self-update (`internal/update/install.go`) is
the closest *trust* analog but is **inverted on the execution axis** — it
deliberately writes a temp file, re-reads it to verify, atomically `rename()`s to
a *persistent* path, and runs from there. The new feature is the same
manifest/trust model with the **opposite** disk behavior: verify in memory, exec
from memfd, never persist. Copy the trust plumbing, not the install path.

## Suggested phased build

1. **MVP (Linux):** `BinaryPush` arm → agent buffers chunks in RAM → verify
   manifest signature against the existing grant-key set + SHA-256 →
   `memfd_create` + `execveat` as a forked process → stream stdout/stderr/
   exit-code into the hash-chained audit log. Gated by a new `exec-binary`
   policy action.
2. **Sandbox:** wrap the fork in namespaces + seccomp + cgroup + Landlock.
3. **Windows:** managed (`Assembly.Load`) for .NET tools; for native, ship
   temp-write-then-unlink and say so.
4. **macOS:** temp-write-then-unlink with notarization preserved; document that
   true memory-only is not available.

## Provenance

Derived from a multi-agent research + adversarial-verification pass. Linux
mechanics were verified empirically on the lab host; the macOS limitation
("no supported way to run an arbitrary unsigned Mach-O purely from memory") was
confirmed high-confidence; the Geneza code map was read against the real tree.
The Windows in-memory-loader detail is deliberately kept high-level (the
defensive, signed, policy-gated framing is the supported lane).
