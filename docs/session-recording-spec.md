# Geneza shell-session recording with asciinema replay

Status: design-locked, build-ready. Capture + upload already exist in-tree; this spec
adds encryption-at-rest, integrity, the metadata index, and the replay path, and fixes
the one blindness violation in the current code (the controller stores cleartext casts).

## Cardinal property

The controller and relay are payload-blind: the E2E Noise tunnel runs client↔agent, the
data path never traverses the controller, the relay forwards opaque ciphertext. Recording
needs the plaintext PTY, so it is a deliberate, authorized exception to blindness — and
the exception is scoped as tightly as the rest of the model:

1. The exception lives ONLY at the agent. The agent already terminates the PTY (it is the
   realtime PEP; `internal/sessionhost` owns the ptmx + vt10x). Recording tees a stream the
   trusted endpoint already holds — it adds no new plaintext-exposure surface. The relay and
   the live data path stay byte-for-byte blind.
2. The controller must NOT become a plaintext oracle. Today the agent uploads a cleartext
   `.cast` and the controller stores it (`nodecontrol.go`). That contradicts blindness at rest
   and is the single most important thing this spec changes: the agent client-side-encrypts
   the cast; the controller stores only ciphertext it cannot read. The controller is a blind
   durable blob store + searchable metadata index — never a plaintext reader, in flight or
   at rest.

## Capture & format (already built — keep)

- Agent-side capture → asciicast v2, tee'd off the single PTY reader (`session.pump`), passive
  observer (recorder errors never break the live session; a truncated cast is still valid).
- Recording hangs off `session`, not the attach stream, so it spans detach/reattach as one
  continuous cast across any number of clients.
- Resize → `["r","CxR"]`; finalize closes the cast + `.done` sidecar; header carries
  width/height/TERM/SHELL/timestamp.

Additions:
- Extend the asciicast header with a `geneza{}` audit block: session_id, node_id/name,
  workspace_id, the DURABLE principal (subject/provider, not display name), action, command,
  grant_id, allow_pty, started_unix — so a downloaded cast is self-describing.
- Add an `["m", reason]` exit marker (exit code + how it ended: exited/killed/reaped/revoked).
- Pipe-mode `exec` (no PTY): record merged stderr as `"o"` (VERIFY if any auditor needs the
  stream split; default merge).

## Storage decision: client-side envelope-encrypted, controller stores opaque ciphertext

Options weighed: (a) on-node only — rejected as resting place (durability/searchability/the
recorded party holds its own evidence); keep only as the spool/retry buffer (built). (b)
controller store cleartext — rejected, this is the bug. (b′) controller store, client-side encrypted
— PICK. (c) S3-compatible — same posture as (b′), make it a pluggable blob backend (local disk
default, S3 optional); the encryption boundary is identical either way.

### Encryption & keying — envelope encryption, agent-side, to a per-workspace audit key

- Use `filippo.io/age` (X25519 + ChaCha20-Poly1305, audited, streaming). Reuse the standard
  lib; do not hand-roll the envelope. Per-workspace audit recipient = one age X25519 recipient
  string shipped in the signed `ClusterConfig`.
- The controller holds only the audit PUBLIC key. The PRIVATE key is held by the auditor / a
  workspace key custodian (offline file / HSM / desktop keychain) — NOT by the controller process.
- Agent at finalize streams the cast through `age.Encrypt(workspaceAuditRecipient)` into the
  spool; uploads ciphertext. Only a holder of the workspace audit private key can decrypt.
  Replay needs the controller (to serve the blob + enforce who-may-fetch) AND the audit key (to
  decrypt) — a deliberate two-party split.

### Threat-model trade-off (decided)

- DEFAULT `audit_key_mode: offline` — controller is blind; a controller compromise yields only
  ciphertext. Cost: replay is not pure in-browser; the auditor supplies the key (console WASM
  `age` / desktop native `age` / `geneza audit rec pull | age -d`).
- Opt-in `audit_key_mode: escrow` — controller/KMS holds the key for frictionless console replay,
  accepting the weaker posture (controller can decrypt). Per-workspace selectable. Default offline,
  because audit must not weaken the blindness it audits.
- OPEN (needs operator input): where the offline private key physically lives operationally.

### Integrity / tamper-evidence

- Agent computes SHA-256 over the CIPHERTEXT, includes it in `.done` + upload; controller stores
  it in the index row. Keep the controller's existing write-once rule (refuse overwrite).
- Agent signs `(session_id, sha256, size, finished_at)` with its node key (the `types.Sign`
  path that signs grants). Controller verifies on upload, persists the signature. Chain:
  controller-signed grant authorized recording → node-signed manifest attests the bytes →
  write-once storage. AEAD tag guards plaintext integrity at decrypt.

## Policy gating (partly built — keep grant-borne, make visible, notify)

- Keep the record decision server-side in policy, carried in the SIGNED `SessionGrant.Record`,
  reaching the agent as `HostCreateRequest.record`. The client cannot request or suppress it.
  Do NOT move it into `SessionCaps` (caps are a downgrade-only LIVE channel; recording is fixed
  at session birth).
- Add a real per-rule `record: true|false` in policy (today every allow-rule hardcodes true).
  Surface `recorded: bool` on `SessionRecord`/`SessionInfo` for the sessions list + audit log.
- Emit a tamper-evident "recording started" SessionEvent at create (recorded, grant_id,
  audit_key_id) — independent of whether the blob arrives.
- Notify the recorded principal (default ON): a one-line PTY banner at start + env
  `GENEZA_SESSION_RECORDED=1`. Policy-suppressible (`notify_recording: false`) for covert-audit
  regimes, but default on.

## Replay path (new — none exists)

- Controller user/admin API: `ListRecordings(workspace, filter)` over index rows;
  `GetRecording(workspace, session_id)` streams the CIPHERTEXT blob + node-signed manifest.
- Authz: require a NEW audit/replay capability (not default operator — replaying a shell is
  privileged), gated through the same access-broker/role check the sessions page uses for
  revoke. Every GetRecording itself emits an audit event — auditors are audited.
- Decryption (offline default): the auditor supplies the workspace audit private key. Desktop
  console (Wails) decrypts in-process via native Go `age` → feeds asciinema-player. Browser
  console decrypts via WASM `age` (key never leaves the browser). CLI:
  `geneza audit rec pull <id> | age -d -i audit.key | asciinema play -`.
- UI: add a Replay action to `web/.../sessions` rows where `recorded && ended`, hosting the
  official `asciinema-player` web component (reuse, don't build a terminal renderer). Verify
  SHA-256 + node signature before play; show an integrity badge.

## Metadata index (new table) — goes into BOTH sql schemas + bbolt

`recordings` keyed `(workspace_id, session_id)`: node_id, principal (durable subject), action,
started_unix, ended_unix, size_bytes, sha256 (over ciphertext), node_sig, audit_key_id,
blob_ref (`local:<id>.cast.age` | `s3://…`), truncated, stored_unix. Index on started_unix.
Mirrors the `sessions` schema convention; must be added through the multi-backend dialect
(Postgres + MariaDB) AND the bbolt store. Set `SessionRecord.Recorded=true` for a badge
without a join. NOTE: depends on the multi-DB store refactor landing first.

## Retention / lifecycle

- Casts are tiny (asciicast stores only emitted bytes + timing; idle gaps cost ~nothing).
  Keep the 512 MiB per-recording backstop; add policy `max_recording_bytes`; on cap-exceed,
  finalize a truncated-but-valid cast flagged `truncated=true`.
- Policy TTL `recording_retention_days` (default 90); idempotent `DELETE … WHERE expired` GC of
  rows + blobs (HA-safe, two controllers race harmlessly). `hold` flag exempts from GC (legal hold).
- Key rotation re-keys only NEW recordings (each row records its audit_key_id); old recordings
  stay decryptable by the retired key the auditor retains until they age out. No re-encryption.

## Build order

1. (depends on multi-DB store) add the `recordings` table to both SQL schemas + bbolt;
   store methods PutRecording/GetRecording/ListRecordings/DeleteRecording.
2. recorder.go (agent): header audit block + exit marker; wrap spool writer in age.Encrypt;
   SHA-256 over ciphertext + node-signed manifest in `.done`.
3. upload.go + proto: additive manifest fields (sha256, size, node_sig, audit_key_id).
4. nodecontrol.go (controller): verify hash + signature, write the index row, flip
   SessionRecord.Recorded, push to the pluggable blob backend; keep write-once + cap; never decrypt.
5. user API + console: ListRecordings/GetRecording (ciphertext) gated by the replay capability +
   per-fetch audit event; Replay UI with asciinema-player; WASM/native age decrypt; `geneza audit rec`.
6. policy: per-rule record/notify_recording/retention/max_bytes; ship the workspace audit
   recipient (public) in the signed ClusterConfig.

## Open questions for the operator
- Offline private-key custody (HSM vs desktop keychain vs sealed file).
- Escrow-vs-offline default confirmation (this spec defaults offline).
- One-time migration of any existing cleartext `data_dir/recordings/*.cast`.
