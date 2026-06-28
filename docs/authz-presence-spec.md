# Geneza — Continuous Authorization + Revocable Authz-State + YubiKey Continuous-Presence Factor
## Buildable Spec & Phased Plan (synthesis of Designs 1–3, judge best-per-fork picks, all red-team mitigations)

> Branch `wip` of `/root/geneza`. bbolt is greenfield-droppable (wipe `state.db` on upgrade); cert shape may change freely. All file paths/line numbers below are verified against the current tree.

> **IMPLEMENTATION STATUS (Authz Phases 0–4 shipped).**
> - Phases 0–2 (Subject plumbing, suspension layer, agent enforcement): done.
> - **Phase 3 (presence + software factor)**: `internal/controller/presence.go` =
>   `PresenceFactor` interface + registry-by-Kind + the software-stub safety gate +
>   `softwareFactor` + `verifyBeat`/`verifyPresenceSession`. Policy `require_presence`
>   (restrictive merge). `UserAPI.Heartbeat` (CLI transport) + `client/presence.go`
>   (auto-beats from `Establish`). `reauthorize` presence-stale predicate (Active +
>   Detached) reuses the session-p2p fail-closed lease as the kill. Web path FAILS
>   CLOSED for presence (deny) pending the browser beacon.
> - **Phase 4 (YubiKey enroll stubs + seam)**: `webauthnFactor` is registered and
>   FAIL-CLOSED (Verify returns "not yet implemented"); `POST /api/v1/presence/
>   enroll/{begin,finish}` + `store.AddPresenceCredential` persist a hardware
>   credential, so the software-stub gate then refuses `software` for that principal.
>   `GET /api/v1/presence/credentials` surfaces the enrolled kinds (SOFTWARE vs
>   hardware audit visibility).
>
> **DROP-IN (the seam, no call-site changes):** to make presence hardware-backed,
> implement `webauthnFactor.Verify` with `go-webauthn/webauthn` assertion checks
> (challenge echo, signature vs `cred.PublicKey`, `signCount` clone-detection, UV
> flag, session-id binding — `softwareFactor` already shows the binding) and add the
> SPA `navigator.credentials.create/get` UI + the browser presence beacon (`POST
> /api/v1/session/heartbeat` against the AuthSession), then lift the web-path deny.
> The interface, registry, enroll storage, gate, and heartbeat transport are all in
> place. Hardware factor F4 hardenings (re-verified data-path lease + host-side kill
> for detached PTYs) were delivered by session-p2p Phase 3/4 and are reused.

---

## 1. Authentication vs Authorization — the model in words

Geneza already proves **who you are** with three authentication mechanisms that this work **does not touch**: the OIDC/Keystone token (or local bcrypt) that bootstraps a login; the short-lived **mTLS user cert** (CLI, ~8h, roles baked in) minted at device-grant redeem; and the browser **Bearer session** (`AuthSession`). Authentication answers *identity*, once, and produces a credential with a lifetime.

This spec adds a **separate, continuously-evaluated authorization layer** that decides **whether you may act right now**, re-checked independently of credential validity. Authorization is the conjunction of an ordered set of **conditions** evaluated every sweep tick and at every broker call:

1. **Authz-state (suspension)** — a *persistent, principal-scoped, sticky-until-lift* deny. A suspended principal keeps a perfectly valid token and cert, but every new session is refused and every live session is torn down — and stays refused across re-login until an admin lifts it.
2. **Presence** — a *per-session* requirement that a human is physically present (proven by a heartbeat factor). When the factor goes silent (YubiKey unplugged / tab closed / process killed), presence goes stale and the session is dropped.

The cardinal invariant: **authentication is necessary but not sufficient.** A valid cert proves *who*; suspension + presence decide *whether*. The two are checked at **distinct sites** (login/cert-issuance, the gRPC interceptor, the broker, the continuous sweep, the web-shell watchdog), and **every authorization check fails closed** — when a principal cannot be keyed (missing Subject), or a factor cannot be verified, or a control message cannot be delivered, the system converges to **deny**, never to allow.

The enforcement engine is the existing, proven machinery — the 15s continuous-authz sweep (`continuousauthz.go`), revoke-over-control-channel (`SendRevoke`), short signed grants, and the web-shell watchdog (`console_shell.go`) — **plus two structural hardenings the red-team proved are mandatory** (a re-verified data-path lease and an authoritative host-side kill), without which "unplug → drop" does not actually hold.

---

## 2. Decisions F1–F5

### F1 — Authz-state schema *(adopt Design 2's siting; per-(ws,provider,subject) key; fail-closed on missing Subject)*

**Justification:** D2's mapping onto verified existing code paths is the tightest (the device redeem closure already carries `ApprovedSubject/Provider/WS`); per-workspace keying fits the existing per-ws member table better than D3's global key, and is the correct scope for a member-scoped deny.

New file `internal/controller/authzstate.go`. New **global** bbolt bucket `bucketSuspensions = []byte("suspensions")` added to `OpenStore`'s create-list.

```go
// Key = principalKey(ws, provider, subject) = ws + "|" + provider + "|" + subject
// PER-PRINCIPAL, never per-display-name (mutable, RT-F12) nor per-cert-serial (dies at re-login).
type SuspensionRecord struct {
    Workspace, Provider, Subject, Username string // Username = audit only, NEVER the key
    Reason, SuspendedBy                     string
    SuspendedUnix, LiftedUnix              int64
    Active                                  bool
}

// principalKey normalizes the provider so the key written at suspend-time and the key
// read at the broker/sweep are BYTE-EQUAL. Strips the "device:" issuance-path prefix.
func principalKey(ws, provider, subject string) string {
    return ws + "|" + strings.TrimPrefix(provider, "device:") + "|" + subject
}
```

Store methods: `SuspendPrincipal(ws,provider,subject,username,by,reason)`, `LiftSuspension(ws,provider,subject)`, `IsSuspended(ws,provider,subject) bool`, `isSuspendedTx(tx,ws,provider,subject) bool` *(tx-scoped, for site-1; see RT-F3)*, `ListSuspensions(ws)`. The row **persists until lifted** — it is *not* auto-reaped.

**Stickiness vs immediate nuke:** `SuspendPrincipal` writes the sticky row **then** calls a new **principal-scoped** `revokeBySubject(ws,provider,subject,reason)` for the instant teardown (NOT the by-display-name `revokeUser`, RT-F20). `LiftSuspension` flips/deletes the row; the next login is clean (the IdP token was never touched).

**Five fail-closed enforcement sites (all distinct from authentication):**

| # | Site | File / verified anchor | Action |
|---|------|------------------------|--------|
| 1 | Cert issuance | `console_device.go:117` issue closure, **inside** `device.go:166` `s.db.Update` | `isSuspendedTx(tx,…)` **before** `issueUserCert` → `access_denied` deviceTokenError. **Refuse, don't mint a deny-all cert.** |
| 2 | gRPC interceptor | `auth.go:196/216`, right after `checkNotRevoked` | `IsSuspended` on the peer cert's principal → `PermissionDenied` on **every** UserAPI/AdminAPI RPC immediately (RT-F4: closes the 15s race window; one bbolt read/RPC, the analog of `checkNotRevoked`). |
| 3 | Browser login | `console_session.go` `establishSession`, after `rolesForMember`, before `mintAuthSession` | `IsSuspended(ws,provider,subject)` → audit `login_denied` + 403 "access suspended". |
| 4 | Broker | `broker.go` `createSession`, after node-approval gate, before `policy.Evaluate` | `IsSuspended(ident.Workspace, ident.Provider, ident.Subject)` → `PermissionDenied`. This is where a still-valid 8h cert stops getting **new** grants. |
| 5 | Continuous sweep + watchdog | `continuousauthz.go` `reauthorize`; `console_shell.go:158` watchdog | `IsSuspended(rec.Workspace, rec.Provider, rec.Subject)` → `false, "principal suspended"` → `revokeSession`. Watchdog gets the identical check on `AuthSession`. |

**Subject plumbing (RT-F2/F13, mandatory & atomic):** `ca.IdentityClaims` and `ca.Identity` gain `Subject` (today they have only `Provider`, ca.go:56/62). `issueUserCert` (identity.go:118) takes & bakes `subject`; the device closure passes `g.ApprovedSubject` (already on the grant, device.go:45). `PeerIdentity` (ca.go:359) parses it back. `SessionRecord` gains `Provider, Subject`, stamped at `createSession`. `runWebShell` (console_shell.go:173) **must** set `ident.Provider=u.Provider, ident.Subject=u.Subject` (data already on `consoleUser`, console.go:57-58). **Missing/empty Subject on any suspendable-or-presence path → cannot-verify → DENY** (revoke). **Never** fall back to the mutable display name as the durable key (RT-F12, the explicit Design-1 wrong-choice).

---

### F2 — Presence model + 3 timers *(adopt Design 3's per-session/condition framing + session-id binding; Design 2's restrictive policy merge)*

**Justification:** presence varies by *sensitivity of what is accessed*, which policy already expresses per-rule; D3's per-session flag + session-id-bound attestation is the most fail-closed model; D2 supplies the load-bearing restrictive merge.

`require_presence` is a **per-policy-rule** property resolved into a **per-session** flag — never a global, never client-chosen.

- `policy.Rule` gains `RequirePresence bool \`yaml:"require_presence,omitempty"\``; `policy.Decision` gains `RequirePresence bool`.
- **`Evaluate` merges it toward the RESTRICTIVE value (RT-F6/F18):** `best.RequirePresence = best.RequirePresence || d.RequirePresence`, evaluated for **every** matched rule including the first-match assignment. The verified merge at policy.go:215-216 ORs `AllowDetach` toward *permissive*; copying that pattern would let a broad allow rule silently disable presence on a sensitive target. Mirror `require_native`'s fail-closed treatment exactly.

**Per-session state** (on the *persisted* records, not in-memory client objects — RT-F17):
- `SessionRecord` (store.go:191) gains `RequirePresence bool`, `LastPresenceUnix int64`, `PresenceChallenge []byte`.
- `AuthSession` (session.go) gains the same three (Provider/Subject already present).
- Set `RequirePresence = decision.RequirePresence` at `createSession`; seed `LastPresenceUnix = StartedUnix` (first-beat grace window).

**The three timers** (all config, validated at load — RT-F11):
- `heartbeat_interval` (client, default **10s**) — client re-asserts presence.
- `presence_ttl` (server, default **30s** = 3 missed beats) — staleness threshold; `0` disables enforcement globally (back-compat: zero-value records are presence-off).
- `reauth_interval` (existing, **15s**) — the sweep/watchdog that does the drop. **No second ticker.**

Invariant enforced at config load (hard error, fail to start): `heartbeat_interval < presence_ttl` and `reauth_interval <= presence_ttl`. Worst-case unplug→drop ≈ `presence_ttl + reauth_interval` (~30-45s).

**Stale → drop in the SAME sweep:** `reauthorize` adds a second predicate after suspension: `if rec.RequirePresence && now-rec.LastPresenceUnix > presence_ttl → false, "presence expired"`. Applies identically to `SessionActive` **and** `SessionDetached` records (the sweep already iterates both, continuousauthz.go:65). The web-shell watchdog gets the identical check on `AuthSession`.

**The interface seam** (new file `internal/controller/presence.go`):

```go
type Attestation struct {
    Kind        string // "software" | "webauthn" | "fido2"
    SessionID   string // MUST be bound & verified (RT-F8/F19 cross-session replay)
    Signature   []byte
    Counter     uint32
    ClientData  []byte // echoes the per-session single-use challenge
    ChallengeID []byte
}
type EnrolledCredential struct {
    Kind      string
    PublicKey []byte
    AAGUID    []byte
    SignCount uint32
}
type PresenceFactor interface {
    Kind() string
    Verify(att Attestation, challenge []byte, cred EnrolledCredential, sessionID string) (newCounter uint32, err error)
}
// registry: map[string]PresenceFactor keyed by Kind, config-gated (allow_software).
```

**Software stub (ships now):** `softwareFactor.Verify` accepts an attestation iff (i) `ClientData` echoes the issued single-use challenge for **this** session, **and** (ii) `att.SessionID == sessionID` (RT-F8/F19 — bound from day one so the real factor inherits it), **and** (iii) `att.Counter` strictly increases (monotonic-nonce clone-defense analog). No crypto, but it exercises the full challenge→verify→stamp path. **"Unplug" = the client stops calling Heartbeat** → `LastPresenceUnix` freezes → stale at `presence_ttl` → dropped. Proves absence→drop with zero hardware. WebAuthn/FIDO2 later return the identical `(newCounter, err)` shape; **no call site changes.**

---

### F3 — Heartbeat transport *(adopt Design 2: dedicated unary RPC + separate Bearer beacon + lost-response grace window; Design 3's session-id binding)*

**Justification:** D2's dedicated transports + the grace-window detail (a network blip must not false-drop a live session) is the correctness edge; D3 contributes the session-id binding.

Two transports, **one** `verifyPresence(principal, sessionID, att)` core that updates `LastPresenceUnix` or rejects.

**CLI (tunnel):** new unary `rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse)` on `UserAPI`, over the **existing mTLS user-cert channel** (no long-lived user→controller stream exists to piggyback; control is unary). Handler: `identityFrom(ctx)` → verify session belongs to `ident` → **check suspension first (RT-F4)** → `registry[att.Kind].Verify(att, storedChallenge, cred, sessionID)` → on success `UpdateSession(LastPresenceUnix=now)` + issue & store `next_challenge`; **on failure/empty, do NOT bump** (session goes stale → sweep drops, fail closed). CLI runs a background goroutine in the session-run loop (`ssh.go`/`exec.go`/`attachrun.go`) beating every `heartbeat_interval`.

**Browser:** `POST /api/v1/session/heartbeat` (Bearer via `c.auth`), body `{kind, signature, counter, clientData, challengeId, sessionId}`, returns `{nextChallenge, presenceTtl}`. A **separate beacon** independent of any open web-shell WS, so a presence-required *non-shell* privileged browser session also beats. The watchdog just re-reads the freshly-stamped `LastPresenceUnix`.

**Replay/false-drop handling:**
- **Fresh per-beat single-use challenge** stored as `PresenceChallenge` on the session → replay defense.
- **Lost-`HeartbeatResponse` grace window (RT-F11):** accept the *previous* challenge for **one** `heartbeat_interval` so a single dropped response doesn't spuriously drop a live session; cap the grace at one interval so it can't mask a real unplug.
- **Absent key → client STOPS beating** (no send-empty path; staleness drops). The software stub simulates unplug by stopping the goroutine.

---

### F4 — Agent/tunnel enforcement *(Design 2/3 conclusion + the TWO mandatory red-team hardenings)*

**Justification:** both designs correctly conclude the agent needs no *protocol* change, but the red-team proved (RT-F5, RT-F19/critical) that the "2m grant TTL self-heals" claim is **false for an established session** and that revoke is a **no-op for a detached PTY** — so two structural hardenings are MUST-ship, not optional.

**Baseline (correct):** suspension & presence are enforced controller-side: `reauthorize` → `revokeSession` → `registry.SendRevoke(nodeID, sessionID, reason)` → agent tears down. `SessionRevoke` is reused as-is. The broker `IsSuspended` check is where a still-valid 8h CLI cert stops getting **new** grants. No new agent grant fields for the happy path.

**Detached-session rule (decided, D3 phrasing):** **`RequirePresence` implies non-survivable detach.** Detach is **allowed** (preserves roaming/worker-update for non-presence sessions — do **not** forbid it, RT-F1/Design-1 wrong-choice); but a presence-required detached session has no client to advance `LastPresenceUnix`, so it goes stale by definition and is reaped within `presence_ttl + sweep`. Surfaced on the CLI `--detach` path ("will be dropped when you disconnect if presence is required").

**MANDATORY HARDENING #1 — re-verified data-path lease (RT-F5, RT-F19, critical).** Verified: `offer.go:40` validates the grant **once** at offer; after `established` (offer.go:172) the relay splice runs to `MaxSessionTTL` (agent-capped, offer.go:53) or an explicit `SessionRevoke`. A blocked/blipped control channel at the moment of unplug/suspend keeps the session alive while the record shows "revoked." Fix: the agent **continuously re-verifies a short lease** inside `runSession` — re-run `grant.Validate(now)` (or consume a controller-refreshed signed lease) every `presence_ttl`; tear down when the current lease expires and no fresh one arrived. The controller **stops minting lease refreshes the instant `reauthorize` returns false**, so a lost `SendRevoke` **fails closed** (no fresh lease → session dies on the next lease boundary). This converts "short grant TTL" from an offer-time-only check into the actual data-path kill switch.

**MANDATORY HARDENING #2 — authoritative host-side kill for detached PTYs (RT-F19, critical).** Verified: `revokeLive` (worker.go:155) returns early when `w.live[id]==nil` (detached), and `host.Kill` (sessionhost.go:420, `HostKillRequest` RPC) is reached **only** from the live-bridge path — so a revoked **detached** PTY runs until `defaultDetachedTTL = 86400s` (24h, sessionhost.go:50). Fix: the controller revoke must carry `HostSessionID` (already on `SessionRecord`); the agent's revoke handler, when there is no live bridge to cancel, **calls `shc.Kill(hostID)`** on the session-host. Belt-and-suspenders: pass a per-session `DetachedTtlSec ≈ presence_ttl` in the grant for `RequirePresence` sessions (sessionhost already honors `DetachedTtlSec`, sessionhost.go:90) so a fully-partitioned host self-reaps fast.

**MANDATORY HARDENING #3 — durable revoke on reconnect (RT-F5).** `revokeSession` swallows `SendRevoke` errors (`_ =`, continuousauthz.go:115) and the sweep skips terminal records forever (continuousauthz.go:65). Fix: enqueue undelivered revokes; on the agent's next control-stream `Hello`, the agent sends its **live + detached session-ID list**, and the controller immediately re-sends `SendRevoke` (idempotent) for any now-denied session before resuming.

---

### F5 — YubiKey terrain / the seam *(adopt Design 3's session-id binding + config-gate; Design 2's registry-by-Kind tightness)*

**Justification:** the `PresenceFactor`/`EnrolledCredential` seam + registry-by-Kind makes a real factor a *drop-in* (register one factor + fill two enroll handlers, zero changes to transports/sweep/watchdog/records/agent); D3's explicit session-id binding + refuse-software-in-prod gate make it the most fail-closed.

**Storage:** `MemberRecord` (membership.go) gains `PresenceCredentials []EnrolledCredential`, keyed by the same `<provider>:<subject>` (`memberKey`). Software stub stores a sentinel `{Kind:"software"}`; enrolling a real key overwrites with `{Kind:"webauthn"|"fido2", PublicKey, AAGUID, SignCount}`. New store methods `AddPresenceCredential`, `GetPresenceCredentials`, `BumpSignCounter`.

**Enrollment ceremony** (endpoints ship as stubs storing software creds; real bodies documented):
- Browser: `POST /api/v1/presence/enroll/begin` → `PublicKeyCredentialCreationOptions` (challenge + rp + `user=Subject`, `authenticatorSelection.userVerification="required"`); `navigator.credentials.create`; `POST /api/v1/presence/enroll/finish` → verify attestation object, extract pubkey + AAGUID + initial signCount → `PutMember`.
- CLI: mirror with `go-libfido2` `Device.MakeCredential`.

**Per-heartbeat attestation verification** (documented, drop-in):
- Browser WebAuthn: `navigator.credentials.get({publicKey:{challenge:nextChallenge, userVerification:"required", allowCredentials:[enrolled]}})`; `webauthnFactor.Verify` checks **(i)** `clientDataJSON.challenge == issued nextChallenge` (replay), **(ii)** signature vs `EnrolledCredential.PublicKey`, **(iii)** `authData.signCount > EnrolledCredential.SignCount` (clone), **(iv)** UV flag, **(v)** session-id binding. Persist `newCounter`. Library `go-webauthn/webauthn`.
- CLI FIDO2: `go-libfido2` `Device.Assertion(rpID, challenge, credID, UV)`; same checks. HMAC-SHA1 slot challenge-response documented as a fallback variant.

**Replay/clone defense (uniform):** fresh per-beat single-use server challenge + monotonic `signCount` persisted on the cred + attestation **bound to session_id** in `clientData`. The software stub enforces challenge-echo + nonce-monotonicity + session-id; `signCount` is a no-op for `Kind=="software"`.

**Software-stub safety gate (RT-F9, MUST):** `presence.allow_software` defaults to a configured value; **once any hardware credential (webauthn/fido2) is enrolled for a principal, the registry MUST refuse `Kind=="software"` for that principal.** `Kind=="software"` is **visible in audit + console** ("presence factor: SOFTWARE") so a software-only "present" is never mistaken for hardware. Ship the gate **with** the stub — an ungated stub is a presence hole, not a seam.

---

## 3. Config / Proto / Store changes

### Config (`internal/controller/config.go`)
```
presence.heartbeat_interval   Duration  default 10s   (advisory, surfaced in HeartbeatResponse)
presence.ttl                  Duration  default 30s   (staleness; 0 = enforcement off globally)
presence.allow_software       bool      default true in lab / false once a real factor exists
reauth_interval               Duration  (EXISTING, 15s) — reused for suspension + presence sweeps
```
Validate at load (hard error): `heartbeat_interval < ttl` **and** `reauth_interval <= ttl` (RT-F11). Policy YAML gains per-rule `require_presence: true`. **No** config to enable suspension (admin action on a per-principal row, always available; empty bucket = nobody suspended). CloudConfig / login configs **unchanged** (suspension/presence are orthogonal to which IdP authenticated you).

### Proto (`api/proto/geneza/v1/control.proto`)
```proto
// UserAPI
rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
message PresenceAttestation { string kind=1; bytes signature=2; uint32 counter=3;
                             bytes client_data=4; bytes challenge_id=5; string session_id=6; }
message HeartbeatRequest  { string session_id=1; PresenceAttestation attestation=2; }
message HeartbeatResponse { bytes next_challenge=1; int64 presence_ttl_seconds=2; bool ok=3; string reason=4; }

// AdminAPI
rpc SuspendPrincipal(SuspendPrincipalRequest) returns (Empty);
rpc LiftSuspension(SuspendPrincipalRequest) returns (Empty);
rpc ListSuspensions(Empty) returns (ListSuspensionsResponse);
message SuspendPrincipalRequest { string workspace=1; string provider=2; string subject=3;
                                  string username=4; string reason=5; }
// (enrollment endpoints are HTTP/console, not gRPC)
```
`ca.IdentityClaims` + `ca.Identity` gain `Subject` (only cert-shape change; greenfield-OK).

### Store (bbolt; greenfield, no migration)
- **NEW global bucket** `bucketSuspensions` + `authzstate.go` (`SuspendPrincipal`/`LiftSuspension`/`IsSuspended`/`isSuspendedTx`/`ListSuspensions` + `SuspensionRecord`).
- `SessionRecord`: add `Provider, Subject, RequirePresence bool, LastPresenceUnix int64, PresenceChallenge []byte`.
- `AuthSession`: add `RequirePresence bool, LastPresenceUnix int64, PresenceChallenge []byte`.
- `MemberRecord`: add `PresenceCredentials []EnrolledCredential`.
- New `UpdateMemberCred` (signCount persistence); reuse existing `UpdateSession` for `LastPresenceUnix`.
- All additions are backward-inert (zero values = presence-off, not-suspended). **Optimization (RT, all):** the sweep loads `ListSuspensions` once into a map per tick, not N bucket-gets.

---

## 4. Security checklist — every red-team mitigation as a MUST

1. **MUST** normalize the principal provider through one `principalKey()` helper that strips the `device:` prefix, so the key written by `SuspendPrincipal` and read at the broker/sweep for the same login are byte-equal. Verified bug: console_device.go:125 mints `"device:"+ApprovedProvider`. *(RT-F1, critical)*
2. **MUST** thread `Subject` end-to-end (`IdentityClaims` → `issueUserCert` (pass `g.ApprovedSubject`) → `PeerIdentity` → `SessionRecord` → broker stamp → `runWebShell` ident literal at console_shell.go:173) as one atomic change; **MUST** treat empty/unkeyable Subject on any suspendable/presence path as cannot-verify → **DENY**, never no-row-found → allow. **MUST NOT** fall back to the mutable display name as the durable key. *(RT-F2/F13/F22, critical/high)*
3. **MUST** implement site-1 (cert issuance) with a **tx-scoped** `isSuspendedTx(tx,…)` reading the caller's transaction — never a fresh `IsSuspended` `View`/`Update` inside `PollDeviceGrant`'s `s.db.Update` (single-writer bbolt → deadlock/DoS). *(RT-F3, high)*
4. **MUST** add an `IsSuspended` gate in `unaryAuthInterceptor`/`streamAuthInterceptor` right after `checkNotRevoked` (auth.go:196/216) → immediate `PermissionDenied`, not 15s later. **MUST** check suspension **before** stamping `LastPresenceUnix` in the Heartbeat handler. *(RT-F4, high)*
5. **MUST** re-verify a short data-path lease inside the agent's `runSession` and tear down when no fresh lease arrives (controller stops refreshing the instant `reauthorize` returns false) — so a lost `SendRevoke` fails closed. *(RT-F5/F19, critical)*
6. **MUST** drive an authoritative `host.Kill(HostSessionID)` for **detached** sessions on revoke (revokeLive must reach the session-host when `w.live[id]==nil`); **MUST** pass `DetachedTtlSec ≈ presence_ttl` for presence-required sessions. Verified: detached PTY otherwise survives 24h. *(RT-F19, critical)*
7. **MUST** make revoke durable: enqueue undelivered revokes; agent sends live+detached session-ID list on reconnect `Hello`; controller re-sends idempotently. *(RT-F5, high)*
8. **MUST** merge `require_presence` toward the **restrictive** value (`||`, OR-toward-requiring) for **every** matched rule — the inverse of the verified `AllowDetach` merge (policy.go:215). Unit-test both rule orders. *(RT-F6/F18, high)*
9. **MUST** extend the web-shell watchdog (console_shell.go:158) to also close on `IsSuspended(provider,subject)` and `RequirePresence && now-LastPresenceUnix > presence_ttl`, re-reading `AuthSession` each tick. *(RT-F7/F16, high)*
10. **MUST** config-gate the software factor (`presence.allow_software`; registry refuses `Kind=="software"` once a hardware cred is enrolled for the principal) and surface `Kind=="software"` in audit/console. *(RT-F9/F23, high)*
11. **MUST** bind every attestation to `session_id` (verified server-side; stub enforces it too) + fresh single-use per-session challenge; server **MUST NOT** bump `LastPresenceUnix` on a failed/empty/wrong-session/replayed attestation. *(RT-F8/F21, high/medium)*
12. **MUST** make `revokeBySubject(ws,provider,subject)` the immediate nuke (matching the stored Provider+Subject), not by-display-name `revokeUser` (verified rec.User match at continuousauthz.go:152). Keep by-name as best-effort over-revoke only (over-revoke fails safe). *(RT-F20, medium)*
13. **MUST** apply the presence condition to `SessionDetached` records identically to `SessionActive`, reading `LastPresenceUnix` off the persisted record; **MUST NOT** clear `RequirePresence` on detach. *(RT-F17, medium)*
14. **MUST** validate the three-timer ordering at config load (hard error), add a one-beat grace window for a lost `HeartbeatResponse`, capped at one `heartbeat_interval`. *(RT-F11, low)*

---

## 5. The YubiKey seam — ships vs documented

**SHIPS NOW (code, lab-green, e2e-proven):**
- Full suspension layer: bucket, record, store methods, **five** enforcement sites (cert-issuance tx-scoped, interceptor, browser login, broker, sweep+watchdog), `SuspendPrincipal` → `revokeBySubject`, AdminAPI Suspend/Lift/List + CLI verbs + SPA action.
- Full presence layer with the **software factor**: `PresenceFactor` interface + registry + config gate, `RequirePresence` policy field (restrictive-merge) propagated to `SessionRecord`+`AuthSession`, `LastPresenceUnix`/`presence_ttl`/`PresenceChallenge`, `UserAPI.Heartbeat` + `POST /api/v1/session/heartbeat`, the sweep + watchdog presence checks, CLI heartbeat goroutine + SPA beacon, session-id binding + fresh-per-beat challenge + grace window.
- The three structural hardenings (re-verified lease, host-side detached kill, durable revoke).
- Subject end-to-end + `ca.Identity.Subject`.

**DOCUMENTED + STUBBED (drop-in, NO protocol/seam redesign):** `webauthnFactor`/`fido2Factor` `Verify` bodies (sig + counter + challenge + UV + session-id), real enroll ceremonies (begin/finish exist as software stubs), SPA `navigator.credentials.create/get`, CLI `go-libfido2` wiring, HMAC-SHA1 slot fallback. Captured in `docs/presence-and-suspension-spec.md`. **Adding a real factor = register one `PresenceFactor` + fill two enroll handlers + the SPA calls; zero changes to transports, sweep, watchdog, session records, or the agent.**

---

## 6. Phased build plan

Each phase is independently committable on `wip`, keeps the existing 50/50 CLI + browser e2e green (defaults: presence-off, no suspensions), and ships one new e2e assertion. Wipe `state.db` after any record/cert-shape change.

> **Phase 0 — Subject plumbing & principal-key foundation** *(prerequisite; nothing keys without it)*
> Files: `internal/ca/ca.go` (add `Subject` to `Identity`+`IdentityClaims`, set in `PeerIdentity`), `internal/controller/identity.go` (`issueUserCert` takes+bakes subject), `internal/controller/console_device.go:125` (pass `g.ApprovedSubject`; **stop** double-keying — keep the `device:` provider only as the cert claim and strip via `principalKey`), `internal/controller/store.go` (`SessionRecord.Provider/Subject`), `internal/controller/broker.go` (stamp both at `createSession`), `internal/controller/console_shell.go:173` (set `ident.Provider/Subject`), new `internal/controller/authzstate.go` (`principalKey` helper).
> **e2e:** a normal keystone CLI login + a browser login still succeed; assert the resulting `SessionRecord` has non-empty `Provider` **and** `Subject` (start-up invariant: no live session may lack a subject). Proves the foundation lands without breaking the happy path. *(RT-F2/F13)*

> **Phase 1 — Suspension layer (durable deny, all sites except presence)**
> Files: `authzstate.go` (`SuspendPrincipal`/`LiftSuspension`/`IsSuspended`/`isSuspendedTx`/`ListSuspensions`, `bucketSuspensions` in `OpenStore`), `auth.go:196/216` (interceptor gate), `console_device.go` (tx-scoped site-1), `console_session.go` (site-3 browser), `broker.go` (site-4), `continuousauthz.go` (`reauthorize` suspension predicate + `revokeBySubject` replacing the by-name nuke in the suspend path), `console_shell.go` (watchdog suspension check), AdminAPI RPCs + `cmd/geneza/admin.go` (`suspend`/`unsuspend`/`suspensions`), SPA suspend/lift action.
> **e2e (the headline assertion):** **suspend a user who holds a valid token** → assert (a) their live **CLI tunnel** is dropped within one sweep (~15s), (b) their open **web shell** WS closes within one sweep, (c) a new `CreateSession` returns `PermissionDenied`, (d) a new device-cert redeem returns `access_denied`, (e) after **lift**, the same principal logs in and brokers a session cleanly. Plus a regression: `handleDeviceToken` runs end-to-end against a **real bbolt store** (catches the nested-txn deadlock, RT-F3). *(RT-F1/F4/F12/F20)*

> **Phase 2 — Agent enforcement hardening (lease + host-kill + durable revoke)**
> Files: `internal/agentd/offer.go` (re-verified lease loop in `runSession`), `internal/agentd/worker.go:155` (`revokeLive` reaches `shc.Kill(hostID)` when no live bridge; live+detached session list on reconnect `Hello`), `internal/controller/continuousauthz.go:115` (durable-revoke queue; stop swallowing `SendRevoke` err), controller grant minting (carry `HostSessionID` + per-session `DetachedTtlSec` for presence sessions), controller reconnect reconcile.
> **e2e:** (a) revoke a session **while the agent control channel is down**, bring it back → assert the tunnel is torn down on reconnect; (b) **detach** a session, suspend → assert the child **PID on the agent VM is gone** within `presence_ttl+sweep` (not merely the record flipped to revoked). *(RT-F5/F19, critical)*

> **Phase 3 — Presence layer with the software factor**
> Files: new `internal/controller/presence.go` (interface + registry + `softwareFactor` + config gate), `internal/policy/policy.go` (`require_presence` rule field + **restrictive merge** at the `Evaluate` block + unit test both orders), `store.go`/`session.go` (presence fields on both record types), `broker.go` (stamp `RequirePresence` + seed `LastPresenceUnix`), `continuousauthz.go` (presence predicate, applies to detached too), `console_shell.go` (watchdog presence check), proto `Heartbeat` + `POST /api/v1/session/heartbeat`, `verifyPresence` core (suspension-first, session-id-bound, fresh challenge, grace window), `config.go` (timers + validation), CLI heartbeat goroutine (`ssh.go`/`exec.go`/`attachrun.go`), SPA beacon (`session-context.tsx`).
> **e2e (the second headline assertion):** with a policy rule `require_presence: true` on a sensitive node — **stop the presence heartbeat (simulated unplug)** → assert the **CLI tunnel** drops within `presence_ttl+sweep` (~30-45s) **and** the **browser web shell** WS closes in the same window. Plus: a presence-required **detached** session, beat stopped → PTY reaped within `presence_ttl+sweep` (RT-F17/F19). Plus: policy merge test (broad-allow + narrow-require-presence in both orders → `RequirePresence==true`, RT-F6/F18). Plus: a captured heartbeat for session A rejected on session B (RT-F8). *(RT-F6/F8/F9/F11/F17)*

> **Phase 4 — YubiKey enroll endpoints (stubbed) + docs**
> Files: `MemberRecord.PresenceCredentials` + `AddPresenceCredential`/`BumpSignCounter` (membership.go), enroll begin/finish HTTP handlers (store software cred), SPA "Register security key" affordance + "presence factor: SOFTWARE" badge, `cmd/geneza/admin.go` `presence enroll`, `docs/presence-and-suspension-spec.md` capturing the seam + WebAuthn/FIDO2 `Verify` bodies + enrollment ceremonies + replay/clone model + the `allow_software` gate semantics.
> **e2e:** enroll a software cred via the endpoint; assert the principal's `MemberRecord` carries it and audit/console shows `Kind=software`; assert that with `presence.allow_software=false` a software heartbeat is **refused** (the production gate, RT-F9). Confirms the seam is wired and the gate is real — the only future work for a real YubiKey is two `Verify` impls + two ceremony bodies.

---

**Relevant absolute paths:** `/root/geneza/internal/ca/ca.go`, `/root/geneza/internal/controller/{authzstate.go(new),presence.go(new),identity.go,console_device.go,console_session.go,console_shell.go,console.go,broker.go,continuousauthz.go,store.go,session.go,membership.go,auth.go,registry.go,device.go,config.go}`, `/root/geneza/internal/agentd/{offer.go,worker.go}`, `/root/geneza/internal/sessionhost/sessionhost.go`, `/root/geneza/internal/policy/policy.go`, `/root/geneza/api/proto/geneza/v1/control.proto`, `/root/geneza/cmd/geneza/admin.go`, `/root/geneza/web/src/session-context.tsx`, `/root/geneza/docs/presence-and-suspension-spec.md (new)`.