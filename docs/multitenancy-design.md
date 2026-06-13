# Multi-tenancy (workspaces) — design + phased plan

Status: **design approved (2026-06-12), not yet implemented.** Decisional-agent
output; this is the source of truth for the build. A *workspace* (a.k.a.
organization; Tailscale's "tailnet") is the isolation boundary owning a set of
machines, users, policy, services, overlay address space, DNS names, sessions,
and audit.

## Decisions (one line each)
- **One gateway hosts many workspaces** (not workspace==gateway) — lowest
  operational burden; the store/relay/CA are already shareable.
- **Workspace is derived SERVER-SIDE from the verified cert, never
  client-supplied** — the fail-closed core (same reasoning the broker uses to
  ignore client-supplied `client_path`).
- **Store isolation = nested bbolt sub-buckets per workspace** — cross-tenant
  access is *structurally* "does not exist" (NotFound), not a filter that can be
  forgotten. Keep a `WorkspaceID` field on records as defense-in-depth/audit.
- **Users↔workspaces = a membership table** (`members` bucket, many-to-many);
  OIDC claim/group is an *accelerator* matched against membership, never
  sufficient alone. **A machine belongs to exactly one** workspace (the join
  token / instance-identity carries it).
- **Shared two-tier CA with workspace in the leaf identity URI**:
  `geneza://user/<workspace>/<name>`, `geneza://node/<workspace>/<id>` (gateway/
  relay certs stay workspace-less). Per-workspace CA is a deferred SaaS option
  behind the same `ca.Profile.Workspace` seam.
- **Per-workspace**: policy engine (map workspaceID→Engine), overlay-IP pool
  (allocator per workspace; each may reuse 100.64.0.0/24 — meaning is only
  within the tunnel), DNS zone, node admission gate. **Global**: artifacts +
  rollout/desired-version (binary is identical + signed for all tenants), the
  hash-chained audit (one chain; add `AuditEvent.Workspace`, filter views).
- **Roles are per-workspace** (admin in A grants nothing in B). A rare
  **gateway operator/super-admin** (minted via break-glass `IssueUserCert`) is
  the only principal that creates workspaces / sees across them.
- **Grant key + artifact root stay shared**; optionally add `SessionGrant.WorkspaceID`
  + an agent-side assertion in `grant.Validate` to close the isolation loop at
  the node too.

## Migration (zero-downtime, keeps the lab green)
- `defaults.DefaultWorkspaceID = "default"`. One-shot, idempotent store
  migration in `OpenStore`/`New`: move existing flat node/token/session/module
  records under `workspaces/default`, stamp `WorkspaceID="default"`. Settings +
  artifacts stay global.
- `PeerIdentity` treats a **2-segment URI as `default`** → existing certs keep
  working until their short TTL expires (≤24h node / ≤8h user) and are reissued
  with the 3-segment URI naturally. No flag day.
- Gateway config with no workspace section == today (one `default` workspace,
  `policy_file` is its policy). Lab deploy/e2e/tuf-proof/enroll-proof unchanged.

## Fail-closed cross-tenant isolation (the security core)
1. Cert carries workspace (URI). `auth.go` puts `ca.Identity{Workspace}` in ctx
   exactly as it carries name/roles. No `workspace_id` on request protos; if a
   client sends one it is ignored. (Login/enroll are the only exceptions —
   `LoginRequest.workspace` selects *which membership*, validated against the
   table; the token is workspace-bound at mint.)
2. Broker uses `ident.Workspace` for EVERY store call (`FindNode`, `resolveService`,
   `PutSession`) and `engine(ident.Workspace).Evaluate(...)`. A user in A asking
   for B's node id gets NotFound — structurally.
3. Node control: hello node_id must match the cert AND the record must exist in
   the cert's workspace. Registry keyed by `(workspace,nodeID)`.
4. Continuous-authz sweeps per workspace with that workspace's policy;
   `revokeUser` scoped to `(workspace,user)`.
5. (Recommended) `SessionGrant.WorkspaceID` + agent re-assert → forged/mis-scoped
   grant also fails at the node (defense in depth).

## Phased plan (each phase ends green on go test + e2e + tuf-proof + enroll-proof)
- **Phase 1 — store + identity scoping, single `default` workspace, no behavior
  change (RISKIEST).** Add `WorkspaceID` to records + `workspaces`/`members`
  buckets; nested sub-buckets; `workspaceID` param on every Store method; the
  migration. `ca.Profile.Workspace` + 3-segment URI + 2-segment→default compat.
  `handleLogin`/`enroll` resolve workspace (default). Broker/nodecontrol/registry/
  continuousauthz/adminapi/userapi/console scoped to caller workspace. Audit
  `Workspace` field. Update test constructors to pass `default`; add the
  flagship **cross-workspace isolation test** (cert in A cannot FindNode/broker
  into B). Behavior byte-identical (all resolves to `default`), so e2e passes.
- **Phase 2 — multiple workspaces + operator mgmt (no UI).** Operator trust
  level + `CreateWorkspace/ListWorkspaces/AddMember/RemoveMember/DeleteWorkspace`;
  real membership resolution; `LoginRequest.workspace`+`available_workspaces`;
  per-workspace policy (file-per-ws or store-backed); `geneza login --workspace`,
  `geneza admin workspaces ...`, `client.Profile.Workspace`. Multi-workspace
  isolation tests.
- **Phase 3 — console UI + per-tenant DNS/overlay.** Workspace switcher
  (`header.tsx`/`user-menu.tsx`), `/api/v1/me` returns workspaces, pages inherit
  scope (keep `App.tsx` eager — web-shell note). Per-tenant DNS (miekg/dns) (see
  [dns-design.md]) + per-workspace overlay CIDR; optional store-backed
  editable policy.

## Riskiest changes / mitigations
- Pervasive `Store` signature change → one mechanical compiler-enforced pass;
  default-everywhere keeps behavior identical; migration idempotent+guarded.
- Cert URI format → 2-segment→default compat = no flag day.
- Per-workspace policy resolution (reload + continuous-authz depend on it) →
  phase 1 keeps a single engine behind `engine(workspaceID)`.
- Forgetting to scope one call site = fail-open → nested buckets make workspace
  naming mandatory; cross-workspace isolation test as a CI gate.

Critical files: `internal/gateway/store.go` (the boundary + migration),
`internal/gateway/broker.go` (fail-closed scoping), `internal/ca/ca.go`
(workspace in URI), `internal/gateway/auth.go`+`identity.go` (server-derived
workspace), `internal/gateway/server.go` + `api/proto/.../control.proto`
(per-workspace policy/overlay; login selector + operator RPCs).
