-- Schema for the Postgres-backed controller store. Every table stores the full
-- record as `doc jsonb` (the same JSON the bbolt store persists) plus a few
-- promoted columns that exist ONLY to back an indexed lookup the code performs;
-- the promoted columns are written from the record on every upsert so they can
-- never drift from the JSON. All statements are idempotent (IF NOT EXISTS) so
-- applying the schema on every open is safe.
--
-- Per-workspace records carry workspace_id in their primary key. A query for a
-- foreign workspace returns the empty set — the same structural tenant
-- isolation the nested bbolt buckets gave by returning a nil sub-bucket.

-- Global tenant registry.
CREATE TABLE IF NOT EXISTS workspaces (
    id  text PRIMARY KEY,
    doc jsonb NOT NULL
);

-- Enrolled machines. Node ids are globally unique: the unique index both
-- resolves a node to its workspace (the unauthenticated desired-version path)
-- and forbids the same node id appearing in a second workspace.
CREATE TABLE IF NOT EXISTS nodes (
    workspace_id text NOT NULL,
    id           text NOT NULL,
    name         text,
    doc          jsonb NOT NULL,
    PRIMARY KEY (workspace_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS nodes_id_uniq ON nodes (id);
CREATE INDEX IF NOT EXISTS nodes_ws_name ON nodes (workspace_id, name);

-- Desired agent-module set per node, with a monotonic version in the doc.
CREATE TABLE IF NOT EXISTS node_modules (
    workspace_id text NOT NULL,
    node_id      text NOT NULL,
    doc          jsonb NOT NULL,
    PRIMARY KEY (workspace_id, node_id)
);

-- Brokered sessions. started_unix backs the time-ordered list views.
CREATE TABLE IF NOT EXISTS sessions (
    workspace_id text NOT NULL,
    id           text NOT NULL,
    started_unix bigint,
    doc          jsonb NOT NULL,
    PRIMARY KEY (workspace_id, id)
);
CREATE INDEX IF NOT EXISTS sessions_started ON sessions (started_unix);

-- Session-recording index. The blob itself (age ciphertext the controller cannot
-- read) lives in the blob backend at blob_ref; this row is the searchable,
-- integrity-checked metadata. sha256 is over the ciphertext; node_sig is the
-- node's attestation over (session_id, sha256, size, ended_unix). Unlike the
-- doc-jsonb tables this is fully columnar: there is no record the agent persists
-- in JSON form, only these promoted fields, so an audit query needs no extract.
CREATE TABLE IF NOT EXISTS recordings (
    workspace_id text NOT NULL,
    session_id   text NOT NULL,
    node_id      text,
    principal    text,
    action       text,
    started_unix bigint,
    ended_unix   bigint,
    size_bytes   bigint,
    sha256       text,
    node_sig     bytea,
    audit_key_id text,
    blob_ref     text,
    truncated    boolean,
    stored_unix  bigint,
    PRIMARY KEY (workspace_id, session_id)
);
CREATE INDEX IF NOT EXISTS recordings_started ON recordings (started_unix);

-- One CycloneDX SBOM per node, stored as the zstd-compressed bytes the agent
-- shipped (bytea, NOT jsonb: the blob is preserved verbatim so it stays the
-- canonical, signable artifact and is never reparsed). content_hash is the
-- agent's hash of the uncompressed document, the same value the heartbeat
-- carries so a steady-state node sends 32 bytes, not the whole SBOM.
CREATE TABLE IF NOT EXISTS node_sboms (
    workspace_id   text NOT NULL,
    node_id        text NOT NULL,
    format         text,
    content_hash   text,
    collected_unix bigint,
    sbom           bytea,
    PRIMARY KEY (workspace_id, node_id)
);

-- The flattened component index extracted from each node's SBOM: the "who has
-- package X" fast path the matcher's inner step joins against. source is part of
-- the key because one purl can come from more than one origin (an OS package and
-- a nested container image). Re-indexing a node replaces its whole set.
CREATE TABLE IF NOT EXISTS node_components (
    workspace_id text NOT NULL,
    node_id      text NOT NULL,
    purl         text NOT NULL,
    source       text NOT NULL,
    ecosystem    text,
    name         text,
    version      text,
    distro       text,
    PRIMARY KEY (workspace_id, node_id, purl, source)
);
CREATE INDEX IF NOT EXISTS node_components_pkg  ON node_components (ecosystem, name);
CREATE INDEX IF NOT EXISTS node_components_node ON node_components (workspace_id, node_id);

-- The computed answer table: one row per (node, component, cve). status is the
-- matcher's verdict (affected | not_affected | fixed | under_investigation);
-- the prioritization columns (severity, kev, epss) and the VEX justification ride
-- the row so a list view needs no second lookup. fixed_version is the DISTRO's
-- patched version, never an upstream one.
CREATE TABLE IF NOT EXISTS node_cve (
    workspace_id      text NOT NULL,
    node_id           text NOT NULL,
    cve               text NOT NULL,
    purl              text NOT NULL,
    status            text,
    severity          text,
    kev               boolean,
    epss              double precision,
    vex_justification text,
    fixed_version     text,
    matched_unix      bigint,
    PRIMARY KEY (workspace_id, node_id, cve, purl)
);
CREATE INDEX IF NOT EXISTS node_cve_cve  ON node_cve (cve, status);
CREATE INDEX IF NOT EXISTS node_cve_node ON node_cve (workspace_id, node_id, status);

-- Vuln advisories, written by any feed (open or paid) through one interface. The
-- full advisory is kept as doc jsonb (it carries its upstream source's own
-- license, surfaced per-record); the promoted columns back the by-package resolve
-- the matcher does. Global, not per-workspace: an advisory is the same fact for
-- every tenant.
CREATE TABLE IF NOT EXISTS advisories (
    id            text PRIMARY KEY,
    source        text,
    ecosystem     text,
    package_name  text,
    doc           jsonb NOT NULL,
    modified_unix bigint
);
CREATE INDEX IF NOT EXISTS advisories_pkg ON advisories (ecosystem, package_name);

-- A container image's flattened component set keyed by content digest, stored ONCE
-- no matter how many nodes (across any tenant) run it: a sha256 digest is the same
-- bytes everywhere, so the components are a property of the digest, not of each node.
-- Reached only through the per-workspace node_images association below, so the global
-- keying never crosses tenants. source is part of the key because one purl can arrive
-- under more than one image source string.
CREATE TABLE IF NOT EXISTS image_components (
    digest    text NOT NULL,
    purl      text NOT NULL,
    source    text NOT NULL,
    ecosystem text,
    name      text,
    version   text,
    distro    text,
    PRIMARY KEY (digest, purl, source)
);
CREATE INDEX IF NOT EXISTS image_components_pkg ON image_components (ecosystem, name);

-- The per-workspace node->digest association: which image digests a node currently
-- runs. The only tenant-scoped link to the global image tables, so a per-node read
-- fans a digest's findings to its nodes without re-storing the image set. Replace-set
-- per node, so a node that stops running a digest drops the association.
CREATE TABLE IF NOT EXISTS node_images (
    workspace_id text NOT NULL,
    node_id      text NOT NULL,
    digest       text NOT NULL,
    PRIMARY KEY (workspace_id, node_id, digest)
);
CREATE INDEX IF NOT EXISTS node_images_digest ON node_images (workspace_id, digest);

-- The computed verdicts for an image digest, matched ONCE per digest and fanned to
-- associated nodes on read. Global like image_components and reached the same
-- ws-scoped way through node_images.
CREATE TABLE IF NOT EXISTS image_cve (
    digest            text NOT NULL,
    cve               text NOT NULL,
    purl              text NOT NULL,
    status            text,
    severity          text,
    kev               boolean,
    epss              double precision,
    vex_justification text,
    fixed_version     text,
    matched_unix      bigint,
    PRIMARY KEY (digest, cve, purl)
);
CREATE INDEX IF NOT EXISTS image_cve_cve ON image_cve (cve, status);

CREATE TABLE IF NOT EXISTS networks (
    workspace_id text NOT NULL,
    id           text NOT NULL,
    doc          jsonb NOT NULL,
    PRIMARY KEY (workspace_id, id)
);

CREATE TABLE IF NOT EXISTS subnets (
    workspace_id text NOT NULL,
    id           text NOT NULL,
    doc          jsonb NOT NULL,
    PRIMARY KEY (workspace_id, id)
);

-- Declared so the routing data plane is drop-in; no rows are written yet.
CREATE TABLE IF NOT EXISTS routes (
    workspace_id text NOT NULL,
    id           text NOT NULL,
    doc          jsonb NOT NULL,
    PRIMARY KEY (workspace_id, id)
);

-- The forwarding table, keyed so a per-Network (vni) list is a primary-key
-- range scan rather than a per-row filter.
CREATE TABLE IF NOT EXISTS bindings (
    workspace_id text NOT NULL,
    vni          bigint NOT NULL,
    node_id      text NOT NULL,
    doc          jsonb NOT NULL,
    PRIMARY KEY (workspace_id, vni, node_id)
);

-- Workspace membership. provider/subject are real columns (the bbolt key
-- forbade ':' only because it flattened them into one string).
CREATE TABLE IF NOT EXISTS members (
    workspace_id text NOT NULL,
    provider     text NOT NULL,
    subject      text NOT NULL,
    doc          jsonb NOT NULL,
    PRIMARY KEY (workspace_id, provider, subject)
);
-- Which workspaces a principal belongs to, without scanning every workspace.
CREATE INDEX IF NOT EXISTS members_principal ON members (provider, subject);

-- Join tokens; each carries its workspace in the doc.
CREATE TABLE IF NOT EXISTS tokens (
    token text PRIMARY KEY,
    doc   jsonb NOT NULL
);

-- Cloud-qualified source bindings (an external identity source -> a workspace).
CREATE TABLE IF NOT EXISTS source_bindings (
    key text PRIMARY KEY,
    doc jsonb NOT NULL
);

-- OpenStack vendordata mint-once dedupe (token + metadata in the doc).
CREATE TABLE IF NOT EXISTS os_enroll (
    key          text PRIMARY KEY,
    created_unix bigint,
    doc          jsonb NOT NULL
);

-- Leaf-cert revocation denylist; the primary key serves the hot per-RPC check.
CREATE TABLE IF NOT EXISTS revoked_certs (
    serial text PRIMARY KEY,
    doc    jsonb NOT NULL
);

-- Persistent authorization deny. provider is the NORMALIZED provider (the
-- 'device:' prefix stripped) so the write key and every read/sweep key match.
CREATE TABLE IF NOT EXISTS suspensions (
    workspace_id   text NOT NULL,
    provider       text NOT NULL,
    subject        text NOT NULL,
    suspended_unix bigint,
    doc            jsonb NOT NULL,
    PRIMARY KEY (workspace_id, provider, subject)
);

-- Node drift quarantine: the node-scoped sibling of a suspension. A node the
-- controller auto-quarantines for drift (binary tamper / identity clone) — or an
-- admin manually denies — gets a sticky deny row here, cleared only when an admin
-- re-approves. host_uuid is the stable hardware evidence that keeps a re-enrolling
-- quarantined host out of auto-approval behind a fresh node id.
CREATE TABLE IF NOT EXISTS node_quarantines (
    workspace_id     text NOT NULL,
    node_id          text NOT NULL,
    host_uuid        text,
    quarantined_unix bigint,
    doc              jsonb NOT NULL,
    PRIMARY KEY (workspace_id, node_id)
);

-- Browser login sessions. provider is normalized (device: stripped) so the
-- by-principal revoke matches; the other columns back the by-user revoke and
-- the expiry sweep.
CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash   text PRIMARY KEY,
    user_name    text,
    provider     text,
    subject      text,
    expires_unix bigint,
    doc          jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_sessions_user      ON auth_sessions (user_name);
CREATE INDEX IF NOT EXISTS auth_sessions_principal ON auth_sessions (provider, subject);
CREATE INDEX IF NOT EXISTS auth_sessions_expires   ON auth_sessions (expires_unix);

-- One-time WebSocket-shell tickets.
CREATE TABLE IF NOT EXISTS ws_tickets (
    ticket_hash  text PRIMARY KEY,
    expires_unix bigint,
    doc          jsonb NOT NULL
);

-- In-flight CLI device-grant logins. The user_code reverse index is folded
-- into a unique index on this table.
CREATE TABLE IF NOT EXISTS device_codes (
    device_hash    text PRIMARY KEY,
    user_code_hash text NOT NULL,
    expires_unix   bigint,
    doc            jsonb NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS device_codes_user    ON device_codes (user_code_hash);
CREATE INDEX        IF NOT EXISTS device_codes_expires ON device_codes (expires_unix);

-- Trusted-dashboard handoff codes (resolved-but-not-yet-minted sessions).
CREATE TABLE IF NOT EXISTS handoff_codes (
    code_hash    text PRIMARY KEY,
    expires_unix bigint,
    doc          jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS handoff_codes_expires ON handoff_codes (expires_unix);

-- Heterogeneous raw settings (rollout versions, canary set).
CREATE TABLE IF NOT EXISTS settings (
    key   text PRIMARY KEY,
    value bytea
);

-- Opaque signed manifests, identical for all tenants.
CREATE TABLE IF NOT EXISTS artifacts (
    key    text PRIMARY KEY,
    signed bytea
);

-- The signed cluster-config trust set is a single row guarded by a version
-- compare-and-swap so exactly one writer wins each version bump.
-- Split-mode trust anchors live in the SAME row as the routine map so a routine
-- map and its anchor advance under one serializable transaction (the cross-binding
-- invariant: a stored map's anchor reference always names the stored anchor).
-- Legacy (un-split) deployments leave anchor_version 0 / anchor_signed NULL and are
-- byte-for-byte unchanged.
CREATE TABLE IF NOT EXISTS cluster_config (
    id             int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    version        bigint NOT NULL,
    signed         bytea  NOT NULL,
    anchor_version bigint NOT NULL DEFAULT 0,
    anchor_signed  bytea
);

-- Which controller owns each agent's live control stream. node_id is globally
-- unique, so the owning controller is cross-tenant routing metadata. The epoch is a
-- fence token: every (re)connect bumps it so a superseded stream is detectable.
CREATE TABLE IF NOT EXISTS agent_affinity (
    node_id      text PRIMARY KEY,
    controller_id   text   NOT NULL,
    epoch        bigint NOT NULL,
    claimed_unix bigint
);
CREATE INDEX IF NOT EXISTS agent_affinity_gw ON agent_affinity (controller_id);

-- Durable copy of each node's advertised service set, stamped with the claiming
-- epoch, so a named-service resolve works for an agent held by another controller.
CREATE TABLE IF NOT EXISTS advertised_services (
    workspace_id text NOT NULL,
    node_id      text NOT NULL,
    epoch        bigint NOT NULL,
    doc          jsonb  NOT NULL,
    PRIMARY KEY (workspace_id, node_id)
);

-- Relay fleet presence: each relay heartbeats its signed-map entry here and the
-- leader assembles the rows into the signed relay map. Eventual presence data,
-- not a deny-path; lastseen_unix is promoted for the staleness sweep.
CREATE TABLE IF NOT EXISTS relays (
    region_id     text NOT NULL,
    relay_id      text NOT NULL,
    lastseen_unix bigint,
    doc           jsonb NOT NULL,
    PRIMARY KEY (region_id, relay_id)
);

CREATE TABLE IF NOT EXISTS agent_presence (
    node_id       text NOT NULL,
    lastseen_unix bigint,
    doc           jsonb NOT NULL,
    PRIMARY KEY (node_id)
);

-- Controller fleet presence (eventual): each controller self-heartbeats its dialable
-- endpoint; the rows assemble into the signed ControllerEndpoints discovery set.
CREATE TABLE IF NOT EXISTS controllers (
    controller_id    text PRIMARY KEY,
    lastseen_unix bigint,
    doc           jsonb NOT NULL
);

-- Managed-domain certificates: one publicly-trusted cert per id (wildcard per
-- workspace today, funnel leaves later). The chain+key bytes live in the blob
-- store; this row indexes renewal state and the blob ref.
CREATE TABLE IF NOT EXISTS managed_certs (
    id            text PRIMARY KEY,
    workspace_id  text NOT NULL,
    notafter_unix bigint,
    doc           jsonb NOT NULL
);

-- Workspace subdomain reservations: a (domain, label) is globally unique (the
-- PK), a workspace holds at most a fixed number, and the cert manager issues a
-- wildcard per row.
CREATE TABLE IF NOT EXISTS subdomain_reservations (
    domain       text NOT NULL,
    label        text NOT NULL,
    workspace_id text NOT NULL,
    doc          jsonb NOT NULL,
    PRIMARY KEY (domain, label)
);
CREATE INDEX IF NOT EXISTS subdomain_reservations_ws ON subdomain_reservations (workspace_id);

-- Funnel bindings: a public hostname (under a reservation) exposed to a target
-- service on the overlay. Hostname is globally unique; one narrow leaf per row.
CREATE TABLE IF NOT EXISTS funnel_bindings (
    hostname     text PRIMARY KEY,
    workspace_id text NOT NULL,
    doc          jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS funnel_bindings_ws ON funnel_bindings (workspace_id);
