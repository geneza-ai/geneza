-- MySQL/MariaDB schema for the controller store, the engine-equivalent of
-- sqlschema.sql. Every table stores the full record as `doc JSON` (the same JSON
-- the bbolt store persists) plus the few promoted columns that back an indexed
-- lookup, written from the record on every upsert so they cannot drift.
--
-- Text key/lookup columns carry an EXPLICIT binary collation. Without it MariaDB's
-- default collation is case-INSENSITIVE, so 'deadbeef' and 'DEADBEEF' would collide
-- into one row — a denylist that lets a different cert through. ASCII-only columns
-- (hashes, serials, codes, tokens, ids) use ascii_bin; columns that may hold
-- Unicode identity (name, subject, user_name, provider) use utf8mb4_bin.
--
-- MySQL 8 / MariaDB have no CREATE INDEX IF NOT EXISTS, so every secondary index is
-- inlined in its CREATE TABLE (which is itself IF NOT EXISTS, so a re-open is safe).

-- Global tenant registry.
CREATE TABLE IF NOT EXISTS workspaces (
    id  VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
    doc JSON NOT NULL
);

-- Enrolled machines. Node ids are globally unique.
CREATE TABLE IF NOT EXISTS nodes (
    workspace_id VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    id           VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    name         VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
    doc          JSON NOT NULL,
    PRIMARY KEY (workspace_id, id),
    UNIQUE KEY nodes_id_uniq (id),
    KEY nodes_ws_name (workspace_id, name)
);

-- Desired agent-module set per node, with a monotonic version in the doc.
CREATE TABLE IF NOT EXISTS node_modules (
    workspace_id VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    node_id      VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    doc          JSON NOT NULL,
    PRIMARY KEY (workspace_id, node_id)
);

-- Brokered sessions. started_unix backs the time-ordered list views.
CREATE TABLE IF NOT EXISTS sessions (
    workspace_id VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    id           VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    started_unix BIGINT,
    doc          JSON NOT NULL,
    PRIMARY KEY (workspace_id, id),
    KEY sessions_started (started_unix)
);

-- Session-recording index. Fully columnar (no doc JSON): the blob is age
-- ciphertext the controller cannot read, stored at blob_ref; this row is the
-- searchable, integrity-checked metadata. ascii_bin keys/hashes are
-- case-significant; principal may hold Unicode identity (utf8mb4_bin); node_sig
-- is the raw ECDSA signature (LONGBLOB).
CREATE TABLE IF NOT EXISTS recordings (
    workspace_id VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    session_id   VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    node_id      VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin,
    principal    VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
    action       VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin,
    started_unix BIGINT,
    ended_unix   BIGINT,
    size_bytes   BIGINT,
    sha256       VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin,
    node_sig     LONGBLOB,
    audit_key_id VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin,
    blob_ref     VARCHAR(512) CHARACTER SET ascii   COLLATE ascii_bin,
    truncated    BOOLEAN,
    stored_unix  BIGINT,
    PRIMARY KEY (workspace_id, session_id),
    KEY recordings_started (started_unix)
);

-- One CycloneDX SBOM per node, the zstd-compressed bytes verbatim (LONGBLOB, the
-- engine-equivalent of Postgres bytea) so the document stays the canonical,
-- signable artifact and is never reparsed. content_hash mirrors the heartbeat's
-- hash so a steady-state node ships 32 bytes, not the whole SBOM.
CREATE TABLE IF NOT EXISTS node_sboms (
    workspace_id   VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    node_id        VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    format         VARCHAR(64)  CHARACTER SET ascii   COLLATE ascii_bin,
    content_hash   VARCHAR(128) CHARACTER SET ascii   COLLATE ascii_bin,
    collected_unix BIGINT,
    sbom           LONGBLOB,
    PRIMARY KEY (workspace_id, node_id)
);

-- The flattened component index extracted from each node's SBOM: the "who has
-- package X" fast path. source is part of the key because one purl can arrive
-- from more than one origin (an OS package and a nested container image).
-- ecosystem is an ASCII OSV label; name may hold a Unicode package identity.
CREATE TABLE IF NOT EXISTS node_components (
    workspace_id VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    node_id      VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    purl         VARCHAR(512) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    source       VARCHAR(128) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    ecosystem    VARCHAR(64)  CHARACTER SET ascii   COLLATE ascii_bin,
    name         VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
    version      VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
    distro       VARCHAR(128) CHARACTER SET ascii   COLLATE ascii_bin,
    PRIMARY KEY (workspace_id, node_id, purl, source),
    KEY node_components_pkg  (ecosystem, name),
    KEY node_components_node (workspace_id, node_id)
);

-- The computed answer table: one row per (node, component, cve). status is the
-- matcher's verdict; the prioritization columns and the VEX justification ride the
-- row so a list view needs no second lookup. fixed_version is the DISTRO's patched
-- version, never an upstream one.
CREATE TABLE IF NOT EXISTS node_cve (
    workspace_id      VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    node_id           VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    cve               VARCHAR(64)  CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    purl              VARCHAR(512) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    status            VARCHAR(32)  CHARACTER SET ascii   COLLATE ascii_bin,
    severity          VARCHAR(32)  CHARACTER SET ascii   COLLATE ascii_bin,
    kev               BOOLEAN,
    epss              DOUBLE,
    vex_justification VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
    fixed_version     VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
    matched_unix      BIGINT,
    PRIMARY KEY (workspace_id, node_id, cve, purl),
    KEY node_cve_cve  (cve, status),
    KEY node_cve_node (workspace_id, node_id, status)
);

-- Vuln advisories, written by any feed (open or paid) through one interface. The
-- full advisory is kept as doc JSON (it carries its upstream source's own license,
-- surfaced per-record); the promoted columns back the by-package resolve. Global,
-- not per-workspace: an advisory is the same fact for every tenant.
CREATE TABLE IF NOT EXISTS advisories (
    id            VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin   PRIMARY KEY,
    source        VARCHAR(64)  CHARACTER SET ascii   COLLATE ascii_bin,
    ecosystem     VARCHAR(64)  CHARACTER SET ascii   COLLATE ascii_bin,
    package_name  VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
    doc           JSON NOT NULL,
    modified_unix BIGINT,
    KEY advisories_pkg (ecosystem, package_name)
);

-- A container image's flattened component set keyed by content digest, stored ONCE
-- no matter how many nodes (across any tenant) run it: a sha256 digest is the same
-- bytes everywhere, so the components are a property of the digest, not of each node.
-- Reached only through the per-workspace node_images association below, so the global
-- keying never crosses tenants. source is part of the key because one purl can arrive
-- under more than one image source string.
CREATE TABLE IF NOT EXISTS image_components (
    digest    VARCHAR(128) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    purl      VARCHAR(512) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    source    VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    ecosystem VARCHAR(64)  CHARACTER SET ascii   COLLATE ascii_bin,
    name      VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
    version   VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
    distro    VARCHAR(128) CHARACTER SET ascii   COLLATE ascii_bin,
    PRIMARY KEY (digest, purl, source),
    KEY image_components_pkg (ecosystem, name)
);

-- The per-workspace node->digest association: which image digests a node currently
-- runs. The only tenant-scoped link to the global image tables, so a per-node read
-- fans a digest's findings to its nodes without re-storing the image set. Replace-set
-- per node, so a node that stops running a digest drops the association.
CREATE TABLE IF NOT EXISTS node_images (
    workspace_id VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    node_id      VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    digest       VARCHAR(128) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    PRIMARY KEY (workspace_id, node_id, digest),
    KEY node_images_digest (workspace_id, digest)
);

-- The computed verdicts for an image digest, matched ONCE per digest and fanned to
-- associated nodes on read. Global like image_components and reached the same
-- ws-scoped way through node_images.
CREATE TABLE IF NOT EXISTS image_cve (
    digest            VARCHAR(128) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    cve               VARCHAR(64)  CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    purl              VARCHAR(512) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    status            VARCHAR(32)  CHARACTER SET ascii   COLLATE ascii_bin,
    severity          VARCHAR(32)  CHARACTER SET ascii   COLLATE ascii_bin,
    kev               BOOLEAN,
    epss              DOUBLE,
    vex_justification VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
    fixed_version     VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
    matched_unix      BIGINT,
    PRIMARY KEY (digest, cve, purl),
    KEY image_cve_cve (cve, status)
);

CREATE TABLE IF NOT EXISTS networks (
    workspace_id VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    id           VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    doc          JSON NOT NULL,
    PRIMARY KEY (workspace_id, id)
);

CREATE TABLE IF NOT EXISTS subnets (
    workspace_id VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    id           VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    doc          JSON NOT NULL,
    PRIMARY KEY (workspace_id, id)
);

-- Declared so the routing data plane is drop-in; no rows are written yet.
CREATE TABLE IF NOT EXISTS routes (
    workspace_id VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    id           VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    doc          JSON NOT NULL,
    PRIMARY KEY (workspace_id, id)
);

-- The forwarding table, keyed so a per-Network (vni) list is a primary-key range
-- scan rather than a per-row filter.
CREATE TABLE IF NOT EXISTS bindings (
    workspace_id VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    vni          BIGINT NOT NULL,
    node_id      VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    doc          JSON NOT NULL,
    PRIMARY KEY (workspace_id, vni, node_id)
);

-- Workspace membership. provider/subject may hold Unicode identity values.
CREATE TABLE IF NOT EXISTS members (
    workspace_id VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    provider     VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    subject      VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    doc          JSON NOT NULL,
    PRIMARY KEY (workspace_id, provider, subject),
    KEY members_principal (provider, subject)
);

-- Join tokens; each carries its workspace in the doc.
CREATE TABLE IF NOT EXISTS tokens (
    token VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
    doc   JSON NOT NULL
);

-- Cloud-qualified source bindings (an external identity source -> a workspace).
CREATE TABLE IF NOT EXISTS source_bindings (
    `key` VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin PRIMARY KEY,
    doc   JSON NOT NULL
);

-- OpenStack vendordata mint-once dedupe (token + metadata in the doc).
CREATE TABLE IF NOT EXISTS os_enroll (
    `key`        VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin PRIMARY KEY,
    created_unix BIGINT,
    doc          JSON NOT NULL
);

-- Leaf-cert revocation denylist; the primary key serves the hot per-RPC check.
-- The binary collation is load-bearing: a serial is hex and case-significant.
CREATE TABLE IF NOT EXISTS revoked_certs (
    serial VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
    doc    JSON NOT NULL
);

-- Persistent authorization deny. provider is the NORMALIZED provider so the write
-- key and every read/sweep key match.
CREATE TABLE IF NOT EXISTS suspensions (
    workspace_id   VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    provider       VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    subject        VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    suspended_unix BIGINT,
    doc            JSON NOT NULL,
    PRIMARY KEY (workspace_id, provider, subject)
);

-- Node drift quarantine: the node-scoped sibling of a suspension (see the
-- postgres schema for the full note).
CREATE TABLE IF NOT EXISTS node_quarantines (
    workspace_id     VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    node_id          VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin   NOT NULL,
    host_uuid        VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
    quarantined_unix BIGINT,
    doc              JSON NOT NULL,
    PRIMARY KEY (workspace_id, node_id)
);

-- Browser login sessions.
CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash   VARCHAR(255) CHARACTER SET ascii   COLLATE ascii_bin   PRIMARY KEY,
    user_name    VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
    provider     VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
    subject      VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
    expires_unix BIGINT,
    doc          JSON NOT NULL,
    KEY auth_sessions_user      (user_name),
    KEY auth_sessions_principal (provider, subject),
    KEY auth_sessions_expires   (expires_unix)
);

-- One-time WebSocket-shell tickets.
CREATE TABLE IF NOT EXISTS ws_tickets (
    ticket_hash  VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
    expires_unix BIGINT,
    doc          JSON NOT NULL
);

-- In-flight CLI device-grant logins. The user_code reverse index is a unique key.
CREATE TABLE IF NOT EXISTS device_codes (
    device_hash    VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
    user_code_hash VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_unix   BIGINT,
    doc            JSON NOT NULL,
    UNIQUE KEY device_codes_user    (user_code_hash),
    KEY          device_codes_expires (expires_unix)
);

-- Trusted-dashboard handoff codes (resolved-but-not-yet-minted sessions).
CREATE TABLE IF NOT EXISTS handoff_codes (
    code_hash    VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
    expires_unix BIGINT,
    doc          JSON NOT NULL,
    KEY handoff_codes_expires (expires_unix)
);

-- Heterogeneous raw settings (rollout versions, canary set).
CREATE TABLE IF NOT EXISTS settings (
    `key` VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
    value LONGBLOB
);

-- Opaque signed manifests, identical for all tenants.
CREATE TABLE IF NOT EXISTS artifacts (
    `key`  VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
    signed LONGBLOB
);

-- The signed cluster-config trust set is a single row guarded by a version
-- compare-and-swap so exactly one writer wins each version bump.
-- Split-mode trust anchors share the routine map's row so both advance under one
-- transaction (the cross-binding invariant). Legacy deployments leave anchor_version
-- 0 / anchor_signed NULL, byte-for-byte unchanged.
CREATE TABLE IF NOT EXISTS cluster_config (
    id             INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    version        BIGINT   NOT NULL,
    signed         LONGBLOB NOT NULL,
    anchor_version BIGINT   NOT NULL DEFAULT 0,
    anchor_signed  LONGBLOB
);

-- Which controller owns each agent's live control stream.
CREATE TABLE IF NOT EXISTS agent_affinity (
    node_id      VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
    controller_id   VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    epoch        BIGINT NOT NULL,
    claimed_unix BIGINT,
    KEY agent_affinity_gw (controller_id)
);

-- Durable copy of each node's advertised service set, stamped with the claiming
-- epoch, so a named-service resolve works for an agent held by another controller.
CREATE TABLE IF NOT EXISTS advertised_services (
    workspace_id VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    node_id      VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    epoch        BIGINT NOT NULL,
    doc          JSON   NOT NULL,
    PRIMARY KEY (workspace_id, node_id)
);

-- Relay fleet presence (eventual): each relay heartbeats its signed-map entry.
CREATE TABLE IF NOT EXISTS relays (
    region_id     VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    relay_id      VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    lastseen_unix BIGINT,
    doc           JSON NOT NULL,
    PRIMARY KEY (region_id, relay_id)
);

-- Agent fleet presence (eventual): each controller records its homed agents'
-- heartbeats (version/health/freshness) so a rollout wave's health is fleet-wide.
CREATE TABLE IF NOT EXISTS agent_presence (
    node_id       VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    lastseen_unix BIGINT,
    doc           JSON NOT NULL,
    PRIMARY KEY (node_id)
);

-- Controller fleet presence (eventual): each controller self-heartbeats its endpoint.
CREATE TABLE IF NOT EXISTS controllers (
    controller_id    VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
    lastseen_unix BIGINT,
    doc           JSON NOT NULL
);

-- Managed-domain certificates: one publicly-trusted cert per id (wildcard per
-- workspace today, funnel leaves later). The chain+key bytes live in the blob
-- store; this row indexes renewal state and the blob ref.
CREATE TABLE IF NOT EXISTS managed_certs (
    id            VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
    workspace_id  VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    notafter_unix BIGINT,
    doc           JSON NOT NULL
);

-- Workspace subdomain reservations: a (domain, label) is globally unique (the
-- PK), a workspace holds at most a fixed number, and the cert manager issues a
-- wildcard per row.
CREATE TABLE IF NOT EXISTS subdomain_reservations (
    domain       VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    label        VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    workspace_id VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    doc          JSON NOT NULL,
    PRIMARY KEY (domain, label),
    INDEX subdomain_reservations_ws (workspace_id)
);

-- Funnel bindings: a public hostname (under a reservation) exposed to a target
-- service on the overlay. Hostname is globally unique; one narrow leaf per row.
CREATE TABLE IF NOT EXISTS funnel_bindings (
    hostname     VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
    workspace_id VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    doc          JSON NOT NULL,
    INDEX funnel_bindings_ws (workspace_id)
);
