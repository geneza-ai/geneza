package controller

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"geneza.io/internal/types"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// sqlStore is the SQL-backed persistence backend, the opt-in alternative to the
// default single-node bbolt store. It runs on Postgres OR MariaDB/MySQL from one
// codebase: a per-engine dialect adapts the shared query vocabulary, and every
// record is stored as the same JSON bbolt persists (in a JSON column) so all three
// backends are behaviourally identical. The single-writer guarantees bbolt gave for
// free — single-spend tokens, the device-grant redeem, the first-admin election,
// the config-version bump — are re-established here as one SERIALIZABLE transaction
// per invariant, so a second concurrent writer either serializes after the first or
// is rejected with a clean deny, never a torn read-modify-write. It is selected by
// `store: postgres` (or `mariadb`/`mysql`) in the controller config.
type sqlStore struct {
	db      *sql.DB
	dialect dialect
	dsn     string // retained so the Postgres realtime bus can open its own LISTEN pool
	bus     realtimeBus
}

// maxSerialRetries bounds how many times a SERIALIZABLE transaction is retried
// after a serialization failure before the caller sees the error. A real
// conflict resolves in one or two retries; the cap stops a pathological livelock.
// MySQL/MariaDB under SERIALIZABLE surfaces contention as deadlocks far more
// readily than Postgres, so the budget is generous and each retry backs off a
// randomized amount to break a deadlock storm of many writers on one key.
const maxSerialRetries = 50

// reconcileLockKey is the fixed 64-bit key for the transient advisory lock that
// debounces the fleet-map rebuild ("geneza" in ASCII). Every controller contends on
// the same key, grabs it for one rebuild, then releases it — no sticky leader.
const reconcileLockKey int64 = 0x67656e657a61

// vulnSyncLockKey is a distinct fixed key for the transient advisory lock that
// debounces the daily vuln-feed sync, so N flat controllers do not all fetch and
// re-match at once. It is separate from reconcileLockKey so a feed sync and a
// fleet-map rebuild never block each other.
const vulnSyncLockKey int64 = 0x67656e657a62

// managedCertLockKey is a distinct fixed key for the transient advisory lock that
// debounces ACME issuance/renewal. It is separate so the slow DNS-01 loop (which
// runs for minutes per cert) never blocks the fleet-map rebuild or the feed sync.
const managedCertLockKey int64 = 0x67656e657a63

// errClusterConfigConflict is returned when a config-version compare-and-swap
// loses the race because another writer already advanced the version. The
// caller re-reads and re-converges; it is never a hard failure.
var errClusterConfigConflict = errors.New("cluster config version conflict")

// OpenSQLStore opens a database/sql pool against dsn for the named backend
// (postgres | mariadb | mysql), applies the engine's schema (idempotent CREATE
// TABLE IF NOT EXISTS), and returns a Store. An unreachable DSN is a hard error
// here — the SQL backend fails closed on open rather than degrading to a
// stale-allow. The realtime bus (LISTEN/NOTIFY on Postgres, a poll loop on MySQL)
// is established lazily by the router, not here.
func OpenSQLStore(ctx context.Context, backend, dsn string) (Store, error) {
	d, err := dialectFor(backend)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open(d.driver(), dsn)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("store unreachable: %w", err)
	}
	if _, err := db.ExecContext(ctx, d.schema()); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply store schema: %w", err)
	}
	return &sqlStore{db: db, dialect: d, dsn: dsn}, nil
}

// dialectFor maps a configured backend name to its dialect. The two MySQL aliases
// pick the same dialect; an unknown name is a hard error, never a silent fallback.
func dialectFor(backend string) (dialect, error) {
	switch backend {
	case "postgres":
		return pgDialect{}, nil
	case "mariadb", "mysql":
		return myDialect{}, nil
	default:
		return nil, fmt.Errorf("unknown sql backend %q (valid: postgres, mariadb, mysql)", backend)
	}
}

func (s *sqlStore) Close() error {
	if s.bus != nil {
		s.bus.Close()
	}
	return s.db.Close()
}

// rewrite adapts a canonical (Postgres-form) query to the active engine. Use it
// only for parameter-free queries; parameterized queries go through exec/query/
// queryRow so the dialect can reorder arguments for MySQL's by-appearance binding.
func (s *sqlStore) rewrite(q string) string { return s.dialect.rewrite(q) }

// exec / query / queryRow run a canonical query against any sqlExec, adapting the
// SQL text and the argument order to the active engine first.
func (s *sqlStore) exec(ctx context.Context, ex sqlExec, q string, args ...any) (sql.Result, error) {
	rq, ra := s.dialect.bind(q, args)
	return ex.ExecContext(ctx, rq, ra...)
}

func (s *sqlStore) query(ctx context.Context, ex sqlExec, q string, args ...any) (*sql.Rows, error) {
	rq, ra := s.dialect.bind(q, args)
	return ex.QueryContext(ctx, rq, ra...)
}

func (s *sqlStore) queryRow(ctx context.Context, ex sqlExec, q string, args ...any) *sql.Row {
	rq, ra := s.dialect.bind(q, args)
	return ex.QueryRowContext(ctx, rq, ra...)
}

// notify rings a deny-path doorbell from inside the caller's transaction (PG
// pg_notify; a no-op on MySQL, whose bus polls instead).
func (s *sqlStore) notify(ctx context.Context, tx *sql.Tx, channel, payload string) error {
	return s.dialect.notifyInTx(ctx, tx, channel, payload)
}

// inSerializable runs fn in a SERIALIZABLE transaction, retrying a bounded number
// of times on a serialization failure (PG 40001; MySQL deadlock/lock-wait). The
// whole invariant — read, decide, write — lives inside fn, so a concurrent writer
// either serializes after this one or forces a clean retry that re-reads the
// now-committed state. SERIALIZABLE is set explicitly because MySQL defaults to
// REPEATABLE READ.
func (s *sqlStore) inSerializable(ctx context.Context, fn func(*sql.Tx) error) error {
	for attempt := 0; ; attempt++ {
		tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			if s.dialect.isSerializationFailure(err) && attempt < maxSerialRetries {
				serialBackoff(ctx, attempt)
				continue
			}
			return err
		}
		err = fn(tx)
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			_ = tx.Rollback()
			if s.dialect.isSerializationFailure(err) && attempt < maxSerialRetries {
				serialBackoff(ctx, attempt)
				continue
			}
			return err
		}
		return nil
	}
}

// serialBackoff sleeps a small randomized, attempt-scaled interval before retrying
// a serialization failure, so a burst of writers contending on one row does not
// re-collide in lockstep on every retry (a deadlock storm). The cap keeps a real
// conflict's resolution fast.
func serialBackoff(ctx context.Context, attempt int) {
	d := time.Duration(attempt+1) * time.Millisecond
	if d > 25*time.Millisecond {
		d = 25 * time.Millisecond
	}
	jitter := time.Duration(rand.Int63n(int64(d) + 1))
	t := time.NewTimer(jitter)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (s *sqlStore) ctx() context.Context { return context.Background() }

// --- json helpers ---

func marshalDoc(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// sqlGetDoc scans a single `doc` JSON column into *T, mapping no-rows to
// ErrNotFound (the same miss signal the bbolt helpers return).
func sqlGetDoc[T any](ctx context.Context, s *sqlStore, q sqlExec, query string, args ...any) (*T, error) {
	var raw []byte
	if err := s.queryRow(ctx, q, query, args...).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// sqlListDocs scans every `doc` JSON column the query returns into a []*T.
func sqlListDocs[T any](ctx context.Context, s *sqlStore, q sqlExec, query string, args ...any) ([]*T, error) {
	rows, err := s.query(ctx, q, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*T
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var rec T
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, err
		}
		out = append(out, &rec)
	}
	return out, rows.Err()
}

// --- workspaces (global) ---

func (s *sqlStore) PutWorkspace(rec *WorkspaceRecord) error {
	doc, err := marshalDoc(rec)
	if err != nil {
		return err
	}
	_, err = s.exec(s.ctx(), s.db, `INSERT INTO workspaces (id, doc) VALUES ($1, $2::jsonb)
		 ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc`, rec.ID, doc)
	return err
}

func (s *sqlStore) GetWorkspace(id string) (*WorkspaceRecord, error) {
	return sqlGetDoc[WorkspaceRecord](s.ctx(), s, s.db, `SELECT doc FROM workspaces WHERE id=$1`, id)
}

func (s *sqlStore) ListWorkspaces() ([]*WorkspaceRecord, error) {
	return sqlListDocs[WorkspaceRecord](s.ctx(), s, s.db, `SELECT doc FROM workspaces ORDER BY id`)
}

// --- networks / subnets (per-workspace) ---

func (s *sqlStore) PutNetwork(rec *NetworkRecord) error {
	doc, err := marshalDoc(rec)
	if err != nil {
		return err
	}
	_, err = s.exec(s.ctx(), s.db, `INSERT INTO networks (workspace_id, id, doc) VALUES ($1, $2, $3::jsonb)
		 ON CONFLICT (workspace_id, id) DO UPDATE SET doc = EXCLUDED.doc`,
		rec.WorkspaceID, rec.ID, doc)
	return err
}

func (s *sqlStore) ListNetworks(ws string) ([]*NetworkRecord, error) {
	return sqlListDocs[NetworkRecord](s.ctx(), s, s.db,
		`SELECT doc FROM networks WHERE workspace_id=$1 ORDER BY id`, ws)
}

func (s *sqlStore) PutSubnet(rec *SubnetRecord) error {
	doc, err := marshalDoc(rec)
	if err != nil {
		return err
	}
	_, err = s.exec(s.ctx(), s.db, `INSERT INTO subnets (workspace_id, id, doc) VALUES ($1, $2, $3::jsonb)
		 ON CONFLICT (workspace_id, id) DO UPDATE SET doc = EXCLUDED.doc`,
		rec.WorkspaceID, rec.ID, doc)
	return err
}

func (s *sqlStore) ListSubnets(ws string) ([]*SubnetRecord, error) {
	return sqlListDocs[SubnetRecord](s.ctx(), s, s.db,
		`SELECT doc FROM subnets WHERE workspace_id=$1 ORDER BY id`, ws)
}

// --- bindings (per-workspace FIB) ---

func (s *sqlStore) PutBinding(rec *BindingRecord) error {
	doc, err := marshalDoc(rec)
	if err != nil {
		return err
	}
	_, err = s.exec(s.ctx(), s.db, `INSERT INTO bindings (workspace_id, vni, node_id, doc) VALUES ($1, $2, $3, $4::jsonb)
		 ON CONFLICT (workspace_id, vni, node_id) DO UPDATE SET doc = EXCLUDED.doc`,
		rec.WorkspaceID, int64(rec.VNI), rec.NodeID, doc)
	return err
}

func (s *sqlStore) GetBinding(ws string, vni uint32, nodeID string) (*BindingRecord, error) {
	return sqlGetDoc[BindingRecord](s.ctx(), s, s.db,
		`SELECT doc FROM bindings WHERE workspace_id=$1 AND vni=$2 AND node_id=$3`, ws, int64(vni), nodeID)
}

func (s *sqlStore) ListBindings(ws string, vni uint32) ([]*BindingRecord, error) {
	return sqlListDocs[BindingRecord](s.ctx(), s, s.db,
		`SELECT doc FROM bindings WHERE workspace_id=$1 AND vni=$2 ORDER BY node_id`, ws, int64(vni))
}

// --- nodes (per-workspace; globally-unique id) ---

func (s *sqlStore) PutNode(ws string, n *NodeRecord) error {
	n.WorkspaceID = ws
	doc, err := marshalDoc(n)
	if err != nil {
		return err
	}
	// The unique index on nodes.id is the single-active-node-per-uuid guard: an
	// insert of the same id under a different workspace is rejected.
	return s.dialect.putNode(s.ctx(), s.db, ws, n.ID, n.Name, doc)
}

func (s *sqlStore) GetNode(ws, id string) (*NodeRecord, error) {
	return sqlGetDoc[NodeRecord](s.ctx(), s, s.db,
		`SELECT doc FROM nodes WHERE workspace_id=$1 AND id=$2`, ws, id)
}

func (s *sqlStore) WorkspaceForNode(id string) (string, error) {
	var ws string
	err := s.queryRow(s.ctx(), s.db, `SELECT workspace_id FROM nodes WHERE id=$1`, id).Scan(&ws)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return ws, err
}

func (s *sqlStore) GetNodeModules(ws, nodeID string) (*NodeModulesRecord, error) {
	rec, err := sqlGetDoc[NodeModulesRecord](s.ctx(), s, s.db,
		`SELECT doc FROM node_modules WHERE workspace_id=$1 AND node_id=$2`, ws, nodeID)
	if errors.Is(err, ErrNotFound) {
		return &NodeModulesRecord{}, nil
	}
	return rec, err
}

func (s *sqlStore) SetNodeModules(ws, nodeID string, modules []NodeModule) (*NodeModulesRecord, error) {
	var rec NodeModulesRecord
	err := s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		rec = NodeModulesRecord{}
		var raw []byte
		err := s.queryRow(s.ctx(), tx, `SELECT doc FROM node_modules WHERE workspace_id=$1 AND node_id=$2 FOR UPDATE`, ws, nodeID).Scan(&raw)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil {
			if uerr := json.Unmarshal(raw, &rec); uerr != nil {
				return uerr
			}
		}
		rec.Version++
		rec.Modules = modules
		doc, merr := marshalDoc(&rec)
		if merr != nil {
			return merr
		}
		_, err = s.exec(s.ctx(), tx, `INSERT INTO node_modules (workspace_id, node_id, doc) VALUES ($1, $2, $3::jsonb)
			 ON CONFLICT (workspace_id, node_id) DO UPDATE SET doc = EXCLUDED.doc`, ws, nodeID, doc)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *sqlStore) DeleteNode(ws, id string) error {
	return s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		ct, err := s.exec(s.ctx(), tx, `DELETE FROM nodes WHERE workspace_id=$1 AND id=$2`, ws, id)
		if err != nil {
			return err
		}
		if n, _ := ct.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		for _, q := range []string{
			`DELETE FROM node_modules WHERE workspace_id=$1 AND node_id=$2`,
			`DELETE FROM node_sboms WHERE workspace_id=$1 AND node_id=$2`,
			`DELETE FROM node_components WHERE workspace_id=$1 AND node_id=$2`,
			`DELETE FROM node_cve WHERE workspace_id=$1 AND node_id=$2`,
			`DELETE FROM node_images WHERE workspace_id=$1 AND node_id=$2`,
		} {
			if _, err := s.exec(s.ctx(), tx, q, ws, id); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *sqlStore) SetNodeApproval(ws, id string, approve bool, by string, now time.Time) (*NodeRecord, error) {
	var n NodeRecord
	err := s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		n = NodeRecord{}
		var raw []byte
		err := s.queryRow(s.ctx(), tx, `SELECT doc FROM nodes WHERE workspace_id=$1 AND id=$2 FOR UPDATE`, ws, id).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if uerr := json.Unmarshal(raw, &n); uerr != nil {
			return uerr
		}
		n.Approved = approve
		if approve {
			n.ApprovedBy = by
			n.ApprovedAtUnix = now.Unix()
			// Baseline preserved across re-approval (see the bbolt twin): re-approval
			// can't launder a still-tampered binary; it re-quarantines on the next beat.
		} else {
			n.ApprovedBy = ""
			n.ApprovedAtUnix = 0
		}
		doc, merr := marshalDoc(&n)
		if merr != nil {
			return merr
		}
		if _, err = s.exec(s.ctx(), tx, `UPDATE nodes SET name=$3, doc=$4::jsonb WHERE workspace_id=$1 AND id=$2`, ws, id, n.Name, doc); err != nil {
			return err
		}
		if approve {
			// Re-approval clears any drift quarantine in the same transaction.
			_, err = s.exec(s.ctx(), tx, `DELETE FROM node_quarantines WHERE workspace_id=$1 AND node_id=$2`, ws, id)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return &n, nil
}

func (s *sqlStore) FindNode(ws, idOrName string) (*NodeRecord, error) {
	if n, err := s.GetNode(ws, idOrName); err == nil {
		return n, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	matches, err := sqlListDocs[NodeRecord](s.ctx(), s, s.db,
		`SELECT doc FROM nodes WHERE workspace_id=$1 AND name=$2`, ws, idOrName)
	if err != nil {
		return nil, err
	}
	switch len(matches) {
	case 0:
		return nil, ErrNotFound
	case 1:
		return matches[0], nil
	default:
		return nil, fmt.Errorf("node name %q is ambiguous (%d matches); use the node id", idOrName, len(matches))
	}
}

func (s *sqlStore) ListNodes(ws string) ([]*NodeRecord, error) {
	return sqlListDocs[NodeRecord](s.ctx(), s, s.db,
		`SELECT doc FROM nodes WHERE workspace_id=$1 ORDER BY id`, ws)
}

func (s *sqlStore) ListAllNodes() ([]*NodeRecord, error) {
	return sqlListDocs[NodeRecord](s.ctx(), s, s.db, `SELECT doc FROM nodes ORDER BY id`)
}

// --- join tokens (global) ---

func (s *sqlStore) PutToken(token string, rec *TokenRecord) error {
	doc, err := marshalDoc(rec)
	if err != nil {
		return err
	}
	_, err = s.exec(s.ctx(), s.db, `INSERT INTO tokens (token, doc) VALUES ($1, $2::jsonb)
		 ON CONFLICT (token) DO UPDATE SET doc = EXCLUDED.doc`, token, doc)
	return err
}

// UseToken consumes one use of a join token. The read, the expiry/use-count
// checks, and the increment all run inside one SERIALIZABLE transaction so a
// second concurrent spend of a single-use token is rejected (ErrTokenExhausted).
func (s *sqlStore) UseToken(token string, now time.Time) (*TokenRecord, error) {
	var rec TokenRecord
	err := s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		var raw []byte
		err := s.queryRow(s.ctx(), tx, `SELECT doc FROM tokens WHERE token=$1 FOR UPDATE`, token).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTokenUnknown
		}
		if err != nil {
			return err
		}
		rec = TokenRecord{}
		if uerr := json.Unmarshal(raw, &rec); uerr != nil {
			return uerr
		}
		if now.Unix() > rec.ExpiresUnix {
			return ErrTokenExpired
		}
		if rec.Uses >= rec.MaxUses {
			return ErrTokenExhausted
		}
		rec.Uses++
		doc, merr := marshalDoc(&rec)
		if merr != nil {
			return merr
		}
		_, err = s.exec(s.ctx(), tx, `UPDATE tokens SET doc=$2::jsonb WHERE token=$1`, token, doc)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// --- source bindings (global) ---

func (s *sqlStore) PutSourceBinding(rec *SourceBinding) error {
	doc, err := marshalDoc(rec)
	if err != nil {
		return err
	}
	_, err = s.exec(s.ctx(), s.db, `INSERT INTO source_bindings (key, doc) VALUES ($1, $2::jsonb)
		 ON CONFLICT (key) DO UPDATE SET doc = EXCLUDED.doc`, rec.Key, doc)
	return err
}

func (s *sqlStore) GetSourceBinding(key string) (*SourceBinding, error) {
	return sqlGetDoc[SourceBinding](s.ctx(), s, s.db, `SELECT doc FROM source_bindings WHERE key=$1`, key)
}

func (s *sqlStore) ListSourceBindings() ([]*SourceBinding, error) {
	return sqlListDocs[SourceBinding](s.ctx(), s, s.db, `SELECT doc FROM source_bindings ORDER BY key`)
}

func (s *sqlStore) DeleteSourceBinding(key string) error {
	_, err := s.exec(s.ctx(), s.db, `DELETE FROM source_bindings WHERE key=$1`, key)
	return err
}

// --- OpenStack enrollment idempotency (global) ---

// OSMintOnce returns the join token for key, minting one only if none exists yet
// (or the prior one has aged past dedupeTTL or been spent). The dedupe read, the
// liveness check, and the conditional mint run in one SERIALIZABLE transaction so
// the ~5 near-simultaneous Nova vendordata hits per boot cannot race to mint
// multiple tokens.
func (s *sqlStore) OSMintOnce(key string, now time.Time, dedupeTTL time.Duration, tok *TokenRecord, newToken func() (string, error)) (token string, reused bool, err error) {
	err = s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		token, reused = "", false
		var prev OSEnrollRecord
		var raw []byte
		gerr := s.queryRow(s.ctx(), tx, `SELECT doc FROM os_enroll WHERE key=$1 FOR UPDATE`, key).Scan(&raw)
		if gerr == nil {
			if uerr := json.Unmarshal(raw, &prev); uerr != nil {
				return uerr
			}
			fresh := now.Sub(time.Unix(prev.CreatedUnix, 0)) < dedupeTTL
			var tr TokenRecord
			var traw []byte
			terr := s.queryRow(s.ctx(), tx, `SELECT doc FROM tokens WHERE token=$1`, prev.Token).Scan(&traw)
			tokenLive := false
			if terr == nil {
				if uerr := json.Unmarshal(traw, &tr); uerr != nil {
					return uerr
				}
				tokenLive = tr.Uses < tr.MaxUses && now.Unix() <= tr.ExpiresUnix
			} else if !errors.Is(terr, sql.ErrNoRows) {
				return terr
			}
			if fresh && tokenLive {
				token, reused = prev.Token, true
				return nil
			}
		} else if !errors.Is(gerr, sql.ErrNoRows) {
			return gerr
		}
		t, nerr := newToken()
		if nerr != nil {
			return nerr
		}
		tokDoc, merr := marshalDoc(tok)
		if merr != nil {
			return merr
		}
		if _, e := s.exec(s.ctx(), tx, `INSERT INTO tokens (token, doc) VALUES ($1, $2::jsonb)
			 ON CONFLICT (token) DO UPDATE SET doc = EXCLUDED.doc`, t, tokDoc); e != nil {
			return e
		}
		rec := OSEnrollRecord{Key: key, Token: t, WorkspaceID: tok.WorkspaceID, ProjectID: tok.Labels["os:project"], CreatedUnix: now.Unix()}
		recDoc, merr := marshalDoc(&rec)
		if merr != nil {
			return merr
		}
		if _, e := s.exec(s.ctx(), tx, `INSERT INTO os_enroll (key, created_unix, doc) VALUES ($1, $2, $3::jsonb)
			 ON CONFLICT (key) DO UPDATE SET created_unix = EXCLUDED.created_unix, doc = EXCLUDED.doc`,
			key, rec.CreatedUnix, recDoc); e != nil {
			return e
		}
		token = t
		return nil
	})
	return token, reused, err
}

// --- leaf-cert revocation (global) ---

func (s *sqlStore) RevokeCert(rec *RevokedCert) error {
	doc, err := marshalDoc(rec)
	if err != nil {
		return err
	}
	return s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		if _, err := s.exec(s.ctx(), tx, `INSERT INTO revoked_certs (serial, doc) VALUES ($1, $2::jsonb)
			 ON CONFLICT (serial) DO UPDATE SET doc = EXCLUDED.doc`, rec.Serial, doc); err != nil {
			return err
		}
		return s.notify(s.ctx(), tx, chanRevoke, rec.Serial)
	})
}

// IsCertRevoked reports whether a serial is on the denylist. A query error fails
// closed (treat as revoked) — a deny path must never allow on a storage fault.
func (s *sqlStore) IsCertRevoked(serialHex string) bool {
	present, err := s.IsCertRevokedE(serialHex)
	if err != nil {
		return true
	}
	return present
}

// IsCertRevokedE is the error-returning twin the deny cache fronts. It returns the
// raw query error (NOT a fail-closed bool) so the cache can serve a fresh entry
// through a blip and fail closed only once the entry lapses.
func (s *sqlStore) IsCertRevokedE(serialHex string) (bool, error) {
	var present bool
	err := s.queryRow(s.ctx(), s.db, `SELECT EXISTS(SELECT 1 FROM revoked_certs WHERE serial=$1)`, serialHex).Scan(&present)
	return present, err
}

func (s *sqlStore) ListRevokedCerts() ([]*RevokedCert, error) {
	return sqlListDocs[RevokedCert](s.ctx(), s, s.db, `SELECT doc FROM revoked_certs ORDER BY serial`)
}

// --- sessions (per-workspace) ---

func (s *sqlStore) PutSession(ws string, rec *SessionRecord) error {
	// Stamp the workspace into the record BEFORE marshaling, mirroring the bbolt
	// store: the broker builds the record without a workspace and relies on the
	// store to set it, and every read path returns the embedded doc — so an
	// unstamped doc would load back with an empty workspace and silently defeat
	// the continuous-authz sweep (suspension teardown, revoke, policy re-eval).
	rec.WorkspaceID = ws
	doc, err := marshalDoc(rec)
	if err != nil {
		return err
	}
	_, err = s.exec(s.ctx(), s.db, `INSERT INTO sessions (workspace_id, id, started_unix, doc) VALUES ($1, $2, $3, $4::jsonb)
		 ON CONFLICT (workspace_id, id) DO UPDATE SET started_unix = EXCLUDED.started_unix, doc = EXCLUDED.doc`,
		ws, rec.ID, rec.StartedUnix, doc)
	return err
}

func (s *sqlStore) GetSession(ws, id string) (*SessionRecord, error) {
	return sqlGetDoc[SessionRecord](s.ctx(), s, s.db,
		`SELECT doc FROM sessions WHERE workspace_id=$1 AND id=$2`, ws, id)
}

// UpdateSession applies fn to a session under a row lock so concurrent updates
// (a heartbeat, a revoke, an end) serialize instead of lost-updating each other.
func (s *sqlStore) UpdateSession(ws, id string, fn func(*SessionRecord)) error {
	return s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		var raw []byte
		err := s.queryRow(s.ctx(), tx, `SELECT doc FROM sessions WHERE workspace_id=$1 AND id=$2 FOR UPDATE`, ws, id).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		var rec SessionRecord
		if uerr := json.Unmarshal(raw, &rec); uerr != nil {
			return uerr
		}
		fn(&rec)
		doc, merr := marshalDoc(&rec)
		if merr != nil {
			return merr
		}
		_, err = s.exec(s.ctx(), tx, `UPDATE sessions SET started_unix=$3, doc=$4::jsonb WHERE workspace_id=$1 AND id=$2`,
			ws, id, rec.StartedUnix, doc)
		return err
	})
}

func (s *sqlStore) ListSessions(ws string) ([]*SessionRecord, error) {
	return sqlListDocs[SessionRecord](s.ctx(), s, s.db,
		`SELECT doc FROM sessions WHERE workspace_id=$1 ORDER BY started_unix`, ws)
}

// QuerySessions pushes the whole list view into the database: a parameterized
// WHERE (state / user / free-text over the JSON doc), a whitelisted ORDER BY, a
// COUNT for the total, and LIMIT/OFFSET — so the controller never loads a large
// sessions table to return one filtered page.
func (s *sqlStore) QuerySessions(ws string, q SessionQuery) ([]*SessionRecord, int, error) {
	where := []string{"workspace_id = $1"}
	args := []any{ws}
	if st := strings.ToLower(strings.TrimSpace(q.State)); st != "" && st != "all" {
		args = append(args, st)
		where = append(where, fmt.Sprintf("lower(%s) = $%d", s.dialect.jsonField("doc", "state"), len(args)))
	}
	if q.User != "" {
		args = append(args, q.User)
		where = append(where, fmt.Sprintf("%s = $%d", s.dialect.jsonField("doc", "user"), len(args)))
	}
	if search := strings.ToLower(strings.TrimSpace(q.Search)); search != "" {
		args = append(args, "%"+search+"%")
		n := len(args)
		where = append(where, fmt.Sprintf(
			"(lower(%s) LIKE $%d OR lower(%s) LIKE $%d OR "+
				"lower(%s) LIKE $%d OR lower(%s) LIKE $%d OR lower(id) LIKE $%d)",
			s.dialect.jsonField("doc", "user"), n, s.dialect.jsonField("doc", "node_name"), n,
			s.dialect.jsonField("doc", "node_id"), n, s.dialect.jsonField("doc", "action"), n, n))
	}
	whereSQL := strings.Join(where, " AND ")

	var total int
	if err := s.queryRow(s.ctx(), s.db, "SELECT count(*) FROM sessions WHERE "+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit, offset := q.Page.normalize()
	args = append(args, limit, offset)
	query := fmt.Sprintf("SELECT doc FROM sessions WHERE %s ORDER BY %s %s LIMIT $%d OFFSET $%d",
		whereSQL, s.sessionsOrderColumn(q.Sort), sqlOrderDir(q.Order), len(args)-1, len(args))
	items, err := sqlListDocs[SessionRecord](s.ctx(), s, s.db, query, args...)
	return items, total, err
}

// sessionsOrderColumn whitelists the sort key to a fixed SQL expression (never
// interpolating user input into the column position).
func (s *sqlStore) sessionsOrderColumn(sort string) string {
	switch strings.ToLower(sort) {
	case "user":
		return s.dialect.jsonField("doc", "user")
	case "node":
		return "coalesce(nullif(" + s.dialect.jsonField("doc", "node_name") + ",''), " + s.dialect.jsonField("doc", "node_id") + ")"
	case "action":
		return s.dialect.jsonField("doc", "action")
	case "state":
		return s.dialect.jsonField("doc", "state")
	default:
		return "started_unix"
	}
}

func sqlOrderDir(order string) string {
	if strings.ToLower(order) == "asc" {
		return "ASC"
	}
	return "DESC"
}

func (s *sqlStore) ListAllSessions() ([]*SessionRecord, error) {
	// Unordered: the sweep/revoke callers re-evaluate each session independently,
	// so ORDER BY would only add a sort over the whole table every sweep.
	return sqlListDocs[SessionRecord](s.ctx(), s, s.db, `SELECT doc FROM sessions`)
}

// --- recordings (per-workspace, fully columnar) ---

// recordingColumns is the column list both the SELECT and the scan use, kept in
// one place so they can never drift out of order.
const recordingColumns = `workspace_id, session_id, node_id, principal, action, ` +
	`started_unix, ended_unix, size_bytes, sha256, node_sig, audit_key_id, ` +
	`blob_ref, truncated, stored_unix`

func scanRecording(sc interface{ Scan(...any) error }) (*RecordingRecord, error) {
	var (
		rec       RecordingRecord
		nodeID    sql.NullString
		principal sql.NullString
		action    sql.NullString
		sha       sql.NullString
		auditKey  sql.NullString
		blobRef   sql.NullString
		truncated sql.NullBool
	)
	if err := sc.Scan(&rec.WorkspaceID, &rec.SessionID, &nodeID, &principal, &action,
		&rec.StartedUnix, &rec.EndedUnix, &rec.SizeBytes, &sha, &rec.NodeSig, &auditKey,
		&blobRef, &truncated, &rec.StoredUnix); err != nil {
		return nil, err
	}
	rec.NodeID = nodeID.String
	rec.Principal = principal.String
	rec.Action = action.String
	rec.SHA256 = sha.String
	rec.AuditKeyID = auditKey.String
	rec.BlobRef = blobRef.String
	rec.Truncated = truncated.Bool
	return &rec, nil
}

func (s *sqlStore) PutRecording(ws string, rec *RecordingRecord) error {
	rec.WorkspaceID = ws
	_, err := s.exec(s.ctx(), s.db,
		`INSERT INTO recordings (workspace_id, session_id, node_id, principal, action,
			started_unix, ended_unix, size_bytes, sha256, node_sig, audit_key_id,
			blob_ref, truncated, stored_unix)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		 ON CONFLICT (workspace_id, session_id) DO UPDATE SET
			node_id = EXCLUDED.node_id, principal = EXCLUDED.principal, action = EXCLUDED.action,
			started_unix = EXCLUDED.started_unix, ended_unix = EXCLUDED.ended_unix,
			size_bytes = EXCLUDED.size_bytes, sha256 = EXCLUDED.sha256, node_sig = EXCLUDED.node_sig,
			audit_key_id = EXCLUDED.audit_key_id, blob_ref = EXCLUDED.blob_ref,
			truncated = EXCLUDED.truncated, stored_unix = EXCLUDED.stored_unix`,
		ws, rec.SessionID, rec.NodeID, rec.Principal, rec.Action,
		rec.StartedUnix, rec.EndedUnix, rec.SizeBytes, rec.SHA256, rec.NodeSig, rec.AuditKeyID,
		rec.BlobRef, rec.Truncated, rec.StoredUnix)
	return err
}

func (s *sqlStore) GetRecording(ws, sessionID string) (*RecordingRecord, error) {
	row := s.queryRow(s.ctx(), s.db,
		`SELECT `+recordingColumns+` FROM recordings WHERE workspace_id=$1 AND session_id=$2`, ws, sessionID)
	rec, err := scanRecording(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return rec, err
}

func (s *sqlStore) ListRecordings(ws string) ([]*RecordingRecord, error) {
	rows, err := s.query(s.ctx(), s.db,
		`SELECT `+recordingColumns+` FROM recordings WHERE workspace_id=$1 ORDER BY started_unix`, ws)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*RecordingRecord
	for rows.Next() {
		rec, err := scanRecording(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *sqlStore) DeleteRecording(ws, sessionID string) error {
	ct, err := s.exec(s.ctx(), s.db,
		`DELETE FROM recordings WHERE workspace_id=$1 AND session_id=$2`, ws, sessionID)
	if err != nil {
		return err
	}
	if n, _ := ct.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- software inventory (per-workspace SBOMs, components, computed cve set) ---

func (s *sqlStore) PutNodeSBOM(ws, nodeID string, rec *NodeSBOMRecord) error {
	rec.WorkspaceID = ws
	rec.NodeID = nodeID
	_, err := s.exec(s.ctx(), s.db,
		`INSERT INTO node_sboms (workspace_id, node_id, format, content_hash, collected_unix, sbom)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (workspace_id, node_id) DO UPDATE SET
			format = EXCLUDED.format, content_hash = EXCLUDED.content_hash,
			collected_unix = EXCLUDED.collected_unix, sbom = EXCLUDED.sbom`,
		ws, nodeID, rec.Format, rec.ContentHash, rec.CollectedUnix, rec.SBOM)
	return err
}

func (s *sqlStore) GetNodeSBOM(ws, nodeID string) (*NodeSBOMRecord, error) {
	var (
		rec    NodeSBOMRecord
		format sql.NullString
		hash   sql.NullString
	)
	err := s.queryRow(s.ctx(), s.db,
		`SELECT workspace_id, node_id, format, content_hash, collected_unix, sbom
		 FROM node_sboms WHERE workspace_id=$1 AND node_id=$2`, ws, nodeID).
		Scan(&rec.WorkspaceID, &rec.NodeID, &format, &hash, &rec.CollectedUnix, &rec.SBOM)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rec.Format = format.String
	rec.ContentHash = hash.String
	return &rec, nil
}

// UpsertNodeComponents replaces a node's whole component set in one serializable
// transaction: the prior rows are deleted and the supplied set inserted, so a
// re-index never leaves a stale component behind.
func (s *sqlStore) UpsertNodeComponents(ws, nodeID string, comps []ComponentRecord) error {
	return s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		if _, err := s.exec(s.ctx(), tx,
			`DELETE FROM node_components WHERE workspace_id=$1 AND node_id=$2`, ws, nodeID); err != nil {
			return err
		}
		for i := range comps {
			c := comps[i]
			if _, err := s.exec(s.ctx(), tx,
				`INSERT INTO node_components (workspace_id, node_id, purl, source, ecosystem, name, version, distro)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
				ws, nodeID, c.Purl, c.Source, c.Ecosystem, c.Name, c.Version, c.Distro); err != nil {
				return err
			}
		}
		return nil
	})
}

// componentColumns is the column list the by-node and by-package reads share, kept
// in one place so the SELECT and the scan can never drift.
const componentColumns = `workspace_id, node_id, purl, source, ecosystem, name, version, distro`

func scanComponent(sc interface{ Scan(...any) error }) (ComponentRecord, error) {
	var (
		rec       ComponentRecord
		ecosystem sql.NullString
		name      sql.NullString
		version   sql.NullString
		distro    sql.NullString
	)
	if err := sc.Scan(&rec.WorkspaceID, &rec.NodeID, &rec.Purl, &rec.Source,
		&ecosystem, &name, &version, &distro); err != nil {
		return rec, err
	}
	rec.Ecosystem = ecosystem.String
	rec.Name = name.String
	rec.Version = version.String
	rec.Distro = distro.String
	return rec, nil
}

func (s *sqlStore) listComponents(query string, args ...any) ([]ComponentRecord, error) {
	rows, err := s.query(s.ctx(), s.db, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ComponentRecord
	for rows.Next() {
		rec, err := scanComponent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *sqlStore) ListNodeComponents(ws, nodeID string) ([]ComponentRecord, error) {
	return s.listComponents(
		`SELECT `+componentColumns+` FROM node_components WHERE workspace_id=$1 AND node_id=$2`, ws, nodeID)
}

func (s *sqlStore) ListComponentsByPackage(ws, ecosystem, name string) ([]ComponentRecord, error) {
	return s.listComponents(
		`SELECT `+componentColumns+` FROM node_components WHERE workspace_id=$1 AND ecosystem=$2 AND name=$3`,
		ws, ecosystem, name)
}

func (s *sqlStore) UpsertNodeCVE(rec *NodeCVERecord) error {
	_, err := s.exec(s.ctx(), s.db,
		`INSERT INTO node_cve (workspace_id, node_id, cve, purl, status, severity, kev, epss,
			vex_justification, fixed_version, matched_unix)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 ON CONFLICT (workspace_id, node_id, cve, purl) DO UPDATE SET
			status = EXCLUDED.status, severity = EXCLUDED.severity, kev = EXCLUDED.kev,
			epss = EXCLUDED.epss, vex_justification = EXCLUDED.vex_justification,
			fixed_version = EXCLUDED.fixed_version, matched_unix = EXCLUDED.matched_unix`,
		rec.WorkspaceID, rec.NodeID, rec.CVE, rec.Purl, rec.Status, rec.Severity, rec.KEV, rec.EPSS,
		rec.VEXJustification, rec.FixedVersion, rec.MatchedUnix)
	return err
}

// ClearNodeCVEs drops every verdict row for one node so a re-match writes a clean
// replace-set (a version bump or removal leaves no stale verdict on the old purl).
func (s *sqlStore) ClearNodeCVEs(ws, nodeID string) error {
	_, err := s.exec(s.ctx(), s.db,
		`DELETE FROM node_cve WHERE workspace_id=$1 AND node_id=$2`, ws, nodeID)
	return err
}

const nodeCVEColumns = `workspace_id, node_id, cve, purl, status, severity, kev, epss, ` +
	`vex_justification, fixed_version, matched_unix`

func scanNodeCVE(sc interface{ Scan(...any) error }) (NodeCVERecord, error) {
	var (
		rec      NodeCVERecord
		status   sql.NullString
		severity sql.NullString
		kev      sql.NullBool
		epss     sql.NullFloat64
		vex      sql.NullString
		fixed    sql.NullString
	)
	if err := sc.Scan(&rec.WorkspaceID, &rec.NodeID, &rec.CVE, &rec.Purl, &status, &severity,
		&kev, &epss, &vex, &fixed, &rec.MatchedUnix); err != nil {
		return rec, err
	}
	rec.Status = status.String
	rec.Severity = severity.String
	rec.KEV = kev.Bool
	rec.EPSS = epss.Float64
	rec.VEXJustification = vex.String
	rec.FixedVersion = fixed.String
	return rec, nil
}

func (s *sqlStore) listNodeCVE(query string, args ...any) ([]NodeCVERecord, error) {
	rows, err := s.query(s.ctx(), s.db, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NodeCVERecord
	for rows.Next() {
		rec, err := scanNodeCVE(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *sqlStore) NodesAffectedByCVE(ws, cve string) ([]NodeCVERecord, error) {
	return s.listNodeCVE(
		`SELECT `+nodeCVEColumns+` FROM node_cve WHERE workspace_id=$1 AND cve=$2`, ws, cve)
}

func (s *sqlStore) CVEsForNode(ws, nodeID string) ([]NodeCVERecord, error) {
	return s.listNodeCVE(
		`SELECT `+nodeCVEColumns+` FROM node_cve WHERE workspace_id=$1 AND node_id=$2`, ws, nodeID)
}

// WorkspaceCVERollups returns the per-CVE union of the workspace's host verdicts and
// its image verdicts, fanned to nodes through the node->digest association. The query
// emits one (cve, node, status, severity, fixed_version) row per host verdict and per
// image verdict on a node currently running the carrying digest; the shared
// aggregator then collapses these into per-CVE rollups, counting distinct nodes (so a
// node carrying a CVE from both its host and a container counts once, two nodes on the
// same affected image count twice) and picking the representative severity/status/fix.
// Both halves are workspace-scoped — the image half only through node_images, which is
// the sole tenant-scoped link to the global image_cve table — so the rollup never
// crosses tenants.
func (s *sqlStore) WorkspaceCVERollups(ws string) ([]WorkspaceCVERollup, error) {
	rows, err := s.query(s.ctx(), s.db,
		`SELECT cve, node_id, status, severity, fixed_version
		   FROM node_cve
		  WHERE workspace_id=$1
		 UNION ALL
		 SELECT ic.cve, ni.node_id, ic.status, ic.severity, ic.fixed_version
		   FROM node_images ni
		   JOIN image_cve ic ON ic.digest = ni.digest
		  WHERE ni.workspace_id=$1`, ws)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var union []cveNodeRow
	for rows.Next() {
		var (
			r        cveNodeRow
			status   sql.NullString
			severity sql.NullString
			fixed    sql.NullString
		)
		if err := rows.Scan(&r.CVE, &r.NodeID, &status, &severity, &fixed); err != nil {
			return nil, err
		}
		r.Status = status.String
		r.Severity = severity.String
		r.FixedVersion = fixed.String
		union = append(union, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rollupCVENodeRows(union), nil
}

// EnrichNodeCVEs overlays KEV/EPSS onto every node_cve row whose CVE is in scores,
// fleet-wide (no workspace filter — the signal is the same fact for every tenant),
// in one transaction. The change-guard predicate (COALESCE so a NULL column
// counts as its zero value) means a re-apply of the same scores updates zero rows,
// so the returned count is the number of rows that actually changed.
func (s *sqlStore) EnrichNodeCVEs(scores map[string]CVEEnrichment) (int, error) {
	if len(scores) == 0 {
		return 0, nil
	}
	ctx := s.ctx()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	updated := 0
	for cve, e := range scores {
		res, err := s.exec(ctx, tx,
			`UPDATE node_cve SET kev=$1, epss=$2
			 WHERE cve=$3 AND (COALESCE(kev, false) <> $1 OR COALESCE(epss, 0) <> $2)`,
			e.KEV, e.EPSS, cve)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		updated += int(n)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return updated, nil
}

// DistinctNodeCVEs returns every CVE id present in node_cve, served from the
// (cve, status) index by a grouped scan.
func (s *sqlStore) DistinctNodeCVEs() ([]string, error) {
	rows, err := s.query(s.ctx(), s.db, `SELECT DISTINCT cve FROM node_cve`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cve string
		if err := rows.Scan(&cve); err != nil {
			return nil, err
		}
		if cve != "" {
			out = append(out, cve)
		}
	}
	return out, rows.Err()
}

// --- image digest dedup (global image components/verdicts + per-ws association) ---

// HasImageComponents reports whether a digest's image component set is already
// stored, so an inventory commit can skip re-storing and a first-seen detector can
// trigger the initial match.
func (s *sqlStore) HasImageComponents(digest string) (bool, error) {
	var one int
	err := s.queryRow(s.ctx(), s.db,
		`SELECT 1 FROM image_components WHERE digest=$1 LIMIT 1`, digest).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// PutImageComponents replaces a digest's image component set in one serializable
// transaction. The digest is content-addressable, so a concurrent re-store writes
// byte-identical rows — the replace-set converges regardless of order.
func (s *sqlStore) PutImageComponents(digest string, comps []ImageComponentRecord) error {
	return s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		if _, err := s.exec(s.ctx(), tx,
			`DELETE FROM image_components WHERE digest=$1`, digest); err != nil {
			return err
		}
		for i := range comps {
			c := comps[i]
			if _, err := s.exec(s.ctx(), tx,
				`INSERT INTO image_components (digest, purl, source, ecosystem, name, version, distro)
				 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
				digest, c.Purl, c.Source, c.Ecosystem, c.Name, c.Version, c.Distro); err != nil {
				return err
			}
		}
		return nil
	})
}

const imageComponentColumns = `digest, purl, source, ecosystem, name, version, distro`

func scanImageComponent(sc interface{ Scan(...any) error }) (ImageComponentRecord, error) {
	var (
		rec       ImageComponentRecord
		ecosystem sql.NullString
		name      sql.NullString
		version   sql.NullString
		distro    sql.NullString
	)
	if err := sc.Scan(&rec.Digest, &rec.Purl, &rec.Source, &ecosystem, &name, &version, &distro); err != nil {
		return rec, err
	}
	rec.Ecosystem = ecosystem.String
	rec.Name = name.String
	rec.Version = version.String
	rec.Distro = distro.String
	return rec, nil
}

func (s *sqlStore) ListImageComponents(digest string) ([]ImageComponentRecord, error) {
	rows, err := s.query(s.ctx(), s.db,
		`SELECT `+imageComponentColumns+` FROM image_components WHERE digest=$1`, digest)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ImageComponentRecord
	for rows.Next() {
		rec, err := scanImageComponent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// ImageDigestsForPackage returns the digests carrying a component of (ecosystem,
// name), served from the (ecosystem, name) index.
func (s *sqlStore) ImageDigestsForPackage(ecosystem, name string) ([]string, error) {
	rows, err := s.query(s.ctx(), s.db,
		`SELECT DISTINCT digest FROM image_components WHERE ecosystem=$1 AND name=$2`, ecosystem, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetNodeImages replaces a node's image-digest association set in one serializable
// transaction (replace-set per node), so a node that stops running a digest stops
// fanning that digest's verdicts to itself.
func (s *sqlStore) SetNodeImages(ws, nodeID string, digests []string) error {
	return s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		if _, err := s.exec(s.ctx(), tx,
			`DELETE FROM node_images WHERE workspace_id=$1 AND node_id=$2`, ws, nodeID); err != nil {
			return err
		}
		for _, d := range digests {
			if _, err := s.exec(s.ctx(), tx,
				`INSERT INTO node_images (workspace_id, node_id, digest) VALUES ($1, $2, $3)`,
				ws, nodeID, d); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *sqlStore) NodeImageDigests(ws, nodeID string) ([]string, error) {
	rows, err := s.query(s.ctx(), s.db,
		`SELECT digest FROM node_images WHERE workspace_id=$1 AND node_id=$2`, ws, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *sqlStore) WorkspaceNodeImages(ws string) ([]NodeImageAssoc, error) {
	rows, err := s.query(s.ctx(), s.db,
		`SELECT node_id, digest FROM node_images WHERE workspace_id=$1`, ws)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NodeImageAssoc
	for rows.Next() {
		var a NodeImageAssoc
		if err := rows.Scan(&a.NodeID, &a.Digest); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *sqlStore) NodesRunningDigest(ws, digest string) ([]string, error) {
	rows, err := s.query(s.ctx(), s.db,
		`SELECT node_id FROM node_images WHERE workspace_id=$1 AND digest=$2`, ws, digest)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *sqlStore) PutImageCVE(rec *ImageCVERecord) error {
	_, err := s.exec(s.ctx(), s.db,
		`INSERT INTO image_cve (digest, cve, purl, status, severity, kev, epss,
			vex_justification, fixed_version, matched_unix)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (digest, cve, purl) DO UPDATE SET
			status = EXCLUDED.status, severity = EXCLUDED.severity, kev = EXCLUDED.kev,
			epss = EXCLUDED.epss, vex_justification = EXCLUDED.vex_justification,
			fixed_version = EXCLUDED.fixed_version, matched_unix = EXCLUDED.matched_unix`,
		rec.Digest, rec.CVE, rec.Purl, rec.Status, rec.Severity, rec.KEV, rec.EPSS,
		rec.VEXJustification, rec.FixedVersion, rec.MatchedUnix)
	return err
}

func (s *sqlStore) ClearImageCVEs(digest string) error {
	_, err := s.exec(s.ctx(), s.db, `DELETE FROM image_cve WHERE digest=$1`, digest)
	return err
}

const imageCVEColumns = `digest, cve, purl, status, severity, kev, epss, ` +
	`vex_justification, fixed_version, matched_unix`

func scanImageCVE(sc interface{ Scan(...any) error }) (ImageCVERecord, error) {
	var (
		rec      ImageCVERecord
		status   sql.NullString
		severity sql.NullString
		kev      sql.NullBool
		epss     sql.NullFloat64
		vex      sql.NullString
		fixed    sql.NullString
	)
	if err := sc.Scan(&rec.Digest, &rec.CVE, &rec.Purl, &status, &severity,
		&kev, &epss, &vex, &fixed, &rec.MatchedUnix); err != nil {
		return rec, err
	}
	rec.Status = status.String
	rec.Severity = severity.String
	rec.KEV = kev.Bool
	rec.EPSS = epss.Float64
	rec.VEXJustification = vex.String
	rec.FixedVersion = fixed.String
	return rec, nil
}

func (s *sqlStore) ImageCVEsForDigest(digest string) ([]ImageCVERecord, error) {
	rows, err := s.query(s.ctx(), s.db,
		`SELECT `+imageCVEColumns+` FROM image_cve WHERE digest=$1`, digest)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ImageCVERecord
	for rows.Next() {
		rec, err := scanImageCVE(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *sqlStore) DistinctImageCVEs() ([]string, error) {
	rows, err := s.query(s.ctx(), s.db, `SELECT DISTINCT cve FROM image_cve`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cve string
		if err := rows.Scan(&cve); err != nil {
			return nil, err
		}
		if cve != "" {
			out = append(out, cve)
		}
	}
	return out, rows.Err()
}

// EnrichImageCVEs overlays KEV/EPSS onto every image_cve row whose CVE is in scores,
// the image-side twin of EnrichNodeCVEs. The change-guard predicate means a re-apply
// updates zero rows, so the returned count is the number actually changed.
func (s *sqlStore) EnrichImageCVEs(scores map[string]CVEEnrichment) (int, error) {
	if len(scores) == 0 {
		return 0, nil
	}
	ctx := s.ctx()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	updated := 0
	for cve, e := range scores {
		res, err := s.exec(ctx, tx,
			`UPDATE image_cve SET kev=$1, epss=$2
			 WHERE cve=$3 AND (COALESCE(kev, false) <> $1 OR COALESCE(epss, 0) <> $2)`,
			e.KEV, e.EPSS, cve)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		updated += int(n)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return updated, nil
}

// --- advisories (global) ---

// PutAdvisories upserts a feed-sync batch in one serializable transaction so the
// sync lands atomically.
func (s *sqlStore) PutAdvisories(recs []AdvisoryRecord) error {
	return s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		for i := range recs {
			doc := string(recs[i].Doc)
			if doc == "" {
				doc = "{}"
			}
			if _, err := s.exec(s.ctx(), tx,
				`INSERT INTO advisories (id, source, ecosystem, package_name, doc, modified_unix)
				 VALUES ($1, $2, $3, $4, $5::jsonb, $6)
				 ON CONFLICT (id) DO UPDATE SET
					source = EXCLUDED.source, ecosystem = EXCLUDED.ecosystem,
					package_name = EXCLUDED.package_name, doc = EXCLUDED.doc,
					modified_unix = EXCLUDED.modified_unix`,
				recs[i].ID, recs[i].Source, recs[i].Ecosystem, recs[i].PackageName, doc, recs[i].ModifiedUnix); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *sqlStore) AdvisoriesForPackage(ecosystem, name string) ([]AdvisoryRecord, error) {
	rows, err := s.query(s.ctx(), s.db,
		`SELECT id, source, ecosystem, package_name, doc, modified_unix
		 FROM advisories WHERE ecosystem=$1 AND package_name=$2`, ecosystem, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdvisoryRecord
	for rows.Next() {
		var (
			rec    AdvisoryRecord
			source sql.NullString
			eco    sql.NullString
			pkg    sql.NullString
			rawDoc []byte
		)
		if err := rows.Scan(&rec.ID, &source, &eco, &pkg, &rawDoc, &rec.ModifiedUnix); err != nil {
			return nil, err
		}
		rec.Source = source.String
		rec.Ecosystem = eco.String
		rec.PackageName = pkg.String
		rec.Doc = json.RawMessage(rawDoc)
		out = append(out, rec)
	}
	return out, rows.Err()
}

// --- settings (global, raw bytes) ---

func (s *sqlStore) SetSetting(key string, val []byte) error {
	_, err := s.exec(s.ctx(), s.db, `INSERT INTO settings (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, key, val)
	return err
}

// GetSetting returns the raw value or (nil, nil) on miss — matching the bbolt
// store, where an absent setting is an empty result, not an error.
func (s *sqlStore) GetSetting(key string) ([]byte, error) {
	var val []byte
	err := s.queryRow(s.ctx(), s.db, `SELECT value FROM settings WHERE key=$1`, key).Scan(&val)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return val, nil
}

func (s *sqlStore) StableVersion() (string, error) { return s.getStringSetting(settingStableVersion) }
func (s *sqlStore) CanaryVersion() (string, error) { return s.getStringSetting(settingCanaryVersion) }

func (s *sqlStore) getStringSetting(key string) (string, error) {
	b, err := s.GetSetting(key)
	return string(b), err
}

func (s *sqlStore) SetStableVersion(v string) error {
	return s.SetSetting(settingStableVersion, []byte(v))
}
func (s *sqlStore) SetCanaryVersion(v string) error {
	return s.SetSetting(settingCanaryVersion, []byte(v))
}

func (s *sqlStore) CanaryNodes() ([]string, error) {
	b, err := s.GetSetting(settingCanaryNodes)
	if err != nil || len(b) == 0 {
		return nil, err
	}
	var out []string
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("settings %s: %w", settingCanaryNodes, err)
	}
	return out, nil
}

func (s *sqlStore) SetCanaryNodes(nodes []string) error {
	b, err := json.Marshal(nodes)
	if err != nil {
		return err
	}
	return s.SetSetting(settingCanaryNodes, b)
}

// Relay rollout ring: independent of the agent ring, keyed on the relay
// settings keys. Same generic settings table — no schema change.
func (s *sqlStore) RelayStableVersion() (string, error) {
	return s.getStringSetting(settingRelayStableVersion)
}
func (s *sqlStore) RelayCanaryVersion() (string, error) {
	return s.getStringSetting(settingRelayCanaryVersion)
}

func (s *sqlStore) SetRelayStableVersion(v string) error {
	return s.SetSetting(settingRelayStableVersion, []byte(v))
}
func (s *sqlStore) SetRelayCanaryVersion(v string) error {
	return s.SetSetting(settingRelayCanaryVersion, []byte(v))
}

func (s *sqlStore) RelayCanaryNodes() ([]string, error) {
	b, err := s.GetSetting(settingRelayCanaryNodes)
	if err != nil || len(b) == 0 {
		return nil, err
	}
	var out []string
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("settings %s: %w", settingRelayCanaryNodes, err)
	}
	return out, nil
}

func (s *sqlStore) SetRelayCanaryNodes(nodes []string) error {
	b, err := json.Marshal(nodes)
	if err != nil {
		return err
	}
	return s.SetSetting(settingRelayCanaryNodes, b)
}

// --- cluster config (global; version compare-and-swap) ---

func (s *sqlStore) ClusterConfigVersion() (int64, error) {
	var v int64
	err := s.queryRow(s.ctx(), s.db, `SELECT version FROM cluster_config WHERE id=1`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v, err
}

func (s *sqlStore) SignedClusterConfig() ([]byte, error) {
	var b []byte
	err := s.queryRow(s.ctx(), s.db, `SELECT signed FROM cluster_config WHERE id=1`).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return b, err
}

func (s *sqlStore) ClusterConfigSnapshot() (int64, []byte, error) {
	var v int64
	var b []byte
	err := s.queryRow(s.ctx(), s.db, `SELECT version, signed FROM cluster_config WHERE id=1`).Scan(&v, &b)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, nil
	}
	return v, b, err
}

// SetSignedClusterConfig advances the single config row to version only if the
// stored version is exactly version-1 (or the row is absent — genesis). A writer
// that loses the race gets errClusterConfigConflict; the caller re-reads and
// re-converges. This makes the version bump globally linearizable.
func (s *sqlStore) SetSignedClusterConfig(version int64, signed []byte) error {
	return s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		var cur int64
		err := s.queryRow(s.ctx(), tx, `SELECT version FROM cluster_config WHERE id=1 FOR UPDATE`).Scan(&cur)
		if errors.Is(err, sql.ErrNoRows) {
			if _, ierr := s.exec(s.ctx(), tx, `INSERT INTO cluster_config (id, version, signed) VALUES (1, $1, $2)`, version, signed); ierr != nil {
				return ierr
			}
			return s.notify(s.ctx(), tx, chanConfig, strconv.FormatInt(version, 10))
		}
		if err != nil {
			return err
		}
		if cur != version-1 {
			return errClusterConfigConflict
		}
		if _, err = s.exec(s.ctx(), tx, `UPDATE cluster_config SET version=$1, signed=$2 WHERE id=1 AND version=$3`, version, signed, cur); err != nil {
			return err
		}
		return s.notify(s.ctx(), tx, chanConfig, strconv.FormatInt(version, 10))
	})
}

func (s *sqlStore) FleetStateSnapshot() (int64, []byte, int64, []byte, error) {
	var mapV, anchorV int64
	var mapSigned, anchorSigned []byte
	err := s.queryRow(s.ctx(), s.db, `SELECT version, signed, anchor_version, anchor_signed FROM cluster_config WHERE id=1`).
		Scan(&mapV, &mapSigned, &anchorV, &anchorSigned)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, 0, nil, nil
	}
	return mapV, mapSigned, anchorV, anchorSigned, err
}

// SetSignedFleetState advances the routine map and (optionally) the trust anchors
// in one serializable transaction. The routine-map CAS is the same =version-1
// predicate as SetSignedClusterConfig; when anchorSigned is non-nil the anchor
// advances under its own =anchor_version-1 predicate in the SAME transaction. The
// cross-binding invariant is enforced before commit: the map's declared anchor
// version must equal whichever anchor version the row will hold after this call.
func (s *sqlStore) SetSignedFleetState(mapVersion int64, mapSigned []byte, mapAnchorVersion int64, anchorVersion int64, anchorSigned []byte) error {
	return s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		var curMap, curAnchor int64
		err := s.queryRow(s.ctx(), tx, `SELECT version, anchor_version FROM cluster_config WHERE id=1 FOR UPDATE`).Scan(&curMap, &curAnchor)
		genesis := errors.Is(err, sql.ErrNoRows)
		if err != nil && !genesis {
			return err
		}

		advanceAnchor := anchorSigned != nil
		// Determine the anchor version the row will hold after this call, and CAS it.
		effectiveAnchor := curAnchor
		if advanceAnchor {
			if !genesis && anchorVersion != curAnchor+1 {
				return errClusterConfigConflict
			}
			effectiveAnchor = anchorVersion
		}
		// Cross-binding: the routine map may only reference the anchor the row ends
		// up holding, so a stale-map/new-anchor or new-map/stale-anchor pairing can
		// never persist.
		if mapAnchorVersion != effectiveAnchor {
			return fmt.Errorf("routine map references anchor v%d but the row holds anchor v%d", mapAnchorVersion, effectiveAnchor)
		}

		if genesis {
			if _, ierr := s.exec(s.ctx(), tx, `INSERT INTO cluster_config (id, version, signed, anchor_version, anchor_signed) VALUES (1, $1, $2, $3, $4)`,
				mapVersion, mapSigned, effectiveAnchor, anchorSigned); ierr != nil {
				return ierr
			}
			return s.notify(s.ctx(), tx, chanConfig, strconv.FormatInt(mapVersion, 10))
		}
		if curMap != mapVersion-1 {
			return errClusterConfigConflict
		}
		if advanceAnchor {
			if _, err = s.exec(s.ctx(), tx, `UPDATE cluster_config SET version=$1, signed=$2, anchor_version=$3, anchor_signed=$4 WHERE id=1 AND version=$5 AND anchor_version=$6`,
				mapVersion, mapSigned, anchorVersion, anchorSigned, curMap, curAnchor); err != nil {
				return err
			}
		} else {
			if _, err = s.exec(s.ctx(), tx, `UPDATE cluster_config SET version=$1, signed=$2 WHERE id=1 AND version=$3`,
				mapVersion, mapSigned, curMap); err != nil {
				return err
			}
		}
		return s.notify(s.ctx(), tx, chanConfig, strconv.FormatInt(mapVersion, 10))
	})
}

// --- artifacts (global) ---

func (s *sqlStore) PutManifest(key string, signed []byte) error {
	_, err := s.exec(s.ctx(), s.db, `INSERT INTO artifacts (key, signed) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET signed = EXCLUDED.signed`, key, signed)
	return err
}

func (s *sqlStore) GetManifest(key string) ([]byte, error) {
	var b []byte
	err := s.queryRow(s.ctx(), s.db, `SELECT signed FROM artifacts WHERE key=$1`, key).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

// IsPublishedBinaryHash scans the published-manifest registry by hash (see the bbolt
// twin). The manifest set is shared across an HA fleet, so this is consistent on
// every controller regardless of which one accepted the publish.
func (s *sqlStore) PublishedManifestForHash(product, sha256hex string) (*types.Manifest, error) {
	if sha256hex == "" {
		return nil, ErrNotFound
	}
	rows, err := s.query(s.ctx(), s.db, `SELECT signed FROM artifacts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		if m := publishedManifestMatch(b, product, sha256hex); m != nil {
			return m, rows.Err()
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return nil, ErrNotFound
}

// --- members (per-workspace) ---

func (s *sqlStore) PutMember(ws string, rec *MemberRecord) error {
	if err := validateMemberIdentity(rec.Provider, rec.Subject); err != nil {
		return err
	}
	rec.Roles = stripReservedRoles(rec.Roles)
	return s.upsertMember(s.db, ws, rec)
}

func (s *sqlStore) upsertMember(q sqlExec, ws string, rec *MemberRecord) error {
	doc, err := marshalDoc(rec)
	if err != nil {
		return err
	}
	_, err = s.exec(s.ctx(), q, `INSERT INTO members (workspace_id, provider, subject, doc) VALUES ($1, $2, $3, $4::jsonb)
		 ON CONFLICT (workspace_id, provider, subject) DO UPDATE SET doc = EXCLUDED.doc`,
		ws, rec.Provider, rec.Subject, doc)
	return err
}

// AddPresenceCredential appends a hardware presence credential to a member
// (creating a minimal row if none exists), idempotent by public key, under a row
// lock so two concurrent enrolls cannot lose one another's credential.
func (s *sqlStore) AddPresenceCredential(ws, provider, subject string, cred EnrolledCredential) error {
	if err := validateMemberIdentity(provider, subject); err != nil {
		return err
	}
	return s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		var rec MemberRecord
		var raw []byte
		err := s.queryRow(s.ctx(), tx, `SELECT doc FROM members WHERE workspace_id=$1 AND provider=$2 AND subject=$3 FOR UPDATE`,
			ws, provider, subject).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			rec = MemberRecord{Provider: provider, Subject: subject, Username: subject, CreatedUnix: time.Now().Unix()}
		} else if err != nil {
			return err
		} else if uerr := json.Unmarshal(raw, &rec); uerr != nil {
			return uerr
		}
		for _, c := range rec.PresenceCredentials {
			if bytesEqual(c.PublicKey, cred.PublicKey) && c.Kind == cred.Kind {
				return nil // already enrolled
			}
		}
		rec.PresenceCredentials = append(rec.PresenceCredentials, cred)
		rec.UpdatedUnix = time.Now().Unix()
		return s.upsertMember(tx, ws, &rec)
	})
}

func (s *sqlStore) GetMember(ws, provider, subject string) (*MemberRecord, error) {
	return sqlGetDoc[MemberRecord](s.ctx(), s, s.db,
		`SELECT doc FROM members WHERE workspace_id=$1 AND provider=$2 AND subject=$3`, ws, provider, subject)
}

func (s *sqlStore) ListMembers(ws string) ([]*MemberRecord, error) {
	return sqlListDocs[MemberRecord](s.ctx(), s, s.db,
		`SELECT doc FROM members WHERE workspace_id=$1 ORDER BY provider, subject`, ws)
}

func (s *sqlStore) DeleteMember(ws, provider, subject string) error {
	_, err := s.exec(s.ctx(), s.db, `DELETE FROM members WHERE workspace_id=$1 AND provider=$2 AND subject=$3`, ws, provider, subject)
	return err
}

func (s *sqlStore) ListMemberWorkspaces(provider, subject string) ([]string, error) {
	rows, err := s.query(s.ctx(), s.db, `SELECT DISTINCT workspace_id FROM members WHERE provider=$1 AND subject=$2 ORDER BY workspace_id`,
		provider, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ws string
		if err := rows.Scan(&ws); err != nil {
			return nil, err
		}
		out = append(out, ws)
	}
	return out, rows.Err()
}

// UpsertFirstAdmin joins a principal to a workspace, applying the "first human in
// an empty workspace becomes ws-admin" rule race-free: the emptiness probe and
// the insert run in one SERIALIZABLE transaction, so two concurrent first logins
// cannot both win — exactly one is admin, the other is mapped normally.
func (s *sqlStore) UpsertFirstAdmin(ws string, rec *MemberRecord) (isFirstAdmin bool, err error) {
	if verr := validateMemberIdentity(rec.Provider, rec.Subject); verr != nil {
		return false, verr
	}
	now := rec.UpdatedUnix
	if now == 0 {
		now = time.Now().Unix()
	}
	// Snapshot the caller's inputs so a SERIALIZABLE retry re-runs from the same
	// starting point rather than from a half-mutated record.
	origRoles := append([]string(nil), rec.Roles...)
	origAddedBy := rec.AddedBy
	origCreated := rec.CreatedUnix
	err = s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		isFirstAdmin = false
		rec.Roles = append([]string(nil), origRoles...)
		rec.AddedBy = origAddedBy
		rec.CreatedUnix = origCreated
		var raw []byte
		gerr := s.queryRow(s.ctx(), tx, `SELECT doc FROM members WHERE workspace_id=$1 AND provider=$2 AND subject=$3 FOR UPDATE`,
			ws, rec.Provider, rec.Subject).Scan(&raw)
		if gerr == nil {
			var ex MemberRecord
			if uerr := json.Unmarshal(raw, &ex); uerr != nil {
				return uerr
			}
			ex.Username = rec.Username
			ex.Groups = rec.Groups
			if rec.SourceUID != "" {
				ex.SourceUID = rec.SourceUID
			}
			ex.UpdatedUnix = now
			*rec = ex // hand the canonical stored record back to the caller
			return s.upsertMember(tx, ws, &ex)
		}
		if !errors.Is(gerr, sql.ErrNoRows) {
			return gerr
		}
		var anyMember bool
		if perr := s.queryRow(s.ctx(), tx, `SELECT EXISTS(SELECT 1 FROM members WHERE workspace_id=$1)`, ws).Scan(&anyMember); perr != nil {
			return perr
		}
		if !anyMember {
			rec.Roles = []string{roleWSAdmin}
			isFirstAdmin = true
			if rec.AddedBy == "" {
				rec.AddedBy = "auto:first-user"
			}
		}
		rec.Roles = stripReservedRoles(rec.Roles)
		if rec.CreatedUnix == 0 {
			rec.CreatedUnix = now
		}
		rec.UpdatedUnix = now
		return s.upsertMember(tx, ws, rec)
	})
	return isFirstAdmin, err
}

// --- suspensions (global authorization deny) ---

func (s *sqlStore) SuspendPrincipal(ws, provider, subject, username, by, reason string) error {
	if subject == "" {
		return fmt.Errorf("cannot suspend: empty subject (principal is not keyable)")
	}
	rec := &SuspensionRecord{
		Workspace: ws, Provider: normProvider(provider), Subject: subject, Username: username,
		Reason: reason, SuspendedBy: by, SuspendedUnix: time.Now().Unix(),
	}
	doc, err := marshalDoc(rec)
	if err != nil {
		return err
	}
	// In a txn so the suspend doorbell commits atomically with the row (so a peer
	// controller can drop its cached allow for this principal sub-TTL).
	return s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		if _, err := s.exec(s.ctx(), tx, `INSERT INTO suspensions (workspace_id, provider, subject, suspended_unix, doc)
			 VALUES ($1, $2, $3, $4, $5::jsonb)
			 ON CONFLICT (workspace_id, provider, subject)
			 DO UPDATE SET suspended_unix = EXCLUDED.suspended_unix, doc = EXCLUDED.doc`,
			ws, rec.Provider, subject, rec.SuspendedUnix, doc); err != nil {
			return err
		}
		return s.notify(s.ctx(), tx, chanSuspend, encPrincipal(ws, rec.Provider, subject))
	})
}

func (s *sqlStore) LiftSuspension(ws, provider, subject string) error {
	return s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		if _, err := s.exec(s.ctx(), tx, `DELETE FROM suspensions WHERE workspace_id=$1 AND provider=$2 AND subject=$3`,
			ws, normProvider(provider), subject); err != nil {
			return err
		}
		return s.notify(s.ctx(), tx, chanLift, encPrincipal(ws, normProvider(provider), subject))
	})
}

// IsSuspended reports whether a login principal is suspended. An empty subject
// (operational cert) is never member-suspended; a query error fails closed (deny).
func (s *sqlStore) IsSuspended(ws, provider, subject string) bool {
	present, err := s.IsSuspendedE(ws, provider, subject)
	if err != nil {
		return true
	}
	return present
}

// IsSuspendedE is the error-returning twin the deny cache fronts.
func (s *sqlStore) IsSuspendedE(ws, provider, subject string) (bool, error) {
	if !suspendable(subject) {
		return false, nil
	}
	var present bool
	err := s.queryRow(s.ctx(), s.db, `SELECT EXISTS(SELECT 1 FROM suspensions WHERE workspace_id=$1 AND provider=$2 AND subject=$3)`,
		ws, normProvider(provider), subject).Scan(&present)
	return present, err
}

func (s *sqlStore) ListSuspensions(ws string) ([]*SuspensionRecord, error) {
	if ws == "" {
		return sqlListDocs[SuspensionRecord](s.ctx(), s, s.db,
			`SELECT doc FROM suspensions ORDER BY suspended_unix DESC`)
	}
	return sqlListDocs[SuspensionRecord](s.ctx(), s, s.db,
		`SELECT doc FROM suspensions WHERE workspace_id=$1 ORDER BY suspended_unix DESC`, ws)
}

// --- node drift quarantine (node-scoped authorization deny) ---

func (s *sqlStore) QuarantineNode(ws, nodeID, reason, by string, detail map[string]string) (*NodeRecord, error) {
	var n NodeRecord
	err := s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		n = NodeRecord{}
		var raw []byte
		err := s.queryRow(s.ctx(), tx, `SELECT doc FROM nodes WHERE workspace_id=$1 AND id=$2 FOR UPDATE`, ws, nodeID).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if uerr := json.Unmarshal(raw, &n); uerr != nil {
			return uerr
		}
		n.Approved = false
		n.ApprovedBy = ""
		n.ApprovedAtUnix = 0
		doc, merr := marshalDoc(&n)
		if merr != nil {
			return merr
		}
		if _, err = s.exec(s.ctx(), tx, `UPDATE nodes SET doc=$3::jsonb WHERE workspace_id=$1 AND id=$2`, ws, nodeID, doc); err != nil {
			return err
		}
		rec := &QuarantineRecord{
			Workspace: ws, NodeID: nodeID, Reason: reason, Detail: detail,
			QuarantinedBy: by, QuarantinedUnix: time.Now().Unix(), HostUUID: n.Platform.HostUUID,
		}
		qdoc, qerr := marshalDoc(rec)
		if qerr != nil {
			return qerr
		}
		_, err = s.exec(s.ctx(), tx, `INSERT INTO node_quarantines (workspace_id, node_id, host_uuid, quarantined_unix, doc)
			 VALUES ($1, $2, $3, $4, $5::jsonb)
			 ON CONFLICT (workspace_id, node_id)
			 DO UPDATE SET host_uuid = EXCLUDED.host_uuid, quarantined_unix = EXCLUDED.quarantined_unix, doc = EXCLUDED.doc`,
			ws, nodeID, rec.HostUUID, rec.QuarantinedUnix, qdoc)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &n, nil
}

func (s *sqlStore) GetQuarantine(ws, nodeID string) (*QuarantineRecord, error) {
	return sqlGetDoc[QuarantineRecord](s.ctx(), s, s.db,
		`SELECT doc FROM node_quarantines WHERE workspace_id=$1 AND node_id=$2`, ws, nodeID)
}

func (s *sqlStore) ListQuarantines(ws string) ([]*QuarantineRecord, error) {
	if ws == "" {
		return sqlListDocs[QuarantineRecord](s.ctx(), s, s.db,
			`SELECT doc FROM node_quarantines ORDER BY quarantined_unix DESC`)
	}
	return sqlListDocs[QuarantineRecord](s.ctx(), s, s.db,
		`SELECT doc FROM node_quarantines WHERE workspace_id=$1 ORDER BY quarantined_unix DESC`, ws)
}

func (s *sqlStore) FindQuarantineByHostUUID(ws, uuid string) (*QuarantineRecord, error) {
	if uuid == "" {
		return nil, ErrNotFound
	}
	return sqlGetDoc[QuarantineRecord](s.ctx(), s, s.db,
		`SELECT doc FROM node_quarantines WHERE workspace_id=$1 AND host_uuid=$2 LIMIT 1`, ws, uuid)
}

func (s *sqlStore) RecordNodeMeasurement(ws, nodeID string, binHash []byte, atUnix int64) (drift, pinned bool, n *NodeRecord, err error) {
	if len(binHash) != sha256Len {
		return false, false, nil, fmt.Errorf("binary hash must be %d bytes, got %d", sha256Len, len(binHash))
	}
	var rec NodeRecord
	terr := s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		rec = NodeRecord{}
		var raw []byte
		err := s.queryRow(s.ctx(), tx, `SELECT doc FROM nodes WHERE workspace_id=$1 AND id=$2 FOR UPDATE`, ws, nodeID).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if uerr := json.Unmarshal(raw, &rec); uerr != nil {
			return uerr
		}
		rec.LastBinaryHash = binHash
		rec.LastMeasuredUnix = atUnix
		if rec.Approved {
			if len(rec.ApprovedBinaryHash) == 0 {
				rec.ApprovedBinaryHash = binHash
				pinned = true
			} else if !bytes.Equal(rec.ApprovedBinaryHash, binHash) {
				drift = true
			}
		}
		doc, merr := marshalDoc(&rec)
		if merr != nil {
			return merr
		}
		_, err = s.exec(s.ctx(), tx, `UPDATE nodes SET doc=$3::jsonb WHERE workspace_id=$1 AND id=$2`, ws, nodeID, doc)
		return err
	})
	if terr != nil {
		return false, false, nil, terr
	}
	return drift, pinned, &rec, nil
}

func (s *sqlStore) RepinBaseline(ws, nodeID string, binHash []byte, createdUnix int64) error {
	return s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		var raw []byte
		err := s.queryRow(s.ctx(), tx, `SELECT doc FROM nodes WHERE workspace_id=$1 AND id=$2 FOR UPDATE`, ws, nodeID).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		var n NodeRecord
		if uerr := json.Unmarshal(raw, &n); uerr != nil {
			return uerr
		}
		n.ApprovedBinaryHash = binHash
		n.ApprovedBinaryCreatedUnix = createdUnix
		n.LastBinaryHash = binHash
		doc, merr := marshalDoc(&n)
		if merr != nil {
			return merr
		}
		_, err = s.exec(s.ctx(), tx, `UPDATE nodes SET doc=$3::jsonb WHERE workspace_id=$1 AND id=$2`, ws, nodeID, doc)
		return err
	})
}

// --- browser auth sessions (global) ---

func (s *sqlStore) PutAuthSession(rec *AuthSession) error {
	doc, err := marshalDoc(rec)
	if err != nil {
		return err
	}
	_, err = s.exec(s.ctx(), s.db, `INSERT INTO auth_sessions (token_hash, user_name, provider, subject, expires_unix, doc)
		 VALUES ($1, $2, $3, $4, $5, $6::jsonb)
		 ON CONFLICT (token_hash) DO UPDATE SET
		   user_name = EXCLUDED.user_name, provider = EXCLUDED.provider,
		   subject = EXCLUDED.subject, expires_unix = EXCLUDED.expires_unix, doc = EXCLUDED.doc`,
		rec.TokenHash, rec.User, normProvider(rec.Provider), rec.Subject, rec.ExpiresUnix, doc)
	return err
}

func (s *sqlStore) GetAuthSession(tokenHash string) (*AuthSession, error) {
	return sqlGetDoc[AuthSession](s.ctx(), s, s.db, `SELECT doc FROM auth_sessions WHERE token_hash=$1`, tokenHash)
}

func (s *sqlStore) DeleteAuthSession(tokenHash string) error {
	_, err := s.exec(s.ctx(), s.db, `DELETE FROM auth_sessions WHERE token_hash=$1`, tokenHash)
	return err
}

func (s *sqlStore) ListAuthSessions() ([]*AuthSession, error) {
	return sqlListDocs[AuthSession](s.ctx(), s, s.db, `SELECT doc FROM auth_sessions ORDER BY token_hash`)
}

func (s *sqlStore) RevokeAuthSessionsForUser(user string) (int, error) {
	ct, err := s.exec(s.ctx(), s.db, `DELETE FROM auth_sessions WHERE user_name=$1`, user)
	if err != nil {
		return 0, err
	}
	n, _ := ct.RowsAffected()
	return int(n), nil
}

func (s *sqlStore) RevokeAuthSessionsForSubject(provider, subject string) (int, error) {
	if subject == "" {
		return 0, nil
	}
	ct, err := s.exec(s.ctx(), s.db, `DELETE FROM auth_sessions WHERE provider=$1 AND subject=$2`, normProvider(provider), subject)
	if err != nil {
		return 0, err
	}
	n, _ := ct.RowsAffected()
	return int(n), nil
}

func (s *sqlStore) SweepExpiredAuthSessions(now int64) (int, error) {
	ct, err := s.exec(s.ctx(), s.db, `DELETE FROM auth_sessions WHERE expires_unix > 0 AND expires_unix <= $1`, now)
	if err != nil {
		return 0, err
	}
	n, _ := ct.RowsAffected()
	return int(n), nil
}

// --- one-time WS-shell tickets (global) ---

func (s *sqlStore) MintWSTicket(sessionTokenHash, nodeID string, ttl time.Duration) (string, error) {
	ticket, err := randToken(32)
	if err != nil {
		return "", err
	}
	rec := &WSTicket{
		TicketHash: hashToken(ticket), SessionTokenHash: sessionTokenHash,
		NodeID: nodeID, ExpiresUnix: time.Now().Add(ttl).Unix(),
	}
	doc, err := marshalDoc(rec)
	if err != nil {
		return "", err
	}
	if _, err := s.exec(s.ctx(), s.db, `INSERT INTO ws_tickets (ticket_hash, expires_unix, doc) VALUES ($1, $2, $3::jsonb)`,
		rec.TicketHash, rec.ExpiresUnix, doc); err != nil {
		return "", err
	}
	return ticket, nil
}

// RedeemWSTicket consumes a ticket once. The delete-on-read burns the ticket on
// any redeem attempt; only one of two concurrent redeems gets the row.
func (s *sqlStore) RedeemWSTicket(ticket string, now int64) (sessionTokenHash, nodeID string, err error) {
	th := hashToken(ticket)
	err = s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		sessionTokenHash, nodeID = "", ""
		raw, gerr := s.dialect.deleteReturningDoc(s.ctx(), tx, "ws_tickets", "ticket_hash", th)
		if errors.Is(gerr, sql.ErrNoRows) {
			return errInvalidTicket
		}
		if gerr != nil {
			return gerr
		}
		var rec WSTicket
		if uerr := json.Unmarshal(raw, &rec); uerr != nil {
			return uerr
		}
		if now >= rec.ExpiresUnix {
			return errInvalidTicket
		}
		sessionTokenHash = rec.SessionTokenHash
		nodeID = rec.NodeID
		return nil
	})
	return sessionTokenHash, nodeID, err
}

// --- trusted-dashboard handoff codes (global) ---

func (s *sqlStore) PutHandoff(rec *HandoffRecord) error {
	doc, err := marshalDoc(rec)
	if err != nil {
		return err
	}
	_, err = s.exec(s.ctx(), s.db, `INSERT INTO handoff_codes (code_hash, expires_unix, doc) VALUES ($1, $2, $3::jsonb)
		 ON CONFLICT (code_hash) DO UPDATE SET expires_unix = EXCLUDED.expires_unix, doc = EXCLUDED.doc`,
		rec.CodeHash, rec.ExpiresUnix, doc)
	return err
}

// RedeemHandoff consumes a handoff code once. The code is burned on any redeem
// attempt (a bad cookie still spends it); only one concurrent redeem wins the row.
func (s *sqlStore) RedeemHandoff(code, cookie string, now int64) (sessionInput, error) {
	ch := hashToken(code)
	var out sessionInput
	err := s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		out = sessionInput{}
		raw, gerr := s.dialect.deleteReturningDoc(s.ctx(), tx, "handoff_codes", "code_hash", ch)
		if errors.Is(gerr, sql.ErrNoRows) {
			return fmt.Errorf("invalid or used handoff code")
		}
		if gerr != nil {
			return gerr
		}
		var rec HandoffRecord
		if uerr := json.Unmarshal(raw, &rec); uerr != nil {
			return uerr
		}
		if now >= rec.ExpiresUnix {
			return fmt.Errorf("handoff code expired")
		}
		if rec.CookieHash != hashToken(cookie) {
			return fmt.Errorf("handoff cookie mismatch")
		}
		out = rec.Session
		return nil
	})
	return out, err
}

func (s *sqlStore) SweepExpiredHandoffs(now int64) (int, error) {
	ct, err := s.exec(s.ctx(), s.db, `DELETE FROM handoff_codes WHERE expires_unix <= $1`, now)
	if err != nil {
		return 0, err
	}
	n, _ := ct.RowsAffected()
	return int(n), nil
}

// --- device grants (global, RFC 8628 CLI login) ---

func (s *sqlStore) PutDeviceGrant(g *DeviceGrant) error {
	doc, err := marshalDoc(g)
	if err != nil {
		return err
	}
	_, err = s.exec(s.ctx(), s.db, `INSERT INTO device_codes (device_hash, user_code_hash, expires_unix, doc)
		 VALUES ($1, $2, $3, $4::jsonb)
		 ON CONFLICT (device_hash) DO UPDATE SET
		   user_code_hash = EXCLUDED.user_code_hash, expires_unix = EXCLUDED.expires_unix, doc = EXCLUDED.doc`,
		g.DeviceHash, g.UserCodeHash, g.ExpiresUnix, doc)
	return err
}

func (s *sqlStore) GetDeviceGrantByUserCode(userCode string) (*DeviceGrant, error) {
	uh := hashToken(normalizeUserCode(userCode))
	return sqlGetDoc[DeviceGrant](s.ctx(), s, s.db,
		`SELECT doc FROM device_codes WHERE user_code_hash=$1`, uh)
}

// ApproveDeviceGrant binds the approver tuple to a pending grant (by user code),
// atomically. mutate fills the approval fields from the approving session.
func (s *sqlStore) ApproveDeviceGrant(userCode string, mutate func(*DeviceGrant) error) error {
	uh := hashToken(normalizeUserCode(userCode))
	return s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		var raw []byte
		gerr := s.queryRow(s.ctx(), tx, `SELECT doc FROM device_codes WHERE user_code_hash=$1 FOR UPDATE`, uh).Scan(&raw)
		if errors.Is(gerr, sql.ErrNoRows) {
			return ErrNotFound
		}
		if gerr != nil {
			return gerr
		}
		var g DeviceGrant
		if uerr := json.Unmarshal(raw, &g); uerr != nil {
			return uerr
		}
		if g.State != deviceStatePending {
			return fmt.Errorf("device grant is %s, not pending", g.State)
		}
		if time.Now().Unix() >= g.ExpiresUnix {
			return fmt.Errorf("device grant expired")
		}
		if err := mutate(&g); err != nil {
			return err
		}
		return s.putDeviceGrantTx(tx, &g)
	})
}

func (s *sqlStore) DenyDeviceGrant(userCode string) error {
	return s.ApproveDeviceGrant(userCode, func(g *DeviceGrant) error {
		g.State = deviceStateDenied
		return nil
	})
}

func (s *sqlStore) putDeviceGrantTx(tx *sql.Tx, g *DeviceGrant) error {
	doc, err := marshalDoc(g)
	if err != nil {
		return err
	}
	_, err = s.exec(s.ctx(), tx, `INSERT INTO device_codes (device_hash, user_code_hash, expires_unix, doc)
		 VALUES ($1, $2, $3, $4::jsonb)
		 ON CONFLICT (device_hash) DO UPDATE SET
		   user_code_hash = EXCLUDED.user_code_hash, expires_unix = EXCLUDED.expires_unix, doc = EXCLUDED.doc`,
		g.DeviceHash, g.UserCodeHash, g.ExpiresUnix, doc)
	return err
}

// PollDeviceGrant runs the RFC 8628 token-endpoint state machine for one poll. On
// success it issues the cert INSIDE the redeem transaction (so the cert is never
// persisted) and marks the grant redeemed atomically; a concurrent poll on the
// same grant serializes on the row lock and sees the redeemed state, so a grant
// is issued exactly once.
func (s *sqlStore) PollDeviceGrant(deviceCode string, now int64, issue func(g *DeviceGrant) ([]byte, error)) ([]byte, error) {
	dh := hashToken(deviceCode)
	var certPEM []byte
	err := s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		certPEM = nil
		var raw []byte
		gerr := s.queryRow(s.ctx(), tx, `SELECT doc FROM device_codes WHERE device_hash=$1 FOR UPDATE`, dh).Scan(&raw)
		if errors.Is(gerr, sql.ErrNoRows) {
			return deviceTokenError{"expired_token"} // unknown == expired/invalid
		}
		if gerr != nil {
			return gerr
		}
		var g DeviceGrant
		if uerr := json.Unmarshal(raw, &g); uerr != nil {
			return uerr
		}
		if now >= g.ExpiresUnix {
			if _, e := s.exec(s.ctx(), tx, `DELETE FROM device_codes WHERE device_hash=$1`, dh); e != nil {
				return e
			}
			return deviceTokenError{"expired_token"}
		}
		switch g.State {
		case deviceStateDenied:
			if _, e := s.exec(s.ctx(), tx, `DELETE FROM device_codes WHERE device_hash=$1`, dh); e != nil {
				return e
			}
			return deviceTokenError{"access_denied"}
		case deviceStateRedeemed:
			return deviceTokenError{"expired_token"} // already consumed (single-use)
		case deviceStateApproved:
			if s.isSuspendedTx(s.ctx(), tx, g.ApprovedWS, g.ApprovedProvider, g.ApprovedSubject) {
				return deviceTokenError{"access_denied"}
			}
			pem, ierr := issue(&g) // cert minted inside the txn; never persisted
			if ierr != nil {
				return ierr // rolls back; the grant stays approved for retry
			}
			certPEM = pem
			g.State = deviceStateRedeemed
			return s.putDeviceGrantTx(tx, &g)
		}
		// Still pending: throttle a too-fast poll (RFC 8628 slow_down).
		if g.LastPollUnix > 0 && now-g.LastPollUnix < int64(g.Interval) {
			g.Interval += 5
			g.LastPollUnix = now
			if e := s.putDeviceGrantTx(tx, &g); e != nil {
				return e
			}
			return deviceTokenError{"slow_down"}
		}
		g.LastPollUnix = now
		if e := s.putDeviceGrantTx(tx, &g); e != nil {
			return e
		}
		return deviceTokenError{"authorization_pending"}
	})
	if err != nil {
		return nil, err
	}
	return certPEM, nil
}

// isSuspendedTx is the transaction-scoped suspension check used inside the device
// redeem, mirroring the bbolt tx-scoped check: an empty subject is never
// suspended, a present row (or a query error) denies (fail closed).
func (s *sqlStore) isSuspendedTx(ctx context.Context, tx *sql.Tx, ws, provider, subject string) bool {
	if !suspendable(subject) {
		return false
	}
	var present bool
	if err := s.queryRow(ctx, tx,
		`SELECT EXISTS(SELECT 1 FROM suspensions WHERE workspace_id=$1 AND provider=$2 AND subject=$3)`,
		ws, normProvider(provider), subject).Scan(&present); err != nil {
		return true
	}
	return present
}

func (s *sqlStore) countDeviceGrants() (int, error) {
	var n int
	err := s.queryRow(s.ctx(), s.db, `SELECT count(*) FROM device_codes`).Scan(&n)
	return n, err
}

func (s *sqlStore) SweepExpiredDeviceGrants(now int64) (int, error) {
	ct, err := s.exec(s.ctx(), s.db, `DELETE FROM device_codes WHERE expires_unix <= $1`, now)
	if err != nil {
		return 0, err
	}
	n, _ := ct.RowsAffected()
	return int(n), nil
}

// --- reconcile lock (advisory) ---

// TryReconcileLock takes a NON-BLOCKING advisory lock that debounces the fleet-map
// rebuild so multiple controllers do not redundantly re-sign the same map. It is
// transient: the returned release unlocks and returns the connection to the pool,
// so the coordinator role moves freely on each tick — there is no sticky leader.
// The lock is held on a single pinned connection (PG advisory + MySQL GET_LOCK are
// both connection-scoped), so acquire and release run on the SAME *sql.Conn.
func (s *sqlStore) TryReconcileLock(ctx context.Context) (held bool, release func(), err error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return false, nil, err
	}
	ok, err := s.dialect.tryAdvisoryLock(ctx, conn, reconcileLockKey)
	if err != nil {
		_ = conn.Close()
		return false, nil, err
	}
	if !ok {
		_ = conn.Close()
		return false, nil, nil
	}
	return true, func() {
		_ = s.dialect.advisoryUnlock(context.Background(), conn, reconcileLockKey)
		_ = conn.Close()
	}, nil
}

// TryVulnSyncLock takes the same kind of NON-BLOCKING, transient advisory lock as
// TryReconcileLock but on a distinct key, so it debounces the daily vuln-feed sync
// without contending with the fleet-map rebuild. Whoever fires first this tick
// grabs it, runs the sync + post-sync re-match, and releases — no sticky leader;
// the watermark persisted in settings makes a sync correct-on-loss (a controller that
// dies mid-sync just leaves the watermark unadvanced and another retries).
func (s *sqlStore) TryVulnSyncLock(ctx context.Context) (held bool, release func(), err error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return false, nil, err
	}
	ok, err := s.dialect.tryAdvisoryLock(ctx, conn, vulnSyncLockKey)
	if err != nil {
		_ = conn.Close()
		return false, nil, err
	}
	if !ok {
		_ = conn.Close()
		return false, nil, nil
	}
	return true, func() {
		_ = s.dialect.advisoryUnlock(context.Background(), conn, vulnSyncLockKey)
		_ = conn.Close()
	}, nil
}
