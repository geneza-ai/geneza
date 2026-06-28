package controller

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
)

// The SQL store speaks one query vocabulary written for Postgres and adapts it to
// each engine through this dialect seam. The Postgres queries stay verbatim ($N
// placeholders, ::jsonb casts, ON CONFLICT, RETURNING); the MySQL/MariaDB dialect
// rewrites the placeholder style, swaps the JSON cast and extract syntax, and
// supplies the few statements the two engines cannot share (the upsert+RETURNING
// and DELETE+RETURNING forms MySQL lacks). Everything else — the SERIALIZABLE
// invariants, the deny-path reads, the fail-closed behaviour — is identical across
// engines because it is expressed once against this interface.

// sqlExec is the subset of database/sql shared by *sql.DB, *sql.Tx and *sql.Conn,
// so a query helper can run either autocommit or inside a transaction (or pinned
// to one connection).
type sqlExec interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

//go:embed sqlschema.sql
var sqlSchemaPG string

//go:embed sqlschema_mysql.sql
var sqlSchemaMySQL string

// dialect abstracts the per-engine differences the SQL store needs. One impl per
// engine; the store holds exactly one. name is the human-facing backend label.
type dialect interface {
	name() string
	driver() string

	// rewrite adapts a query written in the canonical Postgres form to this
	// engine: a no-op on Postgres; on MySQL it rewrites $N placeholders to ? and
	// the upsert/keyword syntax. Used for queries with no parameters or whose $N
	// already appear in strict ascending order; bind() is used when arguments must
	// be remapped (see below).
	rewrite(query string) string

	// bind rewrites a canonical query AND returns the argument slice in the order
	// the rewritten query consumes it. Postgres keeps $N positional, so args pass
	// through unchanged; MySQL uses anonymous ? bound by order of appearance, so a
	// query that reuses or reorders $N (e.g. `SET doc=$2 WHERE id=$1`) needs its
	// args reordered/duplicated to match. Every parameterized query goes through
	// bind so positional drift can never silently mis-bind a deny-path write.
	bind(query string, args []any) (string, []any)

	// jsonField renders an extraction of a top-level JSON string field for use in
	// a WHERE/ORDER BY: Postgres doc->>'f', MySQL JSON_UNQUOTE(JSON_EXTRACT(doc,'$.f')).
	jsonField(col, field string) string

	// isSerializationFailure reports whether err is the engine's retryable
	// serialization/deadlock signal (PG 40001; MySQL 1213/1205).
	isSerializationFailure(err error) bool

	// schema is the full DDL applied (idempotently) on open.
	schema() string

	// notifyInTx rings a deny-path doorbell from inside the caller's transaction,
	// so it commits atomically with the row it announces. Postgres issues a
	// pg_notify; MySQL has no in-band pub/sub, so it is a no-op there and the
	// MySQL realtime bus polls the authoritative rows on a sub-TTL timer instead.
	notifyInTx(ctx context.Context, tx *sql.Tx, channel, payload string) error

	// tryAdvisoryLock / advisoryUnlock take and release a connection-scoped
	// advisory lock on the given pinned connection. tryAdvisoryLock is
	// non-blocking and reports whether the lock was acquired.
	tryAdvisoryLock(ctx context.Context, conn *sql.Conn, key int64) (bool, error)
	advisoryUnlock(ctx context.Context, conn *sql.Conn, key int64) error

	// putNode upserts a node row. Same (workspace_id, id) updates in place; a
	// different workspace claiming an already-used id must ERROR (the globally-unique
	// node id is the single-active-node-per-uuid guard). On Postgres ON CONFLICT
	// targets only the primary key, so the separate unique index on id raises the
	// violation for free; MySQL's ON DUPLICATE KEY UPDATE fires for ANY unique key,
	// so its impl forces an error when the matched row's workspace differs.
	putNode(ctx context.Context, ex sqlExec, ws, id, name, doc string) error

	// claimAffinity performs the affinity claim (upsert that bumps the epoch) and
	// returns the resulting epoch. PG does it in one upsert+RETURNING; MySQL does
	// the upsert then reads the epoch back inside the same serializable txn.
	claimAffinity(ctx context.Context, tx *sql.Tx, nodeID, controllerID string, claimedUnix int64) (int64, error)

	// putAdvertisedServices performs the epoch-gated advertised-services write
	// (only overwrite when the incoming epoch is at least the stored one).
	putAdvertisedServices(ctx context.Context, ex sqlExec, ws, nodeID string, epoch int64, doc string) error

	// deleteReturningDoc deletes a single row matched by one key column and returns
	// its doc, or sql.ErrNoRows if absent. Burns the row whether or not it was
	// valid (single-use redeem). The whole operation runs inside the caller's
	// serializable txn.
	deleteReturningDoc(ctx context.Context, tx *sql.Tx, table, keyCol, key string) ([]byte, error)
}

// --- Postgres ---

type pgDialect struct{}

func (pgDialect) name() string                              { return "postgres" }
func (pgDialect) driver() string                            { return "pgx" }
func (pgDialect) rewrite(q string) string                   { return q }
func (pgDialect) bind(q string, args []any) (string, []any) { return q, args }
func (pgDialect) jsonField(col, field string) string        { return col + "->>'" + field + "'" }
func (pgDialect) schema() string                     { return sqlSchemaPG }

func (pgDialect) isSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40001"
}

func (pgDialect) tryAdvisoryLock(ctx context.Context, conn *sql.Conn, key int64) (bool, error) {
	var ok bool
	err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&ok)
	return ok, err
}

func (pgDialect) advisoryUnlock(ctx context.Context, conn *sql.Conn, key int64) error {
	_, err := conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, key)
	return err
}

func (pgDialect) notifyInTx(ctx context.Context, tx *sql.Tx, channel, payload string) error {
	_, err := tx.ExecContext(ctx, "SELECT pg_notify($1, $2)", channel, payload)
	return err
}

func (pgDialect) putNode(ctx context.Context, ex sqlExec, ws, id, name, doc string) error {
	// ON CONFLICT names only the primary key; the separate unique index on id raises
	// a violation when a different workspace tries to claim a used id.
	_, err := ex.ExecContext(ctx,
		`INSERT INTO nodes (workspace_id, id, name, doc) VALUES ($1, $2, $3, $4::jsonb)
		 ON CONFLICT (workspace_id, id) DO UPDATE SET name = EXCLUDED.name, doc = EXCLUDED.doc`,
		ws, id, name, doc)
	return err
}

func (pgDialect) claimAffinity(ctx context.Context, tx *sql.Tx, nodeID, controllerID string, claimedUnix int64) (int64, error) {
	var epoch int64
	err := tx.QueryRowContext(ctx,
		`INSERT INTO agent_affinity (node_id, controller_id, epoch, claimed_unix)
		 VALUES ($1, $2, 1, $3)
		 ON CONFLICT (node_id) DO UPDATE
		   SET controller_id = EXCLUDED.controller_id,
		       epoch = agent_affinity.epoch + 1,
		       claimed_unix = EXCLUDED.claimed_unix
		 RETURNING epoch`, nodeID, controllerID, claimedUnix).Scan(&epoch)
	return epoch, err
}

func (pgDialect) putAdvertisedServices(ctx context.Context, ex sqlExec, ws, nodeID string, epoch int64, doc string) error {
	_, err := ex.ExecContext(ctx,
		`INSERT INTO advertised_services (workspace_id, node_id, epoch, doc) VALUES ($1, $2, $3, $4::jsonb)
		 ON CONFLICT (workspace_id, node_id) DO UPDATE
		   SET epoch = EXCLUDED.epoch, doc = EXCLUDED.doc
		   WHERE advertised_services.epoch <= EXCLUDED.epoch`, ws, nodeID, epoch, doc)
	return err
}

func (pgDialect) deleteReturningDoc(ctx context.Context, tx *sql.Tx, table, keyCol, key string) ([]byte, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx,
		fmt.Sprintf(`DELETE FROM %s WHERE %s=$1 RETURNING doc`, table, keyCol), key).Scan(&raw)
	return raw, err
}

// --- MySQL / MariaDB ---

type myDialect struct{}

func (myDialect) name() string   { return "mariadb" }
func (myDialect) driver() string { return "mysql" }
func (myDialect) schema() string { return sqlSchemaMySQL }

func (myDialect) jsonField(col, field string) string {
	return "JSON_UNQUOTE(JSON_EXTRACT(" + col + ",'$." + field + "'))"
}

// rewrite turns the canonical Postgres query into a MySQL one: positional $N
// placeholders become ?, and the doc->>'f' JSON extraction becomes the MySQL
// JSON_UNQUOTE(JSON_EXTRACT(...)) form. The only callers that build queries with
// the ->> operator are the session list view, which assembles its WHERE/ORDER BY
// through jsonField() — so by the time text reaches rewrite() the operator is
// already gone. rewrite() therefore only has to renumber placeholders; it is
// applied to every query so a stray engine difference is caught in one place.
func (myDialect) rewrite(q string) string {
	// Quote the reserved `key` column BEFORE the upsert rewrite injects the literal
	// `ON DUPLICATE KEY UPDATE` (whose KEY must stay bare).
	return rewriteUpsert(mysqlPlaceholders(quoteMySQLKeywords(q)))
}

// bind rewrites the query and reorders args to match MySQL's by-appearance binding:
// each $N in the canonical query, in the order it appears, consumes args[N-1]. A
// query whose $N run in strict ascending order is unchanged; one that reorders or
// reuses them (SET doc=$2 WHERE id=$1, a LIKE reusing $n) is remapped so the right
// value reaches the right anonymous placeholder.
func (d myDialect) bind(q string, args []any) (string, []any) {
	order := placeholderOrder(q)
	if len(order) == 0 {
		return d.rewrite(q), args
	}
	out := make([]any, 0, len(order))
	for _, n := range order {
		if n < 1 || n > len(args) {
			// A placeholder index with no matching arg is a programming error; leave
			// the original args so the driver surfaces a clear arg-count mismatch.
			return d.rewrite(q), args
		}
		out = append(out, args[n-1])
	}
	return d.rewrite(q), out
}

// placeholderOrder returns the sequence of $N indices in their order of appearance
// in q, skipping any inside a single-quoted string literal.
func placeholderOrder(q string) []int {
	var order []int
	inStr := false
	for i := 0; i < len(q); i++ {
		c := q[i]
		if c == '\'' {
			inStr = !inStr
			continue
		}
		if c == '$' && !inStr && i+1 < len(q) && q[i+1] >= '0' && q[i+1] <= '9' {
			j := i + 1
			n := 0
			for j < len(q) && q[j] >= '0' && q[j] <= '9' {
				n = n*10 + int(q[j]-'0')
				j++
			}
			order = append(order, n)
			i = j - 1
		}
	}
	return order
}

// rewriteUpsert turns a Postgres `INSERT ... VALUES (...) ON CONFLICT (cols) DO
// UPDATE SET a = EXCLUDED.a, ...` into the MariaDB equivalent `INSERT ... VALUES
// (...) ON DUPLICATE KEY UPDATE a = VALUES(a), ...`. The conflict-target column
// list is dropped — MariaDB keys the upsert off whichever unique/primary index the
// duplicate hit. MariaDB does not support the MySQL 8 row-alias (`AS new`) form, so
// the would-be-inserted value is referenced through VALUES(col): EXCLUDED.col maps
// to VALUES(col). EXCLUDED appears only in these clauses, so the rewrite is local.
func rewriteUpsert(q string) string {
	idx := indexFold(q, "ON CONFLICT")
	if idx < 0 {
		return q
	}
	head := q[:idx]
	rest := q[idx+len("ON CONFLICT"):]
	// Skip whitespace then a balanced (...) conflict target, if present.
	j := 0
	for j < len(rest) && (rest[j] == ' ' || rest[j] == '\n' || rest[j] == '\t' || rest[j] == '\r') {
		j++
	}
	if j < len(rest) && rest[j] == '(' {
		depth := 0
		for j < len(rest) {
			if rest[j] == '(' {
				depth++
			} else if rest[j] == ')' {
				depth--
				if depth == 0 {
					j++
					break
				}
			}
			j++
		}
	}
	rest = rest[j:]
	if k := indexFold(rest, "DO UPDATE SET"); k >= 0 {
		assignments := excludedToValues(rest[k+len("DO UPDATE SET"):])
		return head + "ON DUPLICATE KEY UPDATE" + assignments
	}
	return q // an ON CONFLICT we do not recognize: leave it for a loud failure
}

// excludedToValues rewrites each `EXCLUDED.<col>` reference (any case) to the
// MariaDB `VALUES(<col>)` form used inside ON DUPLICATE KEY UPDATE.
func excludedToValues(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for {
		i := indexFold(s, "EXCLUDED.")
		if i < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:i])
		rest := s[i+len("EXCLUDED."):]
		// Read the column identifier following the dot.
		c := 0
		for c < len(rest) && isIdentChar(rest[c]) {
			c++
		}
		b.WriteString("VALUES(")
		b.WriteString(rest[:c])
		b.WriteString(")")
		s = rest[c:]
	}
	return b.String()
}

// indexFold is a case-insensitive strings.Index.
func indexFold(s, sub string) int {
	return strings.Index(strings.ToUpper(s), strings.ToUpper(sub))
}

// quoteMySQLKeywords backtick-quotes the reserved identifier `key`, which several
// global tables (settings, artifacts, source_bindings, os_enroll) use as a column
// name. Postgres accepts it bare; MySQL reserves KEY, so an unquoted occurrence is
// a syntax error. Only the whole-word identity-column token is quoted — substrings
// (token_hash, user_code_hash, ...) and quoted string literals are left alone.
func quoteMySQLKeywords(q string) string {
	var b strings.Builder
	b.Grow(len(q) + 8)
	inStr := false
	for i := 0; i < len(q); {
		c := q[i]
		if c == '\'' {
			inStr = !inStr
			b.WriteByte(c)
			i++
			continue
		}
		if !inStr && (c == 'k' || c == 'K') && isWordStart(q, i) && hasWord(q, i, "key") {
			b.WriteString("`key`")
			i += 3
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

func isWordStart(q string, i int) bool {
	if i == 0 {
		return true
	}
	return !isIdentChar(q[i-1])
}

func hasWord(q string, i int, word string) bool {
	if i+len(word) > len(q) {
		return false
	}
	if !strings.EqualFold(q[i:i+len(word)], word) {
		return false
	}
	end := i + len(word)
	return end == len(q) || !isIdentChar(q[end])
}

func isIdentChar(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// mysqlPlaceholders replaces $1,$2,... with ? while skipping any $N that sits
// inside a single-quoted SQL string literal (there are none in these queries, but
// the guard keeps the rewrite robust). It also strips the ::jsonb cast that a few
// hand-written inserts carry — MySQL JSON columns take a plain string parameter.
func mysqlPlaceholders(q string) string {
	q = strings.ReplaceAll(q, "::jsonb", "")
	var b strings.Builder
	b.Grow(len(q))
	inStr := false
	for i := 0; i < len(q); i++ {
		c := q[i]
		if c == '\'' {
			inStr = !inStr
			b.WriteByte(c)
			continue
		}
		if c == '$' && !inStr && i+1 < len(q) && q[i+1] >= '0' && q[i+1] <= '9' {
			// Skip the digits of the placeholder index.
			j := i + 1
			for j < len(q) && q[j] >= '0' && q[j] <= '9' {
				j++
			}
			b.WriteByte('?')
			i = j - 1
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func (myDialect) isSerializationFailure(err error) bool {
	var myErr *mysql.MySQLError
	if !errors.As(err, &myErr) {
		return false
	}
	// 1213 = ER_LOCK_DEADLOCK, 1205 = ER_LOCK_WAIT_TIMEOUT, and (MariaDB
	// SERIALIZABLE) 1020 = ER_CHECKREAD "record has changed since last read": all
	// three resolve by re-running the read-decide-write, exactly like a PG 40001.
	return myErr.Number == 1213 || myErr.Number == 1205 || myErr.Number == 1020
}

func (myDialect) tryAdvisoryLock(ctx context.Context, conn *sql.Conn, key int64) (bool, error) {
	var got sql.NullInt64
	// GET_LOCK with a 0 timeout is non-blocking: 1 acquired, 0 busy, NULL on error.
	if err := conn.QueryRowContext(ctx, `SELECT GET_LOCK(?, 0)`, advisoryLockName(key)).Scan(&got); err != nil {
		return false, err
	}
	return got.Valid && got.Int64 == 1, nil
}

func (myDialect) advisoryUnlock(ctx context.Context, conn *sql.Conn, key int64) error {
	_, err := conn.ExecContext(ctx, `SELECT RELEASE_LOCK(?)`, advisoryLockName(key))
	return err
}

// advisoryLockName is the string lock name MySQL's GET_LOCK keys on, derived from
// the same 64-bit key Postgres uses so the two engines lock the same logical thing.
func advisoryLockName(key int64) string {
	return "geneza_" + strconv.FormatInt(key, 16)
}

// notifyInTx is a no-op on MySQL: there is no LISTEN/NOTIFY, so the poll bus
// re-reads the authoritative deny rows on its sub-TTL timer instead.
func (myDialect) notifyInTx(context.Context, *sql.Tx, string, string) error { return nil }

func (myDialect) putNode(ctx context.Context, ex sqlExec, ws, id, name, doc string) error {
	// ON DUPLICATE KEY UPDATE fires for the primary key (workspace_id, id) AND for
	// the unique index on id alone. A same-(ws,id) write must update; a same-id
	// DIFFERENT-ws write must error (the node-id-globally-unique guard). When the
	// matched row's workspace differs, the guard expression below evaluates a
	// subquery that returns two rows, raising a cardinality error (1242) — the
	// closest MySQL gets to "abort this upsert" inside an expression.
	_, err := ex.ExecContext(ctx,
		`INSERT INTO nodes (workspace_id, id, name, doc) VALUES (?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE
		   name = IF(nodes.workspace_id = VALUES(workspace_id), VALUES(name),
		             (SELECT 1 FROM (SELECT 1 UNION SELECT 2) AS _conflict)),
		   doc  = IF(nodes.workspace_id = VALUES(workspace_id), VALUES(doc), nodes.doc)`,
		ws, id, name, doc)
	return err
}

func (myDialect) claimAffinity(ctx context.Context, tx *sql.Tx, nodeID, controllerID string, claimedUnix int64) (int64, error) {
	// MySQL has no upsert+RETURNING, so bump in the upsert then read the epoch back
	// — both inside the caller's SERIALIZABLE txn, so the read sees this writer's bump.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO agent_affinity (node_id, controller_id, epoch, claimed_unix)
		 VALUES (?, ?, 1, ?)
		 ON DUPLICATE KEY UPDATE
		   controller_id = VALUES(controller_id),
		   epoch = agent_affinity.epoch + 1,
		   claimed_unix = VALUES(claimed_unix)`, nodeID, controllerID, claimedUnix); err != nil {
		return 0, err
	}
	var epoch int64
	err := tx.QueryRowContext(ctx, `SELECT epoch FROM agent_affinity WHERE node_id=?`, nodeID).Scan(&epoch)
	return epoch, err
}

func (myDialect) putAdvertisedServices(ctx context.Context, ex sqlExec, ws, nodeID string, epoch int64, doc string) error {
	// The epoch gate ("never let an older claim overwrite a newer set") cannot ride
	// a WHERE on ON DUPLICATE KEY UPDATE, so encode it with a conditional GREATEST/IF:
	// when the incoming epoch is below the stored one, keep both stored values.
	_, err := ex.ExecContext(ctx,
		`INSERT INTO advertised_services (workspace_id, node_id, epoch, doc)
		 VALUES (?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE
		   doc   = IF(VALUES(epoch) >= advertised_services.epoch, VALUES(doc), advertised_services.doc),
		   epoch = IF(VALUES(epoch) >= advertised_services.epoch, VALUES(epoch), advertised_services.epoch)`,
		ws, nodeID, epoch, doc)
	return err
}

func (myDialect) deleteReturningDoc(ctx context.Context, tx *sql.Tx, table, keyCol, key string) ([]byte, error) {
	// MySQL has no DELETE ... RETURNING, so SELECT the row FOR UPDATE then DELETE it,
	// inside the caller's serializable txn — a concurrent redeemer blocks on the row
	// lock and finds it gone, so the row is consumed exactly once.
	var raw []byte
	err := tx.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT doc FROM %s WHERE %s=? FOR UPDATE`, table, keyCol), key).Scan(&raw)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		fmt.Sprintf(`DELETE FROM %s WHERE %s=?`, table, keyCol), key); err != nil {
		return nil, err
	}
	return raw, nil
}
