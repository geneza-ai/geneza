package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"geneza.io/internal/affected"
)

// The schema blob is applied on every open, but it is all CREATE ... IF NOT
// EXISTS: against a database that already has the table, a new column in the DDL
// is silently ignored. Anything added after a deployment shipped therefore needs
// an explicit, guarded ALTER — that is what this file is.
//
// Each addition is idempotent (checked against information_schema first) and
// backfilled, so an upgrade converges without an operator step. Keep entries here
// forever once shipped: a deployment may skip several releases.

// schemaAddition is one additive column plus the backfill that gives existing
// rows a value, and the index that should exist once the column does.
type schemaAddition struct {
	table  string
	column string
	// backfill sets the column for rows where it is still NULL. It is expressed
	// per-row in SQL where possible; ecosystem_key cannot be, because the
	// normalization is Go code (a family:release split with per-distro rules), so
	// those are backfilled by reading and rewriting instead — see backfillFn.
	backfillFn func(ctx context.Context, s *sqlStore) error
	// index, when set, is created after the column exists.
	indexName string
	indexCols string
	// binary selects a byte-array column (bytea / LONGBLOB) instead of the default
	// short text one. A DER key or signature does not fit a VARCHAR(64).
	binary bool
}

// schemaAdditions is the ordered list of post-release schema changes.
//
// ecosystem_key (2026-08): the matcher joined advisories to components on the
// verbatim OSV ecosystem string, which never matches for Ubuntu (advisories are
// filed under "Ubuntu:22.04:LTS", agents report "Ubuntu:22.04") and matches only
// one repo for Red Hat. The join now runs on a normalized family:release key.
//
// source_name (2026-08): distro advisories are filed against the SOURCE package
// ("openssl"), while the installed package is a binary split of it ("libssl3").
// Existing rows cannot be backfilled — the agent never sent the source name — so
// they resolve on the binary name alone until each node next reports its inventory.
var schemaAdditions = []schemaAddition{
	{
		table: "node_components", column: "ecosystem_key",
		indexName: "node_components_pkg_key", indexCols: "ecosystem_key, name",
		backfillFn: func(ctx context.Context, s *sqlStore) error {
			return s.backfillEcosystemKey(ctx, "node_components")
		},
	},
	{
		table: "image_components", column: "ecosystem_key",
		indexName: "image_components_pkg_key", indexCols: "ecosystem_key, name",
		backfillFn: func(ctx context.Context, s *sqlStore) error {
			return s.backfillEcosystemKey(ctx, "image_components")
		},
	},
	{
		table: "node_components", column: "source_name",
		indexName: "node_components_src", indexCols: "ecosystem_key, source_name",
	},
	{
		table: "image_components", column: "source_name",
		indexName: "image_components_src", indexCols: "ecosystem_key, source_name",
	},
	{
		table: "advisories", column: "ecosystem_key",
		indexName: "advisories_pkg_key", indexCols: "ecosystem_key, package_name",
		backfillFn: func(ctx context.Context, s *sqlStore) error {
			return s.backfillEcosystemKey(ctx, "advisories")
		},
	},
	// node_spki (2026-08): the node's signature over the recording manifest was
	// stored and served, but the key that made it was not, and node certs rotate
	// daily — so no auditor could ever check it. Rows written before this stay
	// unverifiable (the key is gone); new uploads carry it.
	{table: "recordings", column: "node_spki", binary: true},
}

// ensureSchemaAdditions applies every pending additive change. It runs on open,
// after the DDL blob, and is safe to run concurrently from several controllers:
// each step re-checks existence, and a lost race just means the other replica did
// the work.
func (s *sqlStore) ensureSchemaAdditions(ctx context.Context) error {
	for _, a := range schemaAdditions {
		has, err := s.objectExists(ctx, s.dialect.columnExistsSQL(), a.table, a.column)
		if err != nil {
			return fmt.Errorf("check %s.%s: %w", a.table, a.column, err)
		}
		if !has {
			slog.Info("adding store column", "component", "store", "table", a.table, "column", a.column)
			add := s.dialect.addColumnSQL
			if a.binary {
				add = s.dialect.addBinaryColumnSQL
			}
			if _, err := s.exec(ctx, s.db, add(a.table, a.column)); err != nil {
				// A concurrent replica may have just added it; re-check rather than
				// failing the whole open.
				if again, cerr := s.objectExists(ctx, s.dialect.columnExistsSQL(), a.table, a.column); cerr != nil || !again {
					return fmt.Errorf("add %s.%s: %w", a.table, a.column, err)
				}
			}
		}
		if a.backfillFn != nil {
			if err := a.backfillFn(ctx, s); err != nil {
				return fmt.Errorf("backfill %s.%s: %w", a.table, a.column, err)
			}
		}
		if a.indexName == "" {
			continue
		}
		hasIdx, err := s.objectExists(ctx, s.dialect.indexExistsSQL(), a.table, a.indexName)
		if err != nil {
			return fmt.Errorf("check index %s: %w", a.indexName, err)
		}
		if !hasIdx {
			if _, err := s.exec(ctx, s.db, s.dialect.createIndexSQL(a.indexName, a.table, a.indexCols)); err != nil {
				if again, cerr := s.objectExists(ctx, s.dialect.indexExistsSQL(), a.table, a.indexName); cerr != nil || !again {
					return fmt.Errorf("create index %s: %w", a.indexName, err)
				}
			}
		}
	}
	return nil
}

// objectExists runs a dialect existence probe that takes (table, name).
func (s *sqlStore) objectExists(ctx context.Context, q, table, name string) (bool, error) {
	row := s.queryRow(ctx, s.db, q, table, name)
	var one int
	switch err := row.Scan(&one); {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, err
	}
	return true, nil
}

// backfillEcosystemKey fills ecosystem_key for rows that have none. The mapping is
// Go (ParseEcosystem), not SQL, so this reads the distinct ecosystems present and
// issues one UPDATE per distinct value — a few dozen statements for any real
// dataset, rather than a row-at-a-time rewrite of a million advisories.
func (s *sqlStore) backfillEcosystemKey(ctx context.Context, table string) error {
	rows, err := s.query(ctx, s.db,
		`SELECT DISTINCT ecosystem FROM `+table+` WHERE ecosystem_key IS NULL AND ecosystem IS NOT NULL`)
	if err != nil {
		return err
	}
	var ecos []string
	for rows.Next() {
		var e sql.NullString
		if err := rows.Scan(&e); err != nil {
			rows.Close()
			return err
		}
		if e.Valid && e.String != "" {
			ecos = append(ecos, e.String)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(ecos) == 0 {
		return nil
	}
	slog.Info("backfilling ecosystem keys", "component", "store", "table", table, "ecosystems", len(ecos))
	for _, e := range ecos {
		if _, err := s.exec(ctx, s.db,
			`UPDATE `+table+` SET ecosystem_key = $1 WHERE ecosystem = $2 AND ecosystem_key IS NULL`,
			affected.EcosystemKey(e), e); err != nil {
			return err
		}
	}
	return nil
}
