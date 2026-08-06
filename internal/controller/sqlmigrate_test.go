package controller

import (
	"context"
	"os"
	"testing"
)

// A running deployment already has these tables, and the schema blob is entirely
// CREATE ... IF NOT EXISTS — so it can never add a column to them. This drives the
// real upgrade shape: drop the store back to the pre-ecosystem_key schema, seed it
// with rows carrying the verbatim OSV spelling, reopen, and require that the
// column, the backfill, the index AND the matching join are all in place.
//
// Without the backfill the upgrade is silently worse than the bug it fixes: every
// advisory synced before the upgrade would sit there with a NULL key and match
// nothing, and nothing in the product would say so.
func TestEnsureSchemaAdditionsUpgradesAndBackfills(t *testing.T) {
	dsn := os.Getenv("GENEZA_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set GENEZA_TEST_PG_DSN to run the SQL migration test")
	}
	ctx := context.Background()
	open := func() *sqlStore {
		t.Helper()
		st, err := OpenSQLStore(ctx, "postgres", dsn)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		ss, ok := st.(*sqlStore)
		if !ok {
			t.Fatalf("OpenSQLStore returned %T", st)
		}
		t.Cleanup(func() { ss.Close() })
		return ss
	}
	s := open()

	// Rewind to the pre-migration shape.
	for _, tbl := range []string{"advisories", "node_components", "image_components"} {
		if _, err := s.exec(ctx, s.db, `DELETE FROM `+tbl); err != nil {
			t.Fatalf("clear %s: %v", tbl, err)
		}
		if _, err := s.exec(ctx, s.db, `ALTER TABLE `+tbl+` DROP COLUMN IF EXISTS ecosystem_key`); err != nil {
			t.Fatalf("drop column on %s: %v", tbl, err)
		}
	}

	// Seed as the OLD code would have: the verbatim OSV ecosystem, no key.
	if _, err := s.exec(ctx, s.db,
		`INSERT INTO advisories (id, source, ecosystem, package_name, doc, modified_unix)
		 VALUES ($1,$2,$3,$4,$5::jsonb,$6)`,
		"UBUNTU-CVE-2022-0778", "osv", "Ubuntu:22.04:LTS", "openssl", `{"id":"UBUNTU-CVE-2022-0778"}`, int64(1),
	); err != nil {
		t.Fatalf("seed advisory: %v", err)
	}
	if _, err := s.exec(ctx, s.db,
		`INSERT INTO node_components (workspace_id, node_id, purl, source, ecosystem, name, version, distro)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		"ws", "n1", "pkg:deb/ubuntu/openssl@1.1.1f", "os", "Ubuntu:22.04", "openssl", "1.1.1f", "ubuntu:22.04",
	); err != nil {
		t.Fatalf("seed component: %v", err)
	}

	// Reopening is what a controller restart after an upgrade does.
	up := open()

	// The pre-existing advisory must have been backfilled, or it stays invisible.
	advs, err := up.AdvisoriesForPackage("Ubuntu:22.04", "openssl")
	if err != nil {
		t.Fatalf("AdvisoriesForPackage: %v", err)
	}
	if len(advs) != 1 {
		t.Fatalf("an advisory synced BEFORE the upgrade must still be found after it: got %d", len(advs))
	}

	// And the component index must resolve from the advisory's own spelling.
	comps, err := up.ListComponentsByPackage("ws", "Ubuntu:22.04:LTS", "openssl")
	if err != nil {
		t.Fatalf("ListComponentsByPackage: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("a component indexed BEFORE the upgrade must resolve from the advisory spelling: got %d", len(comps))
	}

	// Idempotent: a second restart must not fail or double-apply.
	_ = open()

	for _, tbl := range []string{"advisories", "node_components", "image_components"} {
		has, err := up.objectExists(ctx, up.dialect.columnExistsSQL(), tbl, "ecosystem_key")
		if err != nil || !has {
			t.Fatalf("%s.ecosystem_key missing after upgrade (err %v)", tbl, err)
		}
	}
}

// node_spki takes the OTHER column path — a byte array, not the short text column
// every earlier addition used. A DER key silently truncated into a VARCHAR(64)
// would still store, still read back, and never verify.
func TestEnsureSchemaAdditionsAddsTheBinaryRecordingKeyColumn(t *testing.T) {
	dsn := os.Getenv("GENEZA_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set GENEZA_TEST_PG_DSN to run the SQL migration test")
	}
	ctx := context.Background()
	open := func() *sqlStore {
		t.Helper()
		st, err := OpenSQLStore(ctx, "postgres", dsn)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		ss := st.(*sqlStore)
		t.Cleanup(func() { ss.Close() })
		return ss
	}
	s := open()
	if _, err := s.exec(ctx, s.db, `DELETE FROM recordings`); err != nil {
		t.Fatalf("clear recordings: %v", err)
	}
	if _, err := s.exec(ctx, s.db, `ALTER TABLE recordings DROP COLUMN IF EXISTS node_spki`); err != nil {
		t.Fatalf("drop node_spki: %v", err)
	}

	up := open()
	// A real P-256 SubjectPublicKeyInfo is 91 bytes — well past a VARCHAR(64).
	spki := make([]byte, 91)
	for i := range spki {
		spki[i] = byte(i)
	}
	rec := &RecordingRecord{
		SessionID: "s-migrate0001", NodeID: "n1", SHA256: "aa", SizeBytes: 1,
		NodeSig: []byte{9, 8, 7}, NodeSPKI: spki, BlobRef: "local:x", StoredUnix: 1,
	}
	if err := up.PutRecording("ws", rec); err != nil {
		t.Fatalf("put after upgrade: %v", err)
	}
	got, err := up.GetRecording("ws", rec.SessionID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got.NodeSPKI) != string(spki) {
		t.Fatalf("node key stored %d bytes, wrote %d — a truncated key verifies nothing",
			len(got.NodeSPKI), len(spki))
	}
}
