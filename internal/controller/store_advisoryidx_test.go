package controller

import (
	"path/filepath"
	"testing"

	"go.etcd.io/bbolt"
)

// A bbolt store that predates the advisory index holds advisories with no index
// entries. Without a backfill, every lookup through the new index path returns
// nothing — silently, and indistinguishable from a clean fleet. That is the same
// class of failure the index was added to fix, so it gets its own test.
func TestAdvisoryIndexBackfillsOnOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	// Open once and write an advisory the normal way.
	s, err := OpenStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.PutAdvisories([]AdvisoryRecord{{
		ID: "OSV-1", Source: "osv", Ecosystem: "Ubuntu:22.04:LTS", PackageName: "openssl",
		Doc: []byte(`{"id":"OSV-1"}`), ModifiedUnix: 1,
	}}); err != nil {
		t.Fatalf("put: %v", err)
	}
	s.Close()

	// Simulate the pre-upgrade shape: advisories present, index empty.
	db, err := bbolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("reopen raw: %v", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		if err := tx.DeleteBucket(bucketAdvisoryIdx); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(bucketAdvisoryIdx)
		return err
	}); err != nil {
		t.Fatalf("clear index: %v", err)
	}
	db.Close()

	// Reopening is the upgrade. The advisory must be findable again — and under the
	// COMPONENT's spelling, not the advisory's.
	up, err := OpenStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer up.Close()
	got, err := up.AdvisoriesForPackage("Ubuntu:22.04", "openssl")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(got) != 1 || got[0].ID != "OSV-1" {
		t.Fatalf("an advisory stored before the index existed must still resolve after the upgrade, got %+v", got)
	}
}

// Re-filing an advisory under a different package must not leave the old index
// entry behind, or a stale key resolves to a record that no longer names it.
func TestAdvisoryIndexDropsStaleEntryOnRewrite(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	put := func(pkg string) {
		t.Helper()
		if err := s.PutAdvisories([]AdvisoryRecord{{
			ID: "OSV-1", Source: "osv", Ecosystem: "Debian:12", PackageName: pkg,
			Doc: []byte(`{"id":"OSV-1"}`), ModifiedUnix: 1,
		}}); err != nil {
			t.Fatalf("put %s: %v", pkg, err)
		}
	}
	put("openssl")
	put("glibc")

	if got, _ := s.AdvisoriesForPackage("Debian:12", "glibc"); len(got) != 1 {
		t.Fatalf("the new package must resolve, got %d", len(got))
	}
	if got, _ := s.AdvisoriesForPackage("Debian:12", "openssl"); len(got) != 0 {
		t.Fatalf("the old package must no longer resolve, got %d", len(got))
	}
}
