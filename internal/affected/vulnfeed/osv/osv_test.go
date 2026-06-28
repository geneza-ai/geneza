package osv

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"geneza.io/internal/affected/vulnfeed"
)

// memStore is an in-memory vulnfeed.AdvisoryStore so the feed test needs no DB.
type memStore struct {
	byID  map[string]vulnfeed.AdvisoryRecord
	byPkg map[string][]string // ecosystem\x00name -> ids
}

func newMemStore() *memStore {
	return &memStore{byID: map[string]vulnfeed.AdvisoryRecord{}, byPkg: map[string][]string{}}
}

func (m *memStore) PutAdvisories(recs []vulnfeed.AdvisoryRecord) error {
	for _, r := range recs {
		if _, ok := m.byID[r.ID]; !ok {
			k := r.Ecosystem + "\x00" + r.PackageName
			m.byPkg[k] = append(m.byPkg[k], r.ID)
		}
		m.byID[r.ID] = r
	}
	return nil
}

func (m *memStore) AdvisoriesForPackage(ecosystem, name string) ([]vulnfeed.AdvisoryRecord, error) {
	var out []vulnfeed.AdvisoryRecord
	for _, id := range m.byPkg[ecosystem+"\x00"+name] {
		out = append(out, m.byID[id])
	}
	return out, nil
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSyncParsesAndServes(t *testing.T) {
	dir := t.TempDir()
	// A record affecting two packages: one row per (ecosystem, name) must result so
	// each resolves from the by-package index.
	write(t, dir, "multi.json", `{
		"id": "OSV-MULTI", "modified": "2024-03-01T00:00:00Z", "aliases": ["CVE-2024-1"],
		"affected": [
			{"package": {"ecosystem": "Debian:12", "name": "openssl"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.1n-0+deb12u1"}]}]},
			{"package": {"ecosystem": "Debian:12", "name": "libssl"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.1n-0+deb12u1"}]}]}
		],
		"license": "MIT"
	}`)
	write(t, dir, "single.json", `{
		"id": "OSV-SINGLE", "modified": "2024-01-01T00:00:00Z", "aliases": ["CVE-2024-2"],
		"affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
			"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]
	}`)
	write(t, dir, "notjson.txt", `ignored`)

	st := newMemStore()
	f := New(dir, st)
	if f.Name() != "osv-public" {
		t.Errorf("Name: %q", f.Name())
	}
	n, err := f.Sync(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	// 2 (multi: openssl+libssl) + 1 (single) = 3 advisory rows.
	if n != 3 {
		t.Fatalf("Sync wrote %d rows, want 3", n)
	}

	ossl, err := f.Advisories("Debian:12", "openssl")
	if err != nil || len(ossl) != 1 {
		t.Fatalf("Advisories openssl: err=%v len=%d", err, len(ossl))
	}
	if ossl[0].ID != "OSV-MULTI" {
		t.Errorf("want parsed OSV id from Doc, got %q", ossl[0].ID)
	}
	if len(ossl[0].Affected) == 0 || ossl[0].Affected[0].Ranges[0].Events[1].Fixed != "1.1.1n-0+deb12u1" {
		t.Errorf("range did not survive the round-trip: %+v", ossl[0].Affected)
	}
	// The verbatim Doc (carrying the per-source license) is retained.
	if len(ossl[0].Raw) == 0 {
		t.Error("raw doc not retained")
	}

	// libssl resolves to the same record's second package.
	if libssl, _ := f.Advisories("Debian:12", "libssl"); len(libssl) != 1 || libssl[0].ID != "OSV-MULTI" {
		t.Errorf("libssl resolve wrong: %+v", libssl)
	}
	if lod, _ := f.Advisories("npm", "lodash"); len(lod) != 1 || lod[0].ID != "OSV-SINGLE" {
		t.Errorf("lodash resolve wrong: %+v", lod)
	}
	// Unknown package is empty, not an error.
	if u, err := f.Advisories("npm", "nope"); err != nil || len(u) != 0 {
		t.Errorf("unknown package: err=%v len=%d", err, len(u))
	}
}

// TestSyncSinceWatermark skips records older than the watermark.
func TestSyncSinceWatermark(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "old.json", `{"id":"OLD","modified":"2024-01-01T00:00:00Z",
		"affected":[{"package":{"ecosystem":"npm","name":"a"}}]}`)
	write(t, dir, "new.json", `{"id":"NEW","modified":"2024-06-01T00:00:00Z",
		"affected":[{"package":{"ecosystem":"npm","name":"b"}}]}`)
	st := newMemStore()
	f := New(dir, st)
	since := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	n, err := f.Sync(context.Background(), since)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if n != 1 {
		t.Fatalf("watermark Sync wrote %d, want 1 (only NEW)", n)
	}
	if a, _ := f.Advisories("npm", "a"); len(a) != 0 {
		t.Errorf("old record synced past watermark: %+v", a)
	}
	if b, _ := f.Advisories("npm", "b"); len(b) != 1 {
		t.Errorf("new record not synced: %+v", b)
	}
}
