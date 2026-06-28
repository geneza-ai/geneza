package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"
)

// zipOf builds an in-memory all.zip whose entries are the given name→JSON docs.
func zipOf(t *testing.T, docs map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range docs {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fixtureServer serves <ecosystem>/all.zip from an in-memory map so the bulk
// feed never touches the live OSV.dev bucket. It records which paths were hit.
func fixtureServer(t *testing.T, byEco map[string][]byte) (*httptest.Server, *[]string) {
	t.Helper()
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		// Path is /<ecosystem>/all.zip; the ecosystem may be %20-encoded.
		for eco, z := range byEco {
			if r.URL.Path == "/"+ecosystemPath(eco)+"/all.zip" {
				w.Header().Set("Content-Type", "application/zip")
				_, _ = w.Write(z)
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestBulkSyncFetchesParsesAndServes(t *testing.T) {
	debianZip := zipOf(t, map[string]string{
		"OSV-MULTI.json": `{
			"id": "OSV-MULTI", "modified": "2024-03-01T00:00:00Z", "aliases": ["CVE-2024-1"],
			"affected": [
				{"package": {"ecosystem": "Debian:12", "name": "openssl"},
					"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.1n-0+deb12u1"}]}]},
				{"package": {"ecosystem": "Debian:12", "name": "libssl"}}
			],
			"license": "MIT"
		}`,
		"notjson.txt": `ignored`,
	})
	npmZip := zipOf(t, map[string]string{
		"OSV-SINGLE.json": `{"id":"OSV-SINGLE","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2024-2"],
			"affected":[{"package":{"ecosystem":"npm","name":"lodash"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`,
	})
	srv, hits := fixtureServer(t, map[string][]byte{"Debian": debianZip, "npm": npmZip})

	st := newMemStore()
	f := NewBulk(srv.URL, []string{"Debian", "npm"}, st, srv.Client())
	if f.Name() != "osv-public" {
		t.Errorf("Name: %q", f.Name())
	}
	n, err := f.Sync(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	// Debian: openssl + libssl = 2 rows; npm: lodash = 1 row.
	if n != 3 {
		t.Fatalf("Sync wrote %d rows, want 3", n)
	}
	// Both ecosystem zips were fetched.
	if len(*hits) != 2 {
		t.Fatalf("fetched %v, want 2 ecosystem zips", *hits)
	}

	ossl, err := f.Advisories("Debian:12", "openssl")
	if err != nil || len(ossl) != 1 {
		t.Fatalf("Advisories openssl: err=%v len=%d", err, len(ossl))
	}
	if ossl[0].ID != "OSV-MULTI" {
		t.Errorf("want OSV-MULTI, got %q", ossl[0].ID)
	}
	if ossl[0].Affected[0].Ranges[0].Events[1].Fixed != "1.1.1n-0+deb12u1" {
		t.Errorf("range lost in round-trip: %+v", ossl[0].Affected)
	}
	// The verbatim Doc (carrying the per-source license) is retained.
	if !bytes.Contains(ossl[0].Raw, []byte(`"license": "MIT"`)) {
		t.Errorf("verbatim doc/license not retained: %s", ossl[0].Raw)
	}
	if libssl, _ := f.Advisories("Debian:12", "libssl"); len(libssl) != 1 || libssl[0].ID != "OSV-MULTI" {
		t.Errorf("libssl resolve wrong: %+v", libssl)
	}
	if lod, _ := f.Advisories("npm", "lodash"); len(lod) != 1 || lod[0].ID != "OSV-SINGLE" {
		t.Errorf("lodash resolve wrong: %+v", lod)
	}

	// Changed() lists exactly the two OSV ids written this sync, in stable order.
	changed := f.Changed()
	ids := make([]string, len(changed))
	for i, v := range changed {
		ids[i] = v.ID
	}
	sort.Strings(ids)
	if len(ids) != 2 || ids[0] != "OSV-MULTI" || ids[1] != "OSV-SINGLE" {
		t.Fatalf("Changed ids = %v, want [OSV-MULTI OSV-SINGLE]", ids)
	}
}

// TestBulkSyncSinceWatermark skips records at/before the watermark and reports
// only the records past it as changed.
func TestBulkSyncSinceWatermark(t *testing.T) {
	z := zipOf(t, map[string]string{
		"old.json": `{"id":"OLD","modified":"2024-01-01T00:00:00Z",
			"affected":[{"package":{"ecosystem":"npm","name":"a"}}]}`,
		"new.json": `{"id":"NEW","modified":"2024-06-01T00:00:00Z",
			"affected":[{"package":{"ecosystem":"npm","name":"b"}}]}`,
	})
	srv, _ := fixtureServer(t, map[string][]byte{"npm": z})
	st := newMemStore()
	f := NewBulk(srv.URL, []string{"npm"}, st, srv.Client())

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
	if c := f.Changed(); len(c) != 1 || c[0].ID != "NEW" {
		t.Fatalf("Changed = %v, want only NEW", c)
	}
}

// TestBulkSyncEcosystemFetchError fails the whole sync (so the caller never
// advances its watermark past unfetched data) when an ecosystem's zip is missing.
func TestBulkSyncEcosystemFetchError(t *testing.T) {
	srv, _ := fixtureServer(t, map[string][]byte{}) // serves 404 for everything
	st := newMemStore()
	f := NewBulk(srv.URL, []string{"Debian"}, st, srv.Client())
	if _, err := f.Sync(context.Background(), time.Time{}); err == nil {
		t.Fatal("expected a fetch error for a missing ecosystem zip")
	}
}

// TestBulkDefaults exercises the empty-arg fallbacks without any network call.
func TestBulkDefaults(t *testing.T) {
	f := NewBulk("", nil, newMemStore(), nil)
	if f.base != DefaultBulkBaseURL {
		t.Errorf("base default = %q", f.base)
	}
	if len(f.ecosystems) != len(DefaultEcosystems) {
		t.Errorf("ecosystems default len = %d, want %d", len(f.ecosystems), len(DefaultEcosystems))
	}
	if f.http == nil {
		t.Error("http client default is nil")
	}
	// "Red Hat" must URL-encode its space in the bucket path.
	if got := ecosystemPath("Red Hat"); got != "Red%20Hat" {
		t.Errorf("ecosystemPath(Red Hat) = %q", got)
	}
}
