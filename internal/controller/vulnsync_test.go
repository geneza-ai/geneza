package controller

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"geneza.io/internal/affected/vulnfeed/enrich"
	"geneza.io/internal/affected/vulnfeed/osv"
)

// bulkAllZip builds an OSV bulk all.zip of name→JSON docs for a fixture server.
func bulkAllZip(t *testing.T, docs map[string]string) []byte {
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

// vulnSyncSuite seeds inventory, points the controller's vuln-sync chore at a FIXTURE
// OSV bulk server (never the live OSV.dev bucket), runs one tick, and asserts the
// chore synced the advisories AND re-matched only the affected nodes — leaving
// unrelated nodes' verdicts untouched. It runs against any Store so bbolt and both
// SQL engines share the assertions.
func vulnSyncSuite(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	const wsA = "wsA"

	if err := s.PutWorkspace(&WorkspaceRecord{ID: wsA, Name: "A"}); err != nil {
		t.Fatalf("PutWorkspace: %v", err)
	}
	// n1 carries a vulnerable npm dep; n2 carries an unrelated package the advisory
	// must never touch.
	if err := s.UpsertNodeComponents(wsA, "n1", []ComponentRecord{
		{Purl: "pkg:npm/ansi-regex@5.0.0", Source: "lang", Ecosystem: "npm", Name: "ansi-regex", Version: "5.0.0"},
	}); err != nil {
		t.Fatalf("seed n1: %v", err)
	}
	if err := s.UpsertNodeComponents(wsA, "n2", []ComponentRecord{
		{Purl: "pkg:npm/left-pad@1.0.0", Source: "lang", Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"},
	}); err != nil {
		t.Fatalf("seed n2: %v", err)
	}

	// A fixture bulk server serving one npm all.zip with an advisory for ansi-regex.
	npmZip := bulkAllZip(t, map[string]string{
		"GHSA-1.json": `{
			"id": "GHSA-1", "modified": "2024-06-01T00:00:00Z", "aliases": ["CVE-2021-3807"],
			"affected": [{"package": {"ecosystem": "npm", "name": "ansi-regex"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.0.1"}]}]}],
			"license": "MIT"
		}`,
	})
	// The same fixture server also serves a CISA KEV catalog (listing the synced
	// CVE) and a FIRST EPSS CSV, so the chore's enrichment pass runs over fixtures
	// and never the live endpoints.
	const kevBody = `{"vulnerabilities":[{"cveID":"CVE-2021-3807"}]}`
	const epssBody = "#model_version:test\ncve,epss,percentile\nCVE-2021-3807,0.6,0.9\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/npm/all.zip":
			_, _ = w.Write(npmZip)
		case "/kev.json":
			_, _ = w.Write([]byte(kevBody))
		case "/epss.csv":
			_, _ = w.Write([]byte(epssBody))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Build the server the same way New() does for the feed, but bypass full
	// construction: the chore only touches store/feed/vex/enricher/cfg.
	feed := osv.NewBulk(srv.URL, []string{"npm"}, FeedStore(s), srv.Client())
	enricher := enrich.New(enrich.Options{KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv", HTTP: srv.Client()})
	sv := &Server{store: s, inventoryFeed: feed, inventoryEnricher: enricher}
	sv.cfg = &Config{VulnFeed: VulnFeedConfig{
		Source: "osv_bulk", BulkURL: srv.URL, Ecosystems: []string{"npm"},
		SyncInterval: Duration(6 * time.Hour),
		KEVURL:       srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv",
	}}

	// One debounced tick: it grabs the lock, syncs the feed, and re-matches only the
	// changed advisory's nodes.
	sv.vulnSyncTick(ctx)

	// n1 carries the affected verdict for the synced CVE.
	rows, err := s.NodesAffectedByCVE(wsA, "CVE-2021-3807")
	if err != nil {
		t.Fatalf("NodesAffectedByCVE: %v", err)
	}
	if len(rows) != 1 || rows[0].NodeID != "n1" || rows[0].Status != "affected" {
		t.Fatalf("after sync chore: want one affected row for n1, got %v", rows)
	}
	// The enrichment pass overlaid KEV/EPSS onto the synced verdict from the fixture
	// feeds — both the match-time write and the post-sync overlay land on the row.
	if !rows[0].KEV || rows[0].EPSS != 0.6 {
		t.Fatalf("sync chore did not enrich the verdict: kev=%v epss=%v", rows[0].KEV, rows[0].EPSS)
	}
	// n2 (unrelated package) was never touched.
	if n2cves, _ := s.CVEsForNode(wsA, "n2"); len(n2cves) != 0 {
		t.Fatalf("sync chore touched unrelated n2: %v", n2cves)
	}
	// The advisory's source doc was persisted (the per-source license travels with
	// it). Each backend re-encodes the JSON differently (bbolt compacts; Postgres
	// jsonb reformats + reorders; MariaDB keeps the raw bytes), so the license is
	// asserted by PARSING the stored doc, not by byte-comparison.
	advs, _ := s.AdvisoriesForPackage("npm", "ansi-regex")
	if len(advs) != 1 {
		t.Fatalf("want one stored advisory for ansi-regex, got %d", len(advs))
	}
	var doc struct {
		License string `json:"license"`
	}
	if err := json.Unmarshal(advs[0].Doc, &doc); err != nil {
		t.Fatalf("stored doc not valid JSON: %v", err)
	}
	if doc.License != "MIT" {
		t.Fatalf("per-source license did not travel with the stored doc: %q", doc.License)
	}

	// The watermark advanced, so a second tick with no new data writes no new rows.
	wm := sv.vulnSyncWatermark()
	if wm.IsZero() {
		t.Fatal("watermark not advanced after a successful sync")
	}
	sv.vulnSyncTick(ctx)
	if rows2, _ := s.NodesAffectedByCVE(wsA, "CVE-2021-3807"); len(rows2) != 1 {
		t.Fatalf("second tick changed the verdict set: %v", rows2)
	}
}

func TestVulnSyncChoreBbolt(t *testing.T) {
	vulnSyncSuite(t, testStore(t))
}

func TestVulnSyncChoreSQL(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		vulnSyncSuite(t, s)
	})
}

// TestVulnSyncLockDebounce mirrors TestSQLTryReconcileLock for the feed-sync lock:
// only one store handle holds it at a time, and it is transient (released for the
// next contender). bbolt always grants it (single writer), so this is SQL-only.
func TestVulnSyncLockDebounce(t *testing.T) {
	for _, eng := range configuredSQLEngines(t) {
		eng := eng
		t.Run(eng.backend, func(t *testing.T) {
			aRaw, err := OpenSQLStore(context.Background(), eng.backend, eng.dsn)
			if err != nil {
				t.Fatal(err)
			}
			a := aRaw.(*sqlStore)
			defer a.Close()
			bRaw, err := OpenSQLStore(context.Background(), eng.backend, eng.dsn)
			if err != nil {
				t.Fatal(err)
			}
			b := bRaw.(*sqlStore)
			defer b.Close()

			heldA, releaseA, err := a.TryVulnSyncLock(context.Background())
			if err != nil || !heldA {
				t.Fatalf("first handle should win the sync lock: held=%v err=%v", heldA, err)
			}
			heldB, _, err := b.TryVulnSyncLock(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if heldB {
				t.Fatal("second handle must NOT hold the sync lock while the first does")
			}
			releaseA()
			var got bool
			for i := 0; i < 20; i++ {
				h, rel, lerr := b.TryVulnSyncLock(context.Background())
				if lerr != nil {
					t.Fatal(lerr)
				}
				if h {
					rel()
					got = true
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if !got {
				t.Fatal("second handle should grab the sync lock after the first releases it")
			}
		})
	}
}

// TestVulnSyncLockSeparateFromReconcile proves the two debounce locks do not
// contend: a held reconcile lock must not block a sync lock, or a fleet-map
// rebuild and a feed sync would serialize against each other.
func TestVulnSyncLockSeparateFromReconcile(t *testing.T) {
	for _, eng := range configuredSQLEngines(t) {
		eng := eng
		t.Run(eng.backend, func(t *testing.T) {
			raw, err := OpenSQLStore(context.Background(), eng.backend, eng.dsn)
			if err != nil {
				t.Fatal(err)
			}
			st := raw.(*sqlStore)
			defer st.Close()

			heldR, releaseR, err := st.TryReconcileLock(context.Background())
			if err != nil || !heldR {
				t.Fatalf("reconcile lock: held=%v err=%v", heldR, err)
			}
			defer releaseR()
			// A different connection must still get the sync lock (distinct key).
			otherRaw, err := OpenSQLStore(context.Background(), eng.backend, eng.dsn)
			if err != nil {
				t.Fatal(err)
			}
			other := otherRaw.(*sqlStore)
			defer other.Close()
			heldS, releaseS, err := other.TryVulnSyncLock(context.Background())
			if err != nil || !heldS {
				t.Fatalf("sync lock must be grantable while the reconcile lock is held: held=%v err=%v", heldS, err)
			}
			releaseS()
		})
	}
}
