package enrich

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"testing"
)

// fixtureDoer serves a canned body per URL with no network. A URL with no fixture
// yields a 404 so a misrouted fetch fails loudly rather than hanging.
type fixtureDoer struct {
	bodies map[string][]byte
	calls  map[string]int
}

func newFixtureDoer() *fixtureDoer {
	return &fixtureDoer{bodies: map[string][]byte{}, calls: map[string]int{}}
}

func (d *fixtureDoer) Do(req *http.Request) (*http.Response, error) {
	url := req.URL.String()
	d.calls[url]++
	body, ok := d.bodies[url]
	if !ok {
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewReader(nil))}, nil
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body))}, nil
}

func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

const kevURL = "https://kev.test/known_exploited_vulnerabilities.json"
const epssURL = "https://epss.test/epss_scores-current.csv.gz"

// kevFixture is a trimmed CISA catalog: two CVEs on the list.
const kevFixture = `{
	"title": "CISA Catalog of Known Exploited Vulnerabilities",
	"count": 2,
	"vulnerabilities": [
		{"cveID": "CVE-2021-44228", "vendorProject": "Apache"},
		{"cveID": "CVE-2022-0778", "vendorProject": "OpenSSL"}
	]
}`

// epssFixture is the FIRST CSV shape: a comment line, a header, then rows.
const epssFixture = "#model_version:v2023.03.01,score_date:2024-01-01T00:00:00Z\n" +
	"cve,epss,percentile\n" +
	"CVE-2021-44228,0.97500,0.99900\n" +
	"CVE-2022-0778,0.12300,0.50000\n" +
	"CVE-2020-0001,0.00100,0.01000\n"

func TestRefreshKEVAndEPSS(t *testing.T) {
	d := newFixtureDoer()
	d.bodies[kevURL] = []byte(kevFixture)
	d.bodies[epssURL] = gzipBytes(t, epssFixture)

	e := New(Options{KEVURL: kevURL, EPSSURL: epssURL, HTTP: d})
	if !e.Enabled() {
		t.Fatal("want Enabled with both URLs set")
	}
	if err := e.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// KEV membership: listed CVEs are true, an unlisted one false.
	if kev, _ := e.Lookup("CVE-2021-44228"); !kev {
		t.Error("CVE-2021-44228 should be KEV")
	}
	if kev, _ := e.Lookup("CVE-2020-0001"); kev {
		t.Error("CVE-2020-0001 (EPSS-only) should not be KEV")
	}
	if kev, _ := e.Lookup("CVE-9999-9999"); kev {
		t.Error("unknown CVE should not be KEV")
	}

	// EPSS scores: parsed from the gzip CSV past the comment + header.
	if _, epss := e.Lookup("CVE-2021-44228"); epss != 0.975 {
		t.Errorf("CVE-2021-44228 epss: want 0.975, got %v", epss)
	}
	if _, epss := e.Lookup("CVE-2022-0778"); epss != 0.123 {
		t.Errorf("CVE-2022-0778 epss: want 0.123, got %v", epss)
	}
	if _, epss := e.Lookup("CVE-9999-9999"); epss != 0 {
		t.Errorf("unknown CVE epss: want 0, got %v", epss)
	}
}

// TestRefreshPlainCSV proves the EPSS parser tolerates a non-gzipped CSV body (the
// API/plain transport), not just the .csv.gz export.
func TestRefreshPlainCSV(t *testing.T) {
	d := newFixtureDoer()
	d.bodies[epssURL] = []byte(epssFixture)
	e := New(Options{EPSSURL: epssURL, HTTP: d})
	if err := e.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if _, epss := e.Lookup("CVE-2022-0778"); epss != 0.123 {
		t.Errorf("plain-csv epss: want 0.123, got %v", epss)
	}
	if kev, _ := e.Lookup("CVE-2022-0778"); kev {
		t.Error("KEV must be empty when only EPSS configured")
	}
}

// TestDisabledWhenNoURLs proves an Enricher with no feeds is disabled and yields no
// signal — the config gate.
func TestDisabledWhenNoURLs(t *testing.T) {
	e := New(Options{})
	if e.Enabled() {
		t.Fatal("want disabled with no URLs")
	}
	if err := e.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh on disabled: %v", err)
	}
	if kev, epss := e.Lookup("CVE-2022-0778"); kev || epss != 0 {
		t.Errorf("disabled enricher must yield no signal, got kev=%v epss=%v", kev, epss)
	}
}

// TestRefreshIdempotent proves a second refresh over the same fixtures yields the
// same answers (the snapshot is replaced wholesale, not accumulated).
func TestRefreshIdempotent(t *testing.T) {
	d := newFixtureDoer()
	d.bodies[kevURL] = []byte(kevFixture)
	d.bodies[epssURL] = gzipBytes(t, epssFixture)
	e := New(Options{KEVURL: kevURL, EPSSURL: epssURL, HTTP: d})

	for i := 0; i < 3; i++ {
		if err := e.Refresh(context.Background()); err != nil {
			t.Fatalf("Refresh #%d: %v", i, err)
		}
	}
	if kev, epss := e.Lookup("CVE-2021-44228"); !kev || epss != 0.975 {
		t.Errorf("after repeated refresh: kev=%v epss=%v", kev, epss)
	}
}

// TestRefreshErrorKeepsSnapshot proves a feed fetch error fails the refresh and
// leaves the previous snapshot intact rather than blanking it.
func TestRefreshErrorKeepsSnapshot(t *testing.T) {
	d := newFixtureDoer()
	d.bodies[kevURL] = []byte(kevFixture)
	d.bodies[epssURL] = gzipBytes(t, epssFixture)
	e := New(Options{KEVURL: kevURL, EPSSURL: epssURL, HTTP: d})
	if err := e.Refresh(context.Background()); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}

	// Drop the KEV fixture so the next refresh 404s on it.
	delete(d.bodies, kevURL)
	if err := e.Refresh(context.Background()); err == nil {
		t.Fatal("want error when KEV feed 404s")
	}
	// Prior snapshot survives the failed refresh.
	if kev, epss := e.Lookup("CVE-2021-44228"); !kev || epss != 0.975 {
		t.Errorf("failed refresh blanked the snapshot: kev=%v epss=%v", kev, epss)
	}
}
