package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"geneza.io/internal/affected/vulnfeed"
)

// DefaultBulkBaseURL is the OSV.dev bulk-database GCS bucket. Each ecosystem
// publishes an `all.zip` of every OSV JSON record at
// <base>/<ecosystem>/all.zip.
const DefaultBulkBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

// DefaultEcosystems are the OSV ecosystems Geneza matches against: the distro
// package feeds (which carry the distro's OWN backported fixed versions, the
// thing the matcher compares an installed package against) plus the common
// language ecosystems a node's container/app deps land in. The bulk all.zip
// names use these exact strings.
var DefaultEcosystems = []string{
	"Debian", "Ubuntu", "Alpine", "Red Hat",
	"npm", "PyPI", "Go",
}

// httpDoer is the injectable HTTP surface the bulk source fetches through, so a
// test serves the all.zip from a fixture server and the live OSV.dev bucket is
// never a test dependency. *http.Client satisfies it.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// BulkFeed is a vulnfeed.Feed that fetches the OSV.dev bulk database — the
// per-ecosystem all.zip — over HTTP, unzips it, parses each OSV JSON, and
// upserts every record through the same PutAdvisories path the dir source uses.
// It serves by-package reads from the same store, so the matcher cannot tell the
// two sources apart. The HTTP client is injectable so tests use a fixture server.
type BulkFeed struct {
	base       string
	ecosystems []string
	store      vulnfeed.AdvisoryStore
	http       httpDoer

	// changed accumulates the advisories whose records were (re)written by the most
	// recent Sync, so the controller chore re-matches only those — no fleet re-scan.
	// One entry per OSV id, carrying the parsed Vulnerability the matcher consumes.
	changed []vulnfeed.Vulnerability
}

var _ vulnfeed.Feed = (*BulkFeed)(nil)

// NewBulk builds a bulk OSV feed. An empty base falls back to the live OSV.dev
// bucket; an empty ecosystems list falls back to DefaultEcosystems; a nil client
// falls back to http.DefaultClient. store is the seam's narrow advisory surface.
func NewBulk(base string, ecosystems []string, store vulnfeed.AdvisoryStore, client httpDoer) *BulkFeed {
	if base == "" {
		base = DefaultBulkBaseURL
	}
	base = strings.TrimRight(base, "/")
	if len(ecosystems) == 0 {
		ecosystems = DefaultEcosystems
	}
	var doer httpDoer = http.DefaultClient
	if client != nil {
		doer = client
	}
	return &BulkFeed{base: base, ecosystems: append([]string(nil), ecosystems...), store: store, http: doer}
}

// Name is the config selector for the bulk OSV source. It shares the dir source's
// public-feed identity so the two are drop-in interchangeable behind config.
func (f *BulkFeed) Name() string { return "osv-public" }

// Sync fetches each configured ecosystem's all.zip, unzips it, and upserts every
// OSV record modified at or after `since` through PutAdvisories — a delta when
// `since` is non-zero, a full refresh when it is zero. It returns how many
// advisory rows it wrote (one per record × affected-package pair) and records the
// changed advisories for Changed() so the caller re-matches only those. A single
// ecosystem failing (e.g. a 404 for an ecosystem the bucket does not publish)
// fails the whole sync so the watermark is not advanced past unfetched data.
func (f *BulkFeed) Sync(ctx context.Context, since time.Time) (int, error) {
	var recs []vulnfeed.AdvisoryRecord
	changedByID := map[string]vulnfeed.Vulnerability{}
	for _, eco := range f.ecosystems {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		zipBytes, err := f.fetchEcosystem(ctx, eco)
		if err != nil {
			return 0, err
		}
		ecoRecs, err := f.parseZip(eco, zipBytes, since, changedByID)
		if err != nil {
			return 0, err
		}
		recs = append(recs, ecoRecs...)
	}
	// Publish the changed set in a stable order so the caller's re-match and tests
	// see a deterministic sequence.
	f.changed = changedFromMap(changedByID)
	if len(recs) == 0 {
		return 0, nil
	}
	if err := f.store.PutAdvisories(recs); err != nil {
		return 0, err
	}
	return len(recs), nil
}

// Changed returns the advisories whose records the most recent Sync (re)wrote, so
// the controller chore re-matches only their packages' nodes. Empty after a sync
// that changed nothing (e.g. a delta with no records past the watermark).
func (f *BulkFeed) Changed() []vulnfeed.Vulnerability {
	return f.changed
}

// fetchEcosystem GETs <base>/<ecosystem>/all.zip and returns the raw zip bytes. A
// non-200 is an error so a delta does not silently skip an ecosystem and advance
// the watermark past data it never read.
func (f *BulkFeed) fetchEcosystem(ctx context.Context, ecosystem string) ([]byte, error) {
	url := f.base + "/" + ecosystemPath(ecosystem) + "/all.zip"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("osv bulk: build request %s: %w", url, err)
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv bulk: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv bulk: fetch %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("osv bulk: read %s: %w", url, err)
	}
	return body, nil
}

// parseZip unzips one ecosystem's all.zip and parses each OSV JSON entry into
// advisory rows, skipping records at or before the watermark. Records whose
// rows it emits (and records past the watermark with no affected package) are
// added to changedByID so the caller re-matches only what moved.
func (f *BulkFeed) parseZip(ecosystem string, zipBytes []byte, since time.Time, changedByID map[string]vulnfeed.Vulnerability) ([]vulnfeed.AdvisoryRecord, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("osv bulk: open %s zip: %w", ecosystem, err)
	}
	var recs []vulnfeed.AdvisoryRecord
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(zf.Name), ".json") {
			continue
		}
		doc, err := readZipEntry(zf)
		if err != nil {
			return nil, fmt.Errorf("osv bulk: read %s/%s: %w", ecosystem, zf.Name, err)
		}
		rs, _, skipped, perr := advisoryRecordsFromDoc(doc, since)
		if perr != nil {
			return nil, fmt.Errorf("osv bulk: parse %s/%s: %w", ecosystem, zf.Name, perr)
		}
		if skipped || len(rs) == 0 {
			continue
		}
		recs = append(recs, rs...)
		v, perr := parseVulnerability(doc)
		if perr != nil {
			return nil, fmt.Errorf("osv bulk: parse %s/%s: %w", ecosystem, zf.Name, perr)
		}
		changedByID[v.ID] = v
	}
	return recs, nil
}

// readZipEntry reads one zip entry fully into memory (OSV records are small JSON).
func readZipEntry(zf *zip.File) ([]byte, error) {
	rc, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// ecosystemPath URL-encodes an ecosystem name for the bucket path. OSV bucket
// paths keep the human ecosystem name verbatim (including the space in
// "Red Hat"), so only the space needs encoding.
func ecosystemPath(ecosystem string) string {
	return strings.ReplaceAll(ecosystem, " ", "%20")
}

// Advisories serves by-package reads from the store, identically to the dir
// source — the matcher cannot tell the sources apart.
func (f *BulkFeed) Advisories(ecosystem, name string) ([]vulnfeed.Vulnerability, error) {
	return advisoriesFromStore(f.store, ecosystem, name)
}

// Enrich returns no signal: the bulk source carries advisory data, not KEV/EPSS.
func (f *BulkFeed) Enrich(ctx context.Context, cve string) (vulnfeed.Enrichment, error) {
	return vulnfeed.Enrichment{}, nil
}
