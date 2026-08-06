package osv

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
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
	changed vulnfeed.ChangedPackages
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
	// http.DefaultClient has no timeouts at all. A stalled bucket connection then
	// hangs the sync chore forever; the overall bound is the per-ecosystem context
	// deadline, and these catch the failure modes that never produce bytes.
	var doer httpDoer = &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 2 * time.Minute,
			IdleConnTimeout:       90 * time.Second,
		},
	}
	if client != nil {
		doer = client
	}
	return &BulkFeed{base: base, ecosystems: append([]string(nil), ecosystems...), store: store, http: doer}
}

// Name is the config selector for the bulk OSV source. It shares the dir source's
// public-feed identity so the two are drop-in interchangeable behind config.
func (f *BulkFeed) Name() string { return "osv-public" }

// advisoryBatchSize bounds how many advisory rows are held before a commit. The
// whole point is that peak memory is a function of this constant rather than of
// the feed's size: the seven default ecosystems are ~7 GB uncompressed and ~410k
// records, and accumulating all of them before a single write is what made the
// first sync a coin flip on host RAM.
const advisoryBatchSize = 2000

// ecosystemFetchTimeout bounds one ecosystem's download. The client used to be
// http.DefaultClient with no timeout at all against a context with no deadline, so
// a stalled connection hung the sync chore indefinitely with nothing in the logs.
const ecosystemFetchTimeout = 30 * time.Minute

// Sync fetches each configured ecosystem's all.zip, unzips it, and upserts every
// OSV record modified at or after `since` through PutAdvisories — a delta when
// `since` is non-zero, a full refresh when it is zero. It returns how many advisory
// rows it wrote and records the changed advisories for Changed() so the caller
// re-matches only those.
//
// Commits happen per BATCH, inside the per-ecosystem loop, and the zip is streamed
// from a temp file rather than held in memory. Both matter for the same reason: this
// used to accumulate every record from every ecosystem and write once at the very
// end, so any failure — a 404, a stalled connection, the OOM killer arriving
// somewhere in the several gigabytes — left the store with exactly zero advisories
// and no log line, which presents as "SBOMs collected, no CVEs ever found".
//
// An ecosystem that fails still returns an error (the caller must not advance its
// watermark past data it never read), but the ecosystems that already committed
// keep their rows, so each tick makes forward progress instead of restarting from
// nothing.
func (f *BulkFeed) Sync(ctx context.Context, since time.Time) (int, error) {
	var changed vulnfeed.ChangedPackages
	total := 0
	for _, eco := range f.ecosystems {
		if err := ctx.Err(); err != nil {
			f.changed = changed
			return total, err
		}
		n, err := f.syncEcosystem(ctx, eco, since, &changed)
		total += n
		if err != nil {
			f.changed = changed
			return total, err
		}
		slog.Info("osv bulk: ecosystem synced",
			"component", "vulnfeed", "ecosystem", eco, "rows", n, "rows_total", total)
	}
	f.changed = changed
	return total, nil
}

// syncEcosystem downloads one ecosystem's all.zip to a temp file and streams its
// entries, committing every advisoryBatchSize rows. It returns the rows written.
func (f *BulkFeed) syncEcosystem(ctx context.Context, eco string, since time.Time, changed *vulnfeed.ChangedPackages) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, ecosystemFetchTimeout)
	defer cancel()

	path, err := f.downloadEcosystem(ctx, eco)
	if err != nil {
		return 0, err
	}
	defer os.Remove(path)

	zr, err := zip.OpenReader(path)
	if err != nil {
		return 0, fmt.Errorf("osv bulk: open %s zip: %w", eco, err)
	}
	defer zr.Close()

	written := 0
	batch := make([]vulnfeed.AdvisoryRecord, 0, advisoryBatchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := f.store.PutAdvisories(batch); err != nil {
			return err
		}
		written += len(batch)
		batch = batch[:0]
		return nil
	}

	for _, zf := range zr.File {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		if zf.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(zf.Name), ".json") {
			continue
		}
		doc, err := readZipEntry(zf)
		if err != nil {
			return written, fmt.Errorf("osv bulk: read %s/%s: %w", eco, zf.Name, err)
		}
		rs, _, skipped, perr := advisoryRecordsFromDoc(doc, since)
		if perr != nil {
			return written, fmt.Errorf("osv bulk: parse %s/%s: %w", eco, zf.Name, perr)
		}
		if skipped || len(rs) == 0 {
			continue
		}
		// The changed packages are already on the records about to be written, so
		// there is no second parse and nothing retained past the pairs themselves.
		changed.AddRecords(rs)
		batch = append(batch, rs...)
		if len(batch) >= advisoryBatchSize {
			if err := flush(); err != nil {
				return written, err
			}
		}
	}
	if err := flush(); err != nil {
		return written, err
	}
	return written, nil
}

// downloadEcosystem streams <base>/<ecosystem>/all.zip to a temp file and returns
// its path; the caller removes it. Streaming to disk rather than io.ReadAll keeps a
// ~1 GB compressed archive out of the heap, and zip.OpenReader then decompresses
// entries on demand instead of expanding the whole archive at once.
func (f *BulkFeed) downloadEcosystem(ctx context.Context, ecosystem string) (string, error) {
	url := f.base + "/" + ecosystemPath(ecosystem) + "/all.zip"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("osv bulk: build request %s: %w", url, err)
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("osv bulk: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("osv bulk: fetch %s: status %d", url, resp.StatusCode)
	}
	tmp, err := os.CreateTemp("", "geneza-osv-*.zip")
	if err != nil {
		return "", fmt.Errorf("osv bulk: temp file: %w", err)
	}
	n, err := io.Copy(tmp, resp.Body)
	cerr := tmp.Close()
	if err != nil {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("osv bulk: download %s: %w", url, err)
	}
	if cerr != nil {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("osv bulk: close %s: %w", tmp.Name(), cerr)
	}
	slog.Debug("osv bulk: downloaded", "component", "vulnfeed", "ecosystem", ecosystem, "bytes", n)
	return tmp.Name(), nil
}

// ChangedPackages returns the (ecosystem, package) pairs the most recent Sync
// (re)wrote, so the controller chore re-matches only those. Empty after a sync that
// changed nothing (e.g. a delta with no records past the watermark).
func (f *BulkFeed) ChangedPackages() []vulnfeed.Package {
	return f.changed.List()
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
