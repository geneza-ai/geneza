// Package osv is a vulnfeed.Feed backed by OSV advisory records. It offers two
// sources of the same record shape: a local directory of OSV JSON files (for
// offline/airgapped use, and so the matcher's full path can run without a
// network fetch) and the OSV.dev bulk database fetched over HTTP from the OSV
// GCS bucket. Both parse identically and write through the same PutAdvisories
// path, so the only difference between them is where the bytes come from.
//
// Each OSV record is parsed into the seam's vulnfeed.Vulnerability and stored as
// a controller AdvisoryRecord whose Doc is the verbatim OSV JSON, so each advisory's
// own upstream license travels with it rather than the feed asserting one license.
package osv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"geneza.io/internal/affected/vulnfeed"
)

// Feed reads OSV JSON records from a directory and serves them from the store.
type Feed struct {
	dir   string
	store vulnfeed.AdvisoryStore
	// changed holds the advisories the most recent Sync (re)wrote, so the controller
	// chore re-matches only those — one entry per OSV id.
	changed []vulnfeed.Vulnerability
}

// New builds an OSV feed that loads records from dir into store on Sync. store is
// the seam's narrow advisory surface, which the controller store satisfies through an
// adapter, so this package never imports the store.
func New(dir string, store vulnfeed.AdvisoryStore) *Feed {
	return &Feed{dir: dir, store: store}
}

var _ vulnfeed.Feed = (*Feed)(nil)

// Name is the config selector for the public OSV feed.
func (f *Feed) Name() string { return "osv-public" }

// Sync loads every OSV JSON file in the directory whose record was modified at or
// after `since` into the store via PutAdvisories, returning how many it wrote. A
// zero `since` is a full refresh. One AdvisoryRecord is emitted per (record,
// affected-package) pair so the by-package index resolves to it; the Doc on each
// is the verbatim file bytes.
func (f *Feed) Sync(ctx context.Context, since time.Time) (int, error) {
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		return 0, fmt.Errorf("osv feed: read dir %s: %w", f.dir, err)
	}
	var recs []vulnfeed.AdvisoryRecord
	changedByID := map[string]vulnfeed.Vulnerability{}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(strings.ToLower(ent.Name()), ".json") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		path := filepath.Join(f.dir, ent.Name())
		doc, err := os.ReadFile(path)
		if err != nil {
			return 0, fmt.Errorf("osv feed: read %s: %w", path, err)
		}
		rs, _, skipped, perr := advisoryRecordsFromDoc(doc, since)
		if perr != nil {
			return 0, fmt.Errorf("osv feed: parse %s: %w", path, perr)
		}
		recs = append(recs, rs...)
		if !skipped && len(rs) > 0 {
			v, perr := parseVulnerability(doc)
			if perr != nil {
				return 0, fmt.Errorf("osv feed: parse %s: %w", path, perr)
			}
			changedByID[v.ID] = v
		}
	}
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
// the controller chore re-matches only their packages' nodes. Empty after a sync that
// changed nothing (e.g. a delta with no files past the watermark).
func (f *Feed) Changed() []vulnfeed.Vulnerability { return f.changed }

// changedFromMap flattens a by-id changed set into a stable-ordered slice, so the
// caller's re-match and tests see a deterministic sequence.
func changedFromMap(byID map[string]vulnfeed.Vulnerability) []vulnfeed.Vulnerability {
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]vulnfeed.Vulnerability, 0, len(byID))
	for _, id := range ids {
		out = append(out, byID[id])
	}
	return out
}

// Advisories serves the vulnerabilities filed against a package from the store's
// by-package index. Each row's Doc is the verbatim OSV JSON, parsed back into the
// seam's Vulnerability shape the matcher consumes; an unknown package is empty.
func (f *Feed) Advisories(ecosystem, name string) ([]vulnfeed.Vulnerability, error) {
	return advisoriesFromStore(f.store, ecosystem, name)
}

// advisoriesFromStore is the shared by-package read both OSV sources serve from:
// resolve the package's advisory rows and parse each verbatim Doc back into the
// matcher's Vulnerability shape, in a stable order.
func advisoriesFromStore(store vulnfeed.AdvisoryStore, ecosystem, name string) ([]vulnfeed.Vulnerability, error) {
	rows, err := store.AdvisoriesForPackage(ecosystem, name)
	if err != nil {
		return nil, err
	}
	out := make([]vulnfeed.Vulnerability, 0, len(rows))
	for _, r := range rows {
		v, err := parseVulnerability(r.Doc)
		if err != nil {
			return nil, fmt.Errorf("osv feed: parse stored advisory %s: %w", r.ID, err)
		}
		out = append(out, v)
	}
	// Stable order so callers and tests see a deterministic sequence.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Enrich returns no signal: the dir source carries advisory data only, and a feed
// is allowed to answer best-effort with a zero Enrichment.
func (f *Feed) Enrich(ctx context.Context, cve string) (vulnfeed.Enrichment, error) {
	return vulnfeed.Enrichment{}, nil
}
