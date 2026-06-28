package paid

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"geneza.io/internal/affected/vulnfeed"
	"geneza.io/internal/types"
)

// FeedName is the config selector for the curated paid feed.
const FeedName = "geneza-vulnfeed"

// httpDoer is the injectable HTTP surface the client fetches the bundle through,
// so a test serves a signed fixture bundle and the live endpoint is never a test
// dependency. *http.Client satisfies it.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// VersionStore persists the ingested-bundle version watermark across restarts, so
// the rollback guard survives a process restart (an in-memory watermark would let
// a captured older bundle through after a bounce). The controller backs it with the
// shared settings table; a feed used standalone can pass an in-memory one. A
// missing watermark reads as 0, which accepts any version-1-or-greater bundle.
type VersionStore interface {
	GetBundleVersion() (int64, error)
	SetBundleVersion(v int64) error
}

// Options configure the paid feed.
type Options struct {
	// Endpoint is the bundle URL the client GETs. Required.
	Endpoint string
	// LicenseKey authenticates the client to the feed; it is sent as a bearer token.
	LicenseKey string
	// VendorPubKey is the PINNED ed25519 public key the bundle signature is verified
	// against. A bundle not signed by this exact key is rejected, so a MITM cannot
	// substitute its own signing key. Required and must be ed25519.PublicKeySize.
	VendorPubKey ed25519.PublicKey
	// Store is the advisory persistence surface (the same one the open feed writes).
	Store vulnfeed.AdvisoryStore
	// Versions persists the bundle-version watermark; nil falls back to an in-memory
	// watermark (rollback protection within the process lifetime only).
	Versions VersionStore
	// HTTP is the injectable client; nil falls back to http.DefaultClient.
	HTTP httpDoer
}

// Feed is the client for the curated paid vuln feed. It fetches a signed bundle,
// verifies it against the pinned vendor key and the monotonic version watermark,
// and upserts its advisories through the same store path the open feed uses.
type Feed struct {
	endpoint   string
	licenseKey string
	pub        ed25519.PublicKey
	store      vulnfeed.AdvisoryStore
	versions   VersionStore
	http       httpDoer

	mu sync.Mutex
	// enrichment is the curated per-CVE prioritization signal from the most recently
	// ingested bundle, the source Enrich answers from. Replaced wholesale on each
	// successful Sync, like the open enricher's snapshot.
	enrichment map[string]vulnfeed.Enrichment
	// changed holds the advisories the most recent Sync (re)wrote, so the controller
	// chore re-matches only those — one entry per advisory id.
	changed []vulnfeed.Vulnerability
}

var _ vulnfeed.Feed = (*Feed)(nil)

// New builds a paid feed from options. It validates the pinned key shape up front
// so a misconfigured key fails loudly rather than at the first verify. The HTTP
// client and version store fall back to safe defaults.
func New(opts Options) (*Feed, error) {
	if opts.Endpoint == "" {
		return nil, fmt.Errorf("paid feed: endpoint is required")
	}
	if len(opts.VendorPubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("paid feed: pinned vendor public key must be %d bytes, got %d", ed25519.PublicKeySize, len(opts.VendorPubKey))
	}
	if opts.Store == nil {
		return nil, fmt.Errorf("paid feed: advisory store is required")
	}
	var doer httpDoer = http.DefaultClient
	if opts.HTTP != nil {
		doer = opts.HTTP
	}
	var vs VersionStore = opts.Versions
	if vs == nil {
		vs = &memVersionStore{}
	}
	return &Feed{
		endpoint:   opts.Endpoint,
		licenseKey: opts.LicenseKey,
		pub:        append(ed25519.PublicKey(nil), opts.VendorPubKey...),
		store:      opts.Store,
		versions:   vs,
		http:       doer,
		enrichment: map[string]vulnfeed.Enrichment{},
	}, nil
}

// Name is the config selector for the paid feed.
func (f *Feed) Name() string { return FeedName }

// Sync fetches the curated bundle, verifies its signature against the pinned vendor
// key and its version against the persisted watermark, and on success upserts every
// advisory through PutAdvisories and advances the watermark. `since` is unused: the
// bundle's monotonic version, not a time cursor, is this feed's freshness gate, so a
// bundle is ingested whole when its version is past the watermark and skipped (zero
// rows, no error) when it is not. A bad/forged signature, a non-pinned signer, or a
// version at or below the watermark fails the sync without writing anything.
func (f *Feed) Sync(ctx context.Context, since time.Time) (int, error) {
	raw, err := f.fetch(ctx)
	if err != nil {
		return 0, err
	}
	env, err := types.DecodeSigned(raw)
	if err != nil {
		return 0, fmt.Errorf("paid feed: decode bundle envelope: %w", err)
	}
	var bundle Bundle
	// VerifyOne checks the signature against the pinned key (failing closed on a
	// malformed key or signature) and only then unmarshals the verified payload, so
	// nothing from an unverified bundle is ever parsed into the ingest path.
	if err := types.VerifyOne(f.pub, "", signContext, env, &bundle); err != nil {
		return 0, fmt.Errorf("paid feed: verify bundle: %w", err)
	}

	last, err := f.versions.GetBundleVersion()
	if err != nil {
		return 0, fmt.Errorf("paid feed: read version watermark: %w", err)
	}
	if bundle.Version <= last {
		// Rollback/replay guard: a bundle at or below the watermark is refused. This
		// also surfaces suppression-by-omission — a MITM cannot serve an older bundle
		// (with an advisory dropped) without tripping this, and cannot forge a higher
		// version without the pinned key. Not an error: a re-served current bundle is
		// a benign no-op the chore tolerates.
		f.setChanged(nil)
		return 0, nil
	}

	recs, changed, enrichment, err := f.ingest(bundle)
	if err != nil {
		return 0, err
	}
	if len(recs) > 0 {
		if err := f.store.PutAdvisories(recs); err != nil {
			return 0, err
		}
	}
	// Advance the watermark only after the advisories are committed, so a write
	// failure leaves the watermark unmoved and the next sync re-attempts the bundle.
	if err := f.versions.SetBundleVersion(bundle.Version); err != nil {
		return 0, fmt.Errorf("paid feed: persist version watermark: %w", err)
	}
	f.swapEnrichment(enrichment)
	f.setChanged(changed)
	return len(recs), nil
}

// ingest turns a verified bundle into the advisory rows to upsert, the changed-set
// the caller re-matches, and the per-CVE enrichment Enrich serves. One row is
// emitted per (advisory, affected-package) pair so the by-package index resolves to
// it, mirroring the open feed; the Doc is the curated record (or the canonical Vuln
// JSON when the bundle omits an explicit Doc).
func (f *Feed) ingest(b Bundle) ([]vulnfeed.AdvisoryRecord, []vulnfeed.Vulnerability, map[string]vulnfeed.Enrichment, error) {
	var recs []vulnfeed.AdvisoryRecord
	changedByID := map[string]vulnfeed.Vulnerability{}
	enrichment := map[string]vulnfeed.Enrichment{}
	for _, ca := range b.Advisories {
		v := ca.Vuln
		if v.ID == "" {
			continue
		}
		doc := ca.Doc
		if len(doc) == 0 {
			canon, err := json.Marshal(v)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("paid feed: marshal advisory %s: %w", v.ID, err)
			}
			doc = canon
		}
		// Carry the verbatim curated doc on the parsed vuln too, so a re-match consumer
		// keeps the full record the open feed's parse would have retained.
		v.Raw = append([]byte(nil), doc...)
		seen := map[string]bool{}
		for _, a := range v.Affected {
			eco, name := a.Package.Ecosystem, a.Package.Name
			if eco == "" || name == "" {
				continue
			}
			key := eco + "\x00" + name
			if seen[key] {
				continue
			}
			seen[key] = true
			recs = append(recs, vulnfeed.AdvisoryRecord{
				ID:           advisoryID(v.ID, eco, name),
				Source:       FeedName,
				Ecosystem:    eco,
				PackageName:  name,
				Doc:          doc,
				ModifiedUnix: v.Modified.Unix(),
			})
		}
		changedByID[v.ID] = v
		if e := ca.Enrichment; e != (vulnfeed.Enrichment{}) {
			// Index enrichment by the advisory id and every alias, so an Enrich keyed by
			// the CVE alias (the matcher's identifier) resolves even when the advisory's
			// own id differs from the CVE.
			enrichment[v.ID] = e
			for _, al := range v.Aliases {
				if al != "" {
					enrichment[al] = e
				}
			}
		}
	}
	return recs, changedFromMap(changedByID), enrichment, nil
}

// advisoryID keys an advisory row by its id plus the package it was filed against,
// so a record affecting multiple packages stores one resolvable row each instead of
// colliding on the bare id — the same scheme the open feed uses.
func advisoryID(id, ecosystem, name string) string {
	return id + "/" + ecosystem + "/" + name
}

// changedFromMap flattens a by-id changed set into a stable-ordered slice so the
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

// fetch GETs the bundle endpoint with the license key as a bearer token and returns
// the raw envelope bytes. A non-200 is an error so the client never folds an error
// page (or an auth rejection) into the verify path.
func (f *Feed) fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("paid feed: build request %s: %w", f.endpoint, err)
	}
	if f.licenseKey != "" {
		req.Header.Set("Authorization", "Bearer "+f.licenseKey)
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("paid feed: fetch %s: %w", f.endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("paid feed: fetch %s: status %d", f.endpoint, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("paid feed: read %s: %w", f.endpoint, err)
	}
	return body, nil
}

// Advisories serves by-package reads from the store, identically to the open feed —
// the matcher cannot tell the curated source apart from the public one.
func (f *Feed) Advisories(ecosystem, name string) ([]vulnfeed.Vulnerability, error) {
	rows, err := f.store.AdvisoriesForPackage(ecosystem, name)
	if err != nil {
		return nil, err
	}
	out := make([]vulnfeed.Vulnerability, 0, len(rows))
	for _, r := range rows {
		var v vulnfeed.Vulnerability
		if len(r.Doc) > 0 {
			if err := json.Unmarshal(r.Doc, &v); err != nil {
				return nil, fmt.Errorf("paid feed: parse stored advisory %s: %w", r.ID, err)
			}
			v.Raw = append([]byte(nil), r.Doc...)
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Enrich returns the curated prioritization signal for a CVE from the most recently
// ingested bundle, or a zero Enrichment when the bundle carried none for it. Unlike
// the open feed (which has no curated signal and always answers empty), the paid
// feed is the curated, low-latency source.
func (f *Feed) Enrich(ctx context.Context, cve string) (vulnfeed.Enrichment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enrichment[cve], nil
}

// Changed returns the advisories whose records the most recent Sync (re)wrote, so
// the controller chore re-matches only their packages' nodes. Empty after a sync that
// changed nothing (a re-served current bundle, or one rejected by the version guard).
func (f *Feed) Changed() []vulnfeed.Vulnerability {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.changed
}

func (f *Feed) swapEnrichment(e map[string]vulnfeed.Enrichment) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enrichment = e
}

func (f *Feed) setChanged(c []vulnfeed.Vulnerability) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.changed = c
}

// memVersionStore is the in-process fallback when no persistent VersionStore is
// supplied: it gives rollback protection for the process lifetime only.
type memVersionStore struct {
	mu sync.Mutex
	v  int64
}

func (m *memVersionStore) GetBundleVersion() (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.v, nil
}

func (m *memVersionStore) SetBundleVersion(v int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.v = v
	return nil
}
