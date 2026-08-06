package controller

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"geneza.io/internal/affected/engine"
	"geneza.io/internal/affected/vulnfeed"
	"geneza.io/internal/affected/vulnfeed/enrich"
	"geneza.io/internal/affected/vulnfeed/osv"
	"geneza.io/internal/affected/vulnfeed/paid"
)

// settingPaidBundleVersion holds the highest paid-feed bundle version this controller
// has ingested. It is the rollback guard for the curated feed, persisted in the
// shared settings table so the monotonicity check survives a restart and is shared
// across flat controllers — a captured older bundle cannot be replayed after a bounce.
const settingPaidBundleVersion = "vuln_paid_bundle_version"

// settingVulnSyncWatermark holds the Unix seconds of the last successful feed
// sync. It is the delta cursor passed as Sync's `since`, persisted in the shared
// settings table so every flat controller reads the same watermark and a sync is
// correct-on-loss (a controller that dies mid-sync leaves the watermark unadvanced
// and another retries the same window).
const settingVulnSyncWatermark = "vuln_sync_watermark_unix"

// settingVulnSyncLastError records the most recent sync failure (empty after a
// success), so the console can tell "no CVEs because the fleet is clean" apart from
// "no CVEs because the feed has never finished downloading". Without it a failing
// sync is visible only in whichever controller's logs happened to run the tick.
const settingVulnSyncLastError = "vuln_sync_last_error"

// vulnSyncMinInterval floors the configured cadence so a misconfigured tiny
// interval cannot turn the chore into a hot loop hammering the feed source.
const vulnSyncMinInterval = time.Minute

// changedFeed is the optional surface a feed exposes so the sync chore can
// re-match ONLY what a sync (re)wrote, instead of re-scanning the fleet. All three
// sources implement it; a feed that does not is simply synced with no post-sync
// re-match (its verdicts converge when nodes next report).
//
// It reports PACKAGES, not advisories: the re-match is keyed by package, and on a
// first full sync the advisory set is the whole feed — several hundred thousand
// records held only to be reduced to their package names.
type changedFeed interface {
	ChangedPackages() []vulnfeed.Package
}

// The assertion is the point: this is a SILENT seam. A feed that stops satisfying
// it — a rename, a signature change — still compiles, still syncs, and simply
// never re-matches anything again, which presents as a fleet with a full advisory
// store and no verdicts. Every shipped feed is pinned here so that breaks the build
// instead. TestEveryConfiguredFeedReportsChangedPackages covers the wiring.
var (
	_ changedFeed = (*osv.Feed)(nil)
	_ changedFeed = (*osv.BulkFeed)(nil)
	_ changedFeed = (*paid.Feed)(nil)
)

// buildVulnFeed constructs the configured feed and binds it to this server's
// advisory store, or returns nil when no source is configured (today's
// behaviour: SBOMs stored, no verdicts). The same store adapter the node-change
// re-match uses backs the feed, so both triggers read and write one advisory set.
func (s *Server) buildVulnFeed() vulnfeed.Feed {
	store := FeedStore(s.store)
	switch s.cfg.VulnFeed.Source {
	case "osv_dir":
		return osv.New(s.cfg.VulnFeed.Dir, store)
	case "osv_bulk":
		return osv.NewBulk(s.cfg.VulnFeed.BulkURL, s.cfg.VulnFeed.Ecosystems, store, nil)
	case "geneza-paid":
		pub, err := s.cfg.VulnFeed.paidPubKey()
		if err != nil {
			// Config validation already rejected a bad key, so this is unreachable in
			// practice; fail closed (no feed) rather than run the paid feed unpinned.
			slog.Error("paid vuln feed: pinned key", "err", err)
			return nil
		}
		f, err := paid.New(paid.Options{
			Endpoint:     s.cfg.VulnFeed.PaidEndpoint,
			LicenseKey:   s.cfg.VulnFeed.PaidLicense,
			VendorPubKey: pub,
			Store:        store,
			Versions:     paidVersionStore{s: s.store},
		})
		if err != nil {
			slog.Error("paid vuln feed: build", "err", err)
			return nil
		}
		return f
	default:
		return nil
	}
}

// paidVersionStore backs the paid feed's monotonic bundle-version watermark with
// the controller's shared settings table, so the rollback guard is persistent and
// shared across flat controllers rather than living only in process memory.
type paidVersionStore struct{ s Store }

func (p paidVersionStore) GetBundleVersion() (int64, error) {
	b, err := p.s.GetSetting(settingPaidBundleVersion)
	if err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, nil
	}
	v, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		// A garbled value reads as 0 (a full re-ingest), matching the watermark's
		// correct-on-loss posture; never block the feed on a corrupt setting.
		return 0, nil
	}
	return v, nil
}

func (p paidVersionStore) SetBundleVersion(v int64) error {
	return p.s.SetSetting(settingPaidBundleVersion, []byte(strconv.FormatInt(v, 10)))
}

// buildVulnVEX constructs the OpenVEX suppression source from the configured VEX
// directory, loading it once at startup, or returns nil when no directory is
// configured (no suppression). The chore reloads it before each sync so a freshly
// dropped VEX document takes effect without a restart.
func (s *Server) buildVulnVEX() (engine.VEXSource, error) {
	dir := s.cfg.VulnFeed.VEXDir
	if dir == "" {
		return nil, nil
	}
	v := engine.NewDocVEX()
	n, err := v.LoadDir(dir)
	if err != nil {
		return nil, err
	}
	slog.Info("openvex suppression active", "dir", dir, "statements", n)
	return v, nil
}

// buildVulnEnricher constructs the KEV/EPSS enricher from config, or nil when
// neither feed is configured. A URL of "default" resolves to the public endpoint;
// any other non-empty value is used verbatim (so a mirror can be configured).
func (s *Server) buildVulnEnricher() *enrich.Enricher {
	kev := resolveEnrichURL(s.cfg.VulnFeed.KEVURL, enrich.DefaultKEVURL)
	epss := resolveEnrichURL(s.cfg.VulnFeed.EPSSURL, enrich.DefaultEPSSURL)
	if kev == "" && epss == "" {
		return nil
	}
	return enrich.New(enrich.Options{KEVURL: kev, EPSSURL: epss})
}

// resolveEnrichURL maps the config value to a fetch URL: empty stays off, the
// literal "default" resolves to the public endpoint, anything else is verbatim.
func resolveEnrichURL(configured, def string) string {
	if configured == "default" {
		return def
	}
	return configured
}

// runVulnSync is the daily (configurable) feed-sync chore. It is an HA chore:
// every flat controller runs the loop, but a transient advisory lock debounces each
// tick so only one controller fetches + re-matches per interval (no sticky leader),
// and the watermark in the shared settings table makes the sync idempotent and
// correct-on-loss. It is inert unless a feed source is configured. An initial run
// fires shortly after start so a fresh controller populates verdicts without waiting
// a whole interval.
func (s *Server) runVulnSync(ctx context.Context) {
	feedOn := s.cfg.VulnFeed.Enabled() && s.inventoryFeed != nil
	enrichOn := s.inventoryEnricher != nil
	if !feedOn && !enrichOn {
		// Say so. With no feed the inventory module still collects SBOMs and the
		// console still renders every node, so the deployment looks entirely healthy
		// while being structurally incapable of ever reporting a CVE. Silence here is
		// what makes that indistinguishable from a genuinely clean fleet.
		if !s.cfg.VulnFeed.Enabled() {
			slog.Warn("vuln feed disabled: no CVE verdicts will be produced"+
				" (set vuln_feed.source in controller.yaml; SBOM collection is unaffected)",
				"component", "vulnfeed")
		} else {
			slog.Error("vuln feed configured but could not be built: no CVE verdicts will be produced",
				"component", "vulnfeed", "source", s.cfg.VulnFeed.Source)
		}
		return
	}
	interval := s.cfg.VulnFeed.SyncInterval.D()
	if interval < vulnSyncMinInterval {
		interval = vulnSyncMinInterval
	}
	slog.Info("vuln feed sync active", "source", s.cfg.VulnFeed.Source, "enrich", enrichOn, "interval", interval)

	// A short initial delay lets the controller finish coming up (and lets a fleet
	// stagger naturally) before the first sync; the advisory lock still debounces it.
	t := time.NewTimer(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.vulnSyncTick(ctx)
			t.Reset(interval)
		}
	}
}

// vulnSyncTick runs one debounced sync: grab the shared advisory lock (skip the
// tick if another controller holds it), sync the feed from the persisted watermark,
// re-match only the changed advisories' nodes, then advance the watermark. The
// watermark is advanced only on a fully successful sync+re-match, so a failure
// mid-run re-tries the same window next tick rather than skipping advisories.
func (s *Server) vulnSyncTick(ctx context.Context) {
	held, release, err := s.store.TryVulnSyncLock(ctx)
	if err != nil {
		slog.Warn("vuln sync: lock", "err", err)
		return
	}
	if !held {
		return // another controller is syncing this tick
	}
	defer release()

	// Reload the OpenVEX directory so a freshly dropped suppression document takes
	// effect on this tick's re-match without a controller restart. A reload failure is
	// non-fatal: keep the previously loaded statements and carry on.
	if dv, ok := s.inventoryVEX.(*engine.DocVEX); ok {
		if _, err := dv.LoadDir(s.cfg.VulnFeed.VEXDir); err != nil {
			slog.Warn("vuln sync: reload openvex", "err", err)
		}
	}

	n, rematched := 0, 0
	if s.cfg.VulnFeed.Enabled() && s.inventoryFeed != nil {
		n, rematched = s.syncAndRematch(ctx)
	}

	// Enrichment pass: refresh the KEV/EPSS snapshot and overlay it onto the CVEs
	// that currently have verdicts. It runs after the re-match so newly written
	// verdicts are enriched this tick, and it is idempotent so a re-run is cheap.
	enriched := s.enrichVerdicts(ctx)

	if n > 0 || rematched > 0 || enriched > 0 {
		slog.Info("vuln sync complete", "advisories", n, "verdicts", rematched, "enriched", enriched)
	}
}

// syncAndRematch pulls the feed from the persisted watermark, queues the changed
// advisories' packages, and drains as much of that queue as this tick's budget
// allows. It reports the advisories fetched and the verdict rows written.
//
// The watermark advances only when the queue drains completely, so a partial run
// re-syncs the same window next tick — but the queue keeps what it already did, so
// "re-sync the window" costs a feed fetch, not the whole re-match again.
func (s *Server) syncAndRematch(ctx context.Context) (fetched, rematched int) {
	since := s.vulnSyncWatermark()
	startedUnix := time.Now().Unix()
	n, err := s.inventoryFeed.Sync(ctx, since)
	if err != nil {
		slog.Warn("vuln sync: feed sync", "err", err)
		s.setVulnSyncLastError(err.Error())
		return 0, 0
	}
	// Fold the changed advisories into the persisted re-match queue as distinct
	// (ecosystem, package) keys. See vulnrematch.go for why the unit of work is the
	// package rather than the advisory.
	if cf, ok := s.inventoryFeed.(changedFeed); ok {
		if _, err := s.enqueueRematch(cf.ChangedPackages(), startedUnix); err != nil {
			slog.Warn("vuln sync: queue re-match", "err", err)
			s.setVulnSyncLastError(err.Error())
			return n, 0
		}
	}
	w, drained, err := s.drainRematchQueue(ctx, s.inventoryVEX)
	if err != nil {
		slog.Warn("vuln sync: re-match", "err", err)
		s.setVulnSyncLastError(err.Error())
		return n, w
	}
	s.setVulnSyncLastError("")
	if !drained {
		return n, w
	}
	// The cursor is the moment this sync STARTED, not the queue's candidate: a feed
	// that does not report changed advisories never writes a queue, and reading the
	// watermark back from an absent queue would reset it to zero and re-sync the
	// whole feed on every tick.
	if err := s.setVulnSyncWatermark(startedUnix); err != nil {
		slog.Warn("vuln sync: persist watermark", "err", err)
		s.setVulnSyncLastError(err.Error())
	}
	return n, w
}

// enrichVerdicts refreshes the KEV/EPSS feeds and overlays them onto the CVEs that
// appear in node_cve, returning how many rows it changed. It is a no-op when no
// enricher is configured. A feed-refresh error is logged and skips the overlay
// this tick (the prior snapshot, if any, is kept by Refresh). The scores map is
// built only over the CVEs that actually have verdicts, so a quarter-million-entry
// EPSS feed becomes a lookup of the small affected set.
func (s *Server) enrichVerdicts(ctx context.Context) int {
	if s.inventoryEnricher == nil {
		return 0
	}
	if err := s.inventoryEnricher.Refresh(ctx); err != nil {
		slog.Warn("vuln sync: enrich refresh", "err", err)
		return 0
	}
	cves, err := s.store.DistinctNodeCVEs()
	if err != nil {
		slog.Warn("vuln sync: list verdict cves", "err", err)
		return 0
	}
	// Image-side verdicts carry the same prioritization signal; fold their CVEs into
	// the same lookup so a digest verdict is enriched even when no host verdict shares
	// the CVE.
	imageCVEs, err := s.store.DistinctImageCVEs()
	if err != nil {
		slog.Warn("vuln sync: list image verdict cves", "err", err)
		return 0
	}
	if len(cves) == 0 && len(imageCVEs) == 0 {
		return 0
	}
	scores := make(map[string]CVEEnrichment, len(cves)+len(imageCVEs))
	for _, cve := range cves {
		kev, epss := s.inventoryEnricher.Lookup(cve)
		scores[cve] = CVEEnrichment{KEV: kev, EPSS: epss}
	}
	for _, cve := range imageCVEs {
		if _, ok := scores[cve]; ok {
			continue
		}
		kev, epss := s.inventoryEnricher.Lookup(cve)
		scores[cve] = CVEEnrichment{KEV: kev, EPSS: epss}
	}
	updated, err := s.store.EnrichNodeCVEs(scores)
	if err != nil {
		slog.Warn("vuln sync: apply enrichment", "err", err)
		return 0
	}
	imageUpdated, err := s.store.EnrichImageCVEs(scores)
	if err != nil {
		slog.Warn("vuln sync: apply image enrichment", "err", err)
		return updated
	}
	return updated + imageUpdated
}

// vulnSyncWatermark reads the persisted last-sync cursor; a missing/garbled value
// is the zero time (a full refresh), which is safe — Sync is idempotent.
func (s *Server) vulnSyncWatermark() time.Time {
	b, err := s.store.GetSetting(settingVulnSyncWatermark)
	if err != nil || len(b) == 0 {
		return time.Time{}
	}
	secs, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(secs, 0)
}

// setVulnSyncWatermark persists the last-sync cursor in the shared settings table.
func (s *Server) setVulnSyncWatermark(unix int64) error {
	return s.store.SetSetting(settingVulnSyncWatermark, []byte(strconv.FormatInt(unix, 10)))
}

// setVulnSyncLastError records (or, with "", clears) the last sync failure. A
// failure to persist it is not worth failing the tick over — it is a status hint.
func (s *Server) setVulnSyncLastError(msg string) {
	if err := s.store.SetSetting(settingVulnSyncLastError, []byte(msg)); err != nil {
		slog.Warn("vuln sync: persist last error", "err", err)
	}
}

// vulnSyncLastError reads the recorded last sync failure ("" when the last sync
// succeeded or none has run).
func (s *Server) vulnSyncLastError() string {
	b, err := s.store.GetSetting(settingVulnSyncLastError)
	if err != nil {
		return ""
	}
	return string(b)
}

// VulnFeedStatus is what the console needs to render an honest empty state: with a
// feed off, or synced-but-empty, "no vulnerabilities" is not a clean bill of health.
type VulnFeedStatus struct {
	Enabled       bool     `json:"enabled"`
	Source        string   `json:"source"`
	Ecosystems    []string `json:"ecosystems,omitempty"`
	LastSyncUnix  int64    `json:"lastSyncUnix"`
	AdvisoryCount int64    `json:"advisoryCount"`
	LastError     string   `json:"lastError,omitempty"`
}

// vulnFeedStatus assembles the current feed status.
func (s *Server) vulnFeedStatus() VulnFeedStatus {
	st := VulnFeedStatus{
		Enabled:   s.cfg.VulnFeed.Enabled() && s.inventoryFeed != nil,
		Source:    s.cfg.VulnFeed.Source,
		LastError: s.vulnSyncLastError(),
	}
	if st.Enabled {
		st.Ecosystems = s.cfg.VulnFeed.Ecosystems
		if wm := s.vulnSyncWatermark(); !wm.IsZero() {
			st.LastSyncUnix = wm.Unix()
		}
		if n, err := s.store.CountAdvisories(); err == nil {
			st.AdvisoryCount = n
		}
	}
	return st
}
