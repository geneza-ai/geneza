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

// vulnSyncMinInterval floors the configured cadence so a misconfigured tiny
// interval cannot turn the chore into a hot loop hammering the feed source.
const vulnSyncMinInterval = time.Minute

// changedFeed is the optional surface a feed exposes so the sync chore can
// re-match ONLY the advisories a sync (re)wrote, instead of re-scanning the
// fleet. Both OSV sources implement it; a feed that does not is simply synced
// with no post-sync re-match (its verdicts converge when nodes next report).
type changedFeed interface {
	Changed() []vulnfeed.Vulnerability
}

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
		since := s.vulnSyncWatermark()
		startedUnix := time.Now().Unix()
		fetched, err := s.inventoryFeed.Sync(ctx, since)
		if err != nil {
			slog.Warn("vuln sync: feed sync", "err", err)
			return
		}
		n = fetched
		if cf, ok := s.inventoryFeed.(changedFeed); ok {
			for _, adv := range cf.Changed() {
				w, rerr := s.RematchChangedAdvisory(ctx, s.inventoryVEX, adv)
				if rerr != nil {
					// Leave the watermark unadvanced so the next tick re-syncs this window
					// and re-attempts the re-match; a half-applied window is never recorded.
					slog.Warn("vuln sync: re-match advisory", "advisory", adv.ID, "err", rerr)
					return
				}
				rematched += w
			}
		}
		// Advance the watermark only after sync + re-match both fully succeeded. The
		// cursor is the moment the sync STARTED, so an advisory modified during the
		// fetch is re-considered next tick (at-least-once), never skipped.
		if err := s.setVulnSyncWatermark(startedUnix); err != nil {
			slog.Warn("vuln sync: persist watermark", "err", err)
			return
		}
	}

	// Enrichment pass: refresh the KEV/EPSS snapshot and overlay it onto the CVEs
	// that currently have verdicts. It runs after the re-match so newly written
	// verdicts are enriched this tick, and it is idempotent so a re-run is cheap.
	enriched := s.enrichVerdicts(ctx)

	if n > 0 || rematched > 0 || enriched > 0 {
		slog.Info("vuln sync complete", "advisories", n, "verdicts", rematched, "enriched", enriched)
	}
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
