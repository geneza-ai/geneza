package controller

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"geneza.io/internal/affected/vulnfeed"
	"geneza.io/internal/affected/vulnfeed/osv"
)

// countingImageAdvisor counts AdvisoriesForDigest calls. MatchImageDigest consults
// the provider exactly once per call, so this counts image re-matches.
type countingImageAdvisor struct{ calls map[string]int }

func (c *countingImageAdvisor) Name() string { return "counting" }
func (c *countingImageAdvisor) AdvisoriesForDigest(_ context.Context, digest string) ([]vulnfeed.Vulnerability, error) {
	c.calls[digest]++
	return nil, nil
}

// rematchTestServer builds a minimal Server around a bbolt store with an OSV dir
// feed — enough for the sync/re-match path, without the full launch scaffolding.
func rematchTestServer(t *testing.T, fixtures map[string]string) (*Server, *countingImageAdvisor) {
	t.Helper()
	st, err := OpenStore(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	dir := writeOSVFixtures(t, fixtures)
	advisor := &countingImageAdvisor{calls: map[string]int{}}
	srv := &Server{
		store: st,
		cfg:   &Config{VulnFeed: VulnFeedConfig{Source: "osv_dir", Dir: dir}},
	}
	srv.inventoryFeed = osv.New(dir, FeedStore(st))
	srv.inventoryImageAdvisor = advisor
	return srv, advisor
}

// The bug this replaces: the post-sync pass walked CHANGED ADVISORIES, and each one
// re-matched every image digest carrying its package against the whole feed. Two
// advisories against two packages that happen to live in the same image meant that
// image was scanned twice; on a first full OSV sync, where every advisory is
// "changed", a digest carrying a common package was re-scanned thousands of times.
func TestImageDigestIsRematchedOncePerSyncNotOncePerAdvisory(t *testing.T) {
	srv, advisor := rematchTestServer(t, map[string]string{
		"openssl.json": `{
			"id": "USN-1", "modified": "2024-01-01T00:00:00Z", "aliases": ["CVE-2022-0778"],
			"affected": [{"package": {"ecosystem": "Debian:12", "name": "openssl"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9"}]}]}]
		}`,
		"zlib.json": `{
			"id": "USN-2", "modified": "2024-01-01T00:00:00Z", "aliases": ["CVE-2023-45853"],
			"affected": [{"package": {"ecosystem": "Debian:12", "name": "zlib"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9"}]}]}]
		}`,
	})

	// ONE image carrying BOTH advisories' packages.
	const digest = "sha256:aaaa"
	if err := srv.store.PutImageComponents(digest, []ImageComponentRecord{
		{Purl: "pkg:deb/debian/openssl@3.0.11", Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.11"},
		{Purl: "pkg:deb/debian/zlib@1.2.13", Ecosystem: "Debian:12", Name: "zlib", Version: "1.2.13"},
	}); err != nil {
		t.Fatalf("seed image components: %v", err)
	}

	if _, _ = srv.syncAndRematch(context.Background()); advisor.calls[digest] != 1 {
		t.Fatalf("image digest re-matched %d times for 2 dirty packages, want 1",
			advisor.calls[digest])
	}
}

// The queue is keyed by (ecosystem, package): a feed window naming the same few
// packages over and over must collapse to a few units of work.
func TestRematchQueueDedupesAdvisoriesByPackage(t *testing.T) {
	srv, _ := rematchTestServer(t, nil)
	// What a feed reports for a window of 500 advisories against two packages: the
	// feed itself already deduped, but the queue must not re-add on a later window.
	var changed []vulnfeed.Package
	for range 500 {
		changed = append(changed,
			vulnfeed.Package{Ecosystem: "Debian:12", Name: "openssl"},
			vulnfeed.Package{Ecosystem: "Debian:12", Name: "zlib"})
	}
	added, err := srv.enqueueRematch(changed, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if added != 2 {
		t.Fatalf("500 advisories over 2 packages queued %d units of work, want 2", added)
	}
	q := srv.loadRematchQueue()
	if len(q.Pending) != 2 || q.Watermark != 1000 {
		t.Fatalf("queue = %+v", q)
	}

	// A second window must merge, not replace: work left over from an interrupted
	// window has to survive a newer sync or it is silently never done.
	if _, err := srv.enqueueRematch([]vulnfeed.Package{
		{Ecosystem: "npm", Name: "ansi-regex"},
	}, 2000); err != nil {
		t.Fatal(err)
	}
	q = srv.loadRematchQueue()
	if len(q.Pending) != 3 {
		t.Fatalf("a newer window dropped pending work: %+v", q)
	}
	if q.Watermark != 2000 {
		t.Fatalf("candidate watermark = %d, want 2000", q.Watermark)
	}
}

// A feed that reports no changed advisories writes no queue. Reading the watermark
// back from that absent queue would reset it to zero, and the controller would
// re-sync the entire feed on every tick forever — a silent, expensive regression
// that looks exactly like normal operation in the logs.
func TestAQuietSyncAdvancesTheWatermarkInsteadOfResettingIt(t *testing.T) {
	srv, _ := rematchTestServer(t, nil) // no fixtures: nothing changes
	start := time.Now()
	if _, _ = srv.syncAndRematch(context.Background()); true {
		got := srv.vulnSyncWatermark()
		// Must be roughly NOW. A zero/epoch value is the failure mode: it stores and
		// reads back cleanly, and only shows up as the feed re-syncing from scratch
		// on every tick.
		if got.Before(start.Add(-time.Minute)) {
			t.Fatalf("watermark went backwards to %v (sync started %v); "+
				"every tick would re-sync the whole feed", got, start)
		}
	}
}

// An interrupted drain must not advance the feed watermark (that would skip the
// unprocessed packages forever) and must resume where it stopped rather than
// redoing the window — the difference between a fleet that eventually gets
// verdicts and one that never does.
func TestInterruptedRematchResumesAndWithholdsTheWatermark(t *testing.T) {
	srv, _ := rematchTestServer(t, map[string]string{
		"openssl.json": `{
			"id": "USN-1", "modified": "2024-01-01T00:00:00Z", "aliases": ["CVE-2022-0778"],
			"affected": [{"package": {"ecosystem": "Debian:12", "name": "openssl"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9"}]}]}]
		}`,
	})
	if err := srv.store.PutWorkspace(&WorkspaceRecord{ID: "ws", Name: "W"}); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.UpsertNodeComponents("ws", "n1", []ComponentRecord{
		{Purl: "pkg:deb/debian/openssl@3.0.11", Source: "os", Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.11", Distro: "debian:12"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.inventoryFeed.Sync(context.Background(), time.Time{}); err != nil {
		t.Fatal(err)
	}

	// Queue two packages, then interrupt the drain with an already-cancelled context.
	if _, err := srv.enqueueRematch([]vulnfeed.Package{
		{Ecosystem: "Debian:12", Name: "openssl"},
		{Ecosystem: "Debian:12", Name: "zlib"},
	}, 4242); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, drained, err := srv.drainRematchQueue(cancelled, nil)
	if err != nil {
		t.Fatal(err)
	}
	if drained {
		t.Fatal("a cancelled drain must not report the window applied")
	}
	if len(srv.loadRematchQueue().Pending) != 2 {
		t.Fatalf("cancelled before any work, but the queue lost entries: %+v", srv.loadRematchQueue())
	}
	if got := srv.vulnSyncWatermark(); !got.IsZero() {
		t.Fatalf("watermark advanced past unprocessed packages: %v", got)
	}

	// Resume: the same queue drains to completion and the verdict lands.
	written, drained, err := srv.drainRematchQueue(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !drained {
		t.Fatal("resumed drain did not finish")
	}
	if written == 0 {
		t.Fatal("resumed drain wrote no verdicts")
	}
	if len(srv.loadRematchQueue().Pending) != 0 {
		t.Fatalf("queue not empty after a full drain: %+v", srv.loadRematchQueue())
	}
	cves, err := srv.store.CVEsForNode("ws", "n1")
	if err != nil || len(cves) == 0 {
		t.Fatalf("CVEsForNode: err=%v len=%d", err, len(cves))
	}
}

// The type assertions in vulnsync.go prove each feed satisfies changedFeed; this
// proves buildVulnFeed actually HANDS BACK one for every configured source. The
// two are different failures: a source that falls through to a feed without the
// interface syncs advisories forever and writes no verdicts, with nothing in the
// logs to say so.
func TestEveryConfiguredFeedReportsChangedPackages(t *testing.T) {
	for _, source := range []string{"osv_dir", "osv_bulk"} {
		srv := &Server{
			store: func() Store {
				st, err := OpenStore(filepath.Join(t.TempDir(), "s.db"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { st.Close() })
				return st
			}(),
			cfg: &Config{VulnFeed: VulnFeedConfig{Source: source, Dir: t.TempDir()}},
		}
		feed := srv.buildVulnFeed()
		if feed == nil {
			t.Fatalf("%s: buildVulnFeed returned nil", source)
		}
		if _, ok := feed.(changedFeed); !ok {
			t.Fatalf("%s: %T does not report changed packages, so nothing is ever re-matched", source, feed)
		}
	}
}
