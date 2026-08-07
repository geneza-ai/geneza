package controller

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"strings"
	"time"

	"geneza.io/internal/affected"
	"geneza.io/internal/affected/engine"
	"geneza.io/internal/affected/vulnfeed"
)

// The post-sync re-match used to walk the changed advisories one at a time, and on
// a first full OSV sync "changed" is the entire feed — hundreds of thousands of
// advisories. Two things made that pathological rather than merely large:
//
//   - Every advisory naming a package present in a container image re-matched that
//     whole image digest against the whole feed, deduped only WITHIN one advisory.
//     A digest carrying a common package (glibc, openssl) was therefore re-scanned
//     once per advisory that mentions it.
//   - The watermark advanced only after the entire changed set finished, and the
//     changed set lives in memory. A failure or a restart near the end threw away
//     every hour of work and started the same window over — which is how a fleet
//     ends up with SBOMs collected and no verdicts, indefinitely.
//
// So the work is keyed by distinct (ecosystem, package) instead of by advisory,
// persisted as a queue, and drained incrementally with a checkpoint after each
// chunk. Fewer keys than advisories by orders of magnitude, each image digest
// re-matched at most once per drain, and an interrupted run resumes where it
// stopped instead of restarting.

// settingVulnRematchQueue holds the pending re-match work: the deduped
// (ecosystem, package) keys still to process, plus the feed watermark that becomes
// current once they are all done.
const settingVulnRematchQueue = "vuln_rematch_queue"

// rematchChunk is how many package keys are processed between checkpoints. Small
// enough that a crash loses seconds of work, large enough that the checkpoint
// write is not the dominant cost.
const rematchChunk = 25

// rematchBudget bounds one tick's drain so a huge backlog does not hold the
// shared advisory lock (or an unresponsive context) for the whole sync interval.
// Whatever is left stays queued for the next tick.
const rematchBudget = 2 * time.Minute

// rematchDrainInterval is how soon the chore comes back while the queue still has
// work. A first full OSV sync queues far more than one budget can drain, and
// waiting the whole sync interval between attempts would leave the fleet with a
// complete advisory store and no verdicts for hours.
const rematchDrainInterval = time.Minute

// rematchQueue is the persisted work list. Pending keys are "<ecosystem>\x00<name>".
type rematchQueue struct {
	// Watermark is the candidate feed cursor: it is written to
	// settingVulnSyncWatermark only once Pending drains to empty, so an
	// interrupted drain re-syncs the same window rather than skipping advisories.
	Watermark int64    `json:"watermark"`
	Pending   []string `json:"pending"`
}

func pkgQueueKey(ecosystem, name string) string { return ecosystem + "\x00" + name }

func (s *Server) loadRematchQueue() rematchQueue {
	var q rematchQueue
	b, err := s.store.GetSetting(settingVulnRematchQueue)
	if err != nil || len(b) == 0 {
		return q
	}
	if err := json.Unmarshal(b, &q); err != nil {
		slog.Warn("vuln sync: unreadable re-match queue, starting a fresh one", "err", err)
		return rematchQueue{}
	}
	return q
}

func (s *Server) saveRematchQueue(q rematchQueue) error {
	b, err := json.Marshal(q)
	if err != nil {
		return err
	}
	return s.store.SetSetting(settingVulnRematchQueue, b)
}

// enqueueRematch folds one sync window's changed packages into the persisted
// queue. Merging rather than replacing is what keeps at-least-once: a package left
// over from an interrupted window stays queued even as a newer window's packages
// arrive, so the candidate watermark can safely move forward to the newer sync.
func (s *Server) enqueueRematch(changed []vulnfeed.Package, watermark int64) (int, error) {
	q := s.loadRematchQueue()
	have := make(map[string]struct{}, len(q.Pending))
	for _, k := range q.Pending {
		have[k] = struct{}{}
	}
	added := 0
	for _, p := range changed {
		if p.Name == "" || p.Ecosystem == "" {
			continue
		}
		k := pkgQueueKey(p.Ecosystem, p.Name)
		if _, dup := have[k]; dup {
			continue
		}
		have[k] = struct{}{}
		q.Pending = append(q.Pending, k)
		added++
	}
	if watermark > q.Watermark {
		q.Watermark = watermark
	}
	// Deterministic order so a resumed drain covers the same ground in the same
	// sequence, and so two controllers taking alternate ticks agree on progress.
	sort.Strings(q.Pending)
	return added, s.saveRematchQueue(q)
}

// drainRematchQueue processes queued package keys until the queue empties, the
// budget expires, or the context is cancelled. It reports the verdict rows written
// and whether the queue drained completely (the caller advances the feed watermark
// only then).
func (s *Server) drainRematchQueue(ctx context.Context, vex engine.VEXSource) (written int, drained bool, err error) {
	q := s.loadRematchQueue()
	if len(q.Pending) == 0 {
		return 0, true, nil
	}
	m := s.affectedMatcher(vex)
	// Digests re-matched in THIS drain. A digest carrying twenty dirty packages is
	// re-matched once, not twenty times — the whole point of batching by package.
	doneDigests := map[string]struct{}{}
	deadline := time.Now().Add(rematchBudget)
	start := len(q.Pending)

	for len(q.Pending) > 0 {
		if ctx.Err() != nil {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		n := min(rematchChunk, len(q.Pending))
		for _, key := range q.Pending[:n] {
			eco, name, ok := strings.Cut(key, "\x00")
			if !ok {
				continue // malformed entry: drop it rather than wedge the queue
			}
			w, perr := s.rematchPackage(ctx, m, eco, name, doneDigests)
			written += w
			if perr != nil {
				// Checkpoint what DID finish before returning, so the failure costs
				// this chunk rather than the whole backlog.
				_ = s.saveRematchQueue(q)
				return written, false, perr
			}
		}
		q.Pending = q.Pending[n:]
		if err := s.saveRematchQueue(q); err != nil {
			return written, false, err
		}
	}
	drained = len(q.Pending) == 0
	// Say something whenever real work happened. A drain that matches 200k packages
	// and writes no verdicts (a fleet whose inventory simply does not carry those
	// packages) is the common case, and reporting only the verdict count made it
	// indistinguishable from an idle controller for minutes at a time.
	switch {
	case !drained:
		slog.Info("vuln sync: re-match paused with work remaining",
			"component", "vulnsync", "done", start-len(q.Pending), "remaining", len(q.Pending),
			"verdicts", written)
	case start > 0:
		slog.Info("vuln sync: re-match complete",
			"component", "vulnsync", "packages", start, "verdicts", written)
	}
	return written, drained, nil
}

// rematchPackage re-evaluates one (ecosystem, package) across every workspace's
// stored components and every image digest carrying it. It matches the package's
// FULL advisory set rather than a single advisory: the unit of work is the package,
// and the feed's by-package resolve (backed by the store's by-package index) is
// what makes that as cheap as the single-advisory lookup it replaces.
func (s *Server) rematchPackage(ctx context.Context, m *affectedMatcher, ecosystem, name string, doneDigests map[string]struct{}) (int, error) {
	if s.inventoryFeed == nil {
		return 0, nil
	}
	advs, err := s.inventoryFeed.Advisories(ecosystem, name)
	if err != nil {
		return 0, err
	}
	written := 0
	if len(advs) > 0 {
		wss, err := s.store.ListWorkspaces()
		if err != nil {
			return written, err
		}
		for _, ws := range wss {
			comps, err := s.store.ListComponentsByPackage(ws.ID, ecosystem, name)
			if err != nil {
				return written, err
			}
			if len(comps) == 0 {
				continue
			}
			cands := make([]affected.Component, len(comps))
			for i := range comps {
				cands[i] = componentFromRecord(comps[i])
			}
			eng := engine.New(ws.ID, m.vex)
			for _, adv := range advs {
				matches, err := eng.MatchAdvisory(ctx, adv, cands)
				if err != nil {
					return written, err
				}
				for _, mt := range matches {
					if err := m.persist(ws.ID, mt); err != nil {
						return written, err
					}
					written++
				}
			}
		}
	}

	digests, err := s.store.ImageDigestsForPackage(ecosystem, name)
	if err != nil {
		return written, err
	}
	for _, d := range digests {
		if _, done := doneDigests[d]; done {
			continue
		}
		doneDigests[d] = struct{}{}
		w, err := m.MatchImageDigest(ctx, s.inventoryFeed, d)
		if err != nil {
			return written, err
		}
		written += w
	}
	return written, nil
}
