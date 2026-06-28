package update

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"geneza.io/internal/defaults"
)

// WorkerHealthFileName is the file the worker touches inside run_dir once it
// is up and has checked in healthy. The bootstrap removes the stale file
// before swapping workers, so its (re)appearance with a fresh mtime is proof
// the NEW binary came up — the signal that gates commit-vs-rollback. The name
// is defined in the shared defaults package so the worker and bootstrap cannot
// disagree on it (they once did: worker.health vs worker-health).
const WorkerHealthFileName = defaults.WorkerHealthFileName

// WorkerHealthFile returns the conventional health file path for a run dir.
func WorkerHealthFile(runDir string) string {
	return filepath.Join(runDir, WorkerHealthFileName)
}

const defaultHealthPoll = 250 * time.Millisecond

// HealthGate waits until healthFile exists with a modification time at or
// after the moment this call was made, failing after timeout or ctx expiry.
func HealthGate(ctx context.Context, healthFile string, timeout time.Duration) error {
	return healthGate(ctx, healthFile, time.Now(), timeout, defaultHealthPoll, time.Now)
}

// HealthGateSince is HealthGate with an explicit start instant. The
// bootstrap captures `since` BEFORE removing the stale file and starting the
// new worker, so a worker that writes its health file faster than the
// bootstrap reaches the gate still passes.
func HealthGateSince(ctx context.Context, healthFile string, since time.Time, timeout time.Duration) error {
	return healthGate(ctx, healthFile, since, timeout, defaultHealthPoll, time.Now)
}

// healthGate is the injectable core: `now` supplies the clock used for both
// the staleness comparison and the deadline so tests control time.
func healthGate(ctx context.Context, healthFile string, since time.Time, timeout, poll time.Duration, now func() time.Time) error {
	deadline := since.Add(timeout)
	for {
		fi, err := os.Stat(healthFile)
		// A file with mtime older than `since` is a stale leftover (e.g.
		// from the old worker); it must NOT pass the gate.
		if err == nil && !fi.ModTime().Before(since) {
			return nil
		}
		if now().After(deadline) {
			return fmt.Errorf("health gate: no fresh %s within %s", healthFile, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}
