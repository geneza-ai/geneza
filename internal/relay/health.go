package relay

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"geneza.io/internal/version"
)

// healthTouchPeriod is how often the relay refreshes its update health file
// while serving. It mirrors the agent worker's cadence: well under the
// bootstrap's health-gate timeout so a healthy relay's file always reads fresh.
const healthTouchPeriod = 10 * time.Second

// drainStatusPeriod is how often a draining relay rewrites its drain-status file
// (the drained gate the bootstrap polls before a swap). Short so the bootstrap sees
// the active count fall to 0 within a beat of the last session migrating off.
const drainStatusPeriod = 500 * time.Millisecond

// RunHealthFile writes healthFile once and then periodically until ctx ends. It
// is the relay's liveness signal for a bootstrap-supervised deployment: the
// bootstrap removes the stale file before a swap and gates commit-vs-rollback on
// the NEW relay touching a fresh one — so this loop only starts after the relay
// is actually serving (wired via SetOnServing). Like the agent worker, it keeps
// writing regardless of controller/registrar reachability: a registrar outage must
// never make a serving relay look unhealthy and trigger a needless rollback.
func RunHealthFile(ctx context.Context, healthFile string, log *slog.Logger) {
	if healthFile == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(healthFile), 0o755); err != nil && log != nil {
		log.Error("relay: create health file dir", "path", healthFile, "err", err)
	}
	touch := func() {
		content := fmt.Sprintf("ok %d pid=%d version=%s\n", time.Now().UnixMilli(), os.Getpid(), version.Version)
		if err := os.WriteFile(healthFile, []byte(content), 0o644); err != nil && log != nil {
			log.Error("relay: write health file", "path", healthFile, "err", err)
		}
	}
	touch()
	t := time.NewTicker(healthTouchPeriod)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			touch()
		}
	}
}

// RunDrainStatusFile writes the relay's drain status to statusFile while ctx lives:
// once the relay starts draining it rewrites the file on a fast cadence with the live
// active (splice + control-mux) count, so a bootstrap-supervised relay's drained gate
// — "active reached 0" — is observable from the file alone, no controller round trip. It
// is the local counterpart of the heartbeat's active_count: the bootstrap drains the
// running relay (SIGUSR1) and polls this file to 0 (or a bounded window) BEFORE it
// stops and swaps the binary, so a swap never force-closes a session that could have
// migrated. Before draining the file reads "draining=false active=N"; the bootstrap
// only gates on it once it has signalled the drain.
func RunDrainStatusFile(ctx context.Context, statusFile string, r *Relay, log *slog.Logger) {
	if statusFile == "" || r == nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(statusFile), 0o755); err != nil && log != nil {
		log.Error("relay: create drain-status file dir", "path", statusFile, "err", err)
	}
	write := func() {
		content := fmt.Sprintf("draining=%t active=%d ts=%d\n", r.Draining(), r.Active(), time.Now().UnixMilli())
		if err := os.WriteFile(statusFile, []byte(content), 0o644); err != nil && log != nil {
			log.Error("relay: write drain-status file", "path", statusFile, "err", err)
		}
	}
	write()
	// Idle until the relay actually begins draining, then poll fast so the bootstrap
	// observes the count fall promptly. A pre-drain relay writes the file once (so a
	// stale gate never misreads a missing file) and otherwise stays quiet.
	select {
	case <-ctx.Done():
		return
	case <-r.DrainSignal():
	}
	write()
	t := time.NewTicker(drainStatusPeriod)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			write()
		}
	}
}
