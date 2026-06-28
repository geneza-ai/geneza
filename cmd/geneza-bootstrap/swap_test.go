package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"geneza.io/internal/update"
)

// These tests prove the bootstrap's product knob: the SAME swapWorker /
// Supervisor machinery health-gates and rolls back a geneza-RELAY worker exactly
// as it does the agent, with the only difference being the on-disk binary name
// (cfg.Product) and the worker argv (no session host). A relay worker that comes
// up healthy commits; one that never writes its health file is rolled back.

// fakeRelay writes an executable "geneza-relay" into <versionsDir>/<version>/.
// healthy=true makes it touch the health file (the readiness signal swapWorker
// gates on) and stay alive; healthy=false makes it exit immediately without ever
// writing health, which must trigger a rollback.
func fakeRelay(t *testing.T, versionsDir, version, healthFile string, healthy bool) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake worker is POSIX-only")
	}
	dir := filepath.Join(versionsDir, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var script string
	if healthy {
		// Refresh the health file with a fresh mtime on a tight loop so it always
		// reads fresh to a health gate, mirroring the real worker's touch loop.
		script = "#!/bin/sh\nwhile true; do date > " + shellQuote(healthFile) + "; sleep 1; done\n"
	} else {
		// Never write health; exit non-zero immediately.
		script = "#!/bin/sh\nexit 1\n"
	}
	bin := filepath.Join(dir, "geneza-relay")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func shellQuote(s string) string { return "'" + s + "'" }

func newRelayBootstrap(t *testing.T, versionsDir, runDir, current string) *bootstrap {
	t.Helper()
	st := &update.State{Current: current}
	return &bootstrap{
		cfg: &config{
			Product:          productRelay,
			WorkerConfig:     filepath.Join(t.TempDir(), "relay.yaml"),
			VersionsDir:      versionsDir,
			RunDir:           runDir,
			HealthTimeoutSec: 5,
			PollIntervalSec:  1,
		},
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		st:      st,
		current: current,
	}
}

func TestRelaySwapCommit(t *testing.T) {
	versionsDir := t.TempDir()
	runDir := t.TempDir()
	healthFile := update.WorkerHealthFile(runDir)

	fakeRelay(t, versionsDir, "1.0.0", healthFile, true) // current (good)
	fakeRelay(t, versionsDir, "2.0.0", healthFile, true) // new (good)

	b := newRelayBootstrap(t, versionsDir, runDir, "1.0.0")
	b.worker = b.startWorker(b.binPath("1.0.0"))
	t.Cleanup(func() { b.worker.Stop(context.Background()) })
	// Let the current relay establish health before the swap.
	if err := update.HealthGate(context.Background(), healthFile, 5*time.Second); err != nil {
		t.Fatalf("current relay never became healthy: %v", err)
	}

	b.swapWorker(context.Background(), b.binPath("2.0.0"), "2.0.0", time.Now().Unix())

	if b.current != "2.0.0" {
		t.Fatalf("after a healthy swap, current = %q, want 2.0.0", b.current)
	}
	if b.st.Current != "2.0.0" || b.st.Previous != "1.0.0" {
		t.Fatalf("state = current %q previous %q, want 2.0.0 / 1.0.0", b.st.Current, b.st.Previous)
	}
	if b.st.IsBad("2.0.0") {
		t.Fatal("healthy version must not be marked bad")
	}
}

func TestRelaySwapRollback(t *testing.T) {
	versionsDir := t.TempDir()
	runDir := t.TempDir()
	healthFile := update.WorkerHealthFile(runDir)

	fakeRelay(t, versionsDir, "1.0.0", healthFile, true)  // current (good)
	fakeRelay(t, versionsDir, "2.0.0", healthFile, false) // new (broken)

	b := newRelayBootstrap(t, versionsDir, runDir, "1.0.0")
	b.worker = b.startWorker(b.binPath("1.0.0"))
	t.Cleanup(func() { b.worker.Stop(context.Background()) })
	if err := update.HealthGate(context.Background(), healthFile, 5*time.Second); err != nil {
		t.Fatalf("current relay never became healthy: %v", err)
	}

	b.swapWorker(context.Background(), b.binPath("2.0.0"), "2.0.0", time.Now().Unix())

	// The broken relay failed its health gate: stay on the old version, mark the new
	// one bad so reconcile never retries it until the operator moves the target.
	if b.current != "1.0.0" {
		t.Fatalf("after a failed swap, current = %q, want 1.0.0 (rolled back)", b.current)
	}
	if !b.st.IsBad("2.0.0") {
		t.Fatal("failed version must be marked bad")
	}
	// The rolled-back (good) relay must be healthy again.
	if err := update.HealthGate(context.Background(), healthFile, 5*time.Second); err != nil {
		t.Fatalf("rolled-back relay did not become healthy: %v", err)
	}
}
