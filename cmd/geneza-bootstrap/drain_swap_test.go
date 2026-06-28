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

// These tests prove the relay drain-before-swap gate: before stopping a relay worker
// for a swap, the bootstrap signals it to drain (SIGUSR1) and waits for its
// drain-status file to report the active count at 0, so live sessions migrate off the
// relay instead of being force-closed by the stop. When the relay never clears, a
// bounded window lets the swap proceed anyway (the stop's SIGTERM force-closes the
// remainder, as before this gate existed).

// fakeDrainingRelay writes a relay that, on SIGUSR1, rewrites statusFile to
// "draining=true active=<N>" — first reporting clearDelay's worth of pinned work
// (active=1) and then active=0, so the bootstrap's poll observes the gate clear.
// When clearDelay is < 0 it NEVER clears (active stays 1), exercising the window path.
func fakeDrainingRelay(t *testing.T, versionsDir, version, healthFile, statusFile string, clearDelay time.Duration) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake worker is POSIX-only")
	}
	dir := filepath.Join(versionsDir, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The script: touch health on a loop; on SIGUSR1 write draining=true active=1, then
	// (when clearDelay >= 0) after that delay write draining=true active=0.
	script := "#!/bin/sh\n" +
		"STATUS=" + shellQuote(statusFile) + "\n" +
		"HEALTH=" + shellQuote(healthFile) + "\n" +
		"printf 'draining=false active=0 ts=0\\n' > \"$STATUS\"\n" +
		"drain() {\n" +
		"  printf 'draining=true active=1 ts=0\\n' > \"$STATUS\"\n"
	if clearDelay >= 0 {
		secs := float64(clearDelay/time.Millisecond) / 1000.0
		script += "  ( sleep " + ftoa(secs) + "; printf 'draining=true active=0 ts=0\\n' > \"$STATUS\" ) &\n"
	}
	script += "}\n" +
		"trap drain USR1\n" +
		"while true; do date > \"$HEALTH\"; sleep 0.2; done\n"
	bin := filepath.Join(dir, "geneza-relay")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// ftoa formats a small positive number of seconds for `sleep` without importing fmt
// verbs that the shell would choke on.
func ftoa(f float64) string {
	whole := int(f)
	frac := int((f - float64(whole)) * 1000)
	out := itoa(whole) + "."
	for d := 100; d > 0; d /= 10 {
		out += string(rune('0' + (frac/d)%10))
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func newDrainBootstrap(t *testing.T, versionsDir, runDir, current, statusFile string) *bootstrap {
	t.Helper()
	return &bootstrap{
		cfg: &config{
			Product:          productRelay,
			WorkerConfig:     filepath.Join(t.TempDir(), "relay.yaml"),
			VersionsDir:      versionsDir,
			RunDir:           runDir,
			HealthTimeoutSec: 5,
			PollIntervalSec:  1,
			DrainStatusFile:  statusFile,
			DrainWindowSec:   5,
		},
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		st:      &update.State{Current: current},
		current: current,
	}
}

// The swap waits for the relay to drain (active -> 0) before stopping it, then
// health-gates the new relay and commits.
func TestDrainBeforeSwapWaitsThenCommits(t *testing.T) {
	versionsDir := t.TempDir()
	runDir := t.TempDir()
	healthFile := update.WorkerHealthFile(runDir)
	statusFile := filepath.Join(runDir, "relay-drain.status")

	// Current relay drains and clears after ~600ms; the new relay is healthy.
	fakeDrainingRelay(t, versionsDir, "1.0.0", healthFile, statusFile, 600*time.Millisecond)
	fakeRelay(t, versionsDir, "2.0.0", healthFile, true)

	b := newDrainBootstrap(t, versionsDir, runDir, "1.0.0", statusFile)
	b.worker = b.startWorker(b.binPath("1.0.0"))
	t.Cleanup(func() { b.worker.Stop(context.Background()) })
	if err := update.HealthGate(context.Background(), healthFile, 5*time.Second); err != nil {
		t.Fatalf("current relay never became healthy: %v", err)
	}

	start := time.Now()
	b.swapWorker(context.Background(), b.binPath("2.0.0"), "2.0.0", time.Now().Unix())
	waited := time.Since(start)

	if waited < 400*time.Millisecond {
		t.Fatalf("swap did not wait for the drain to clear (took %s)", waited)
	}
	if b.current != "2.0.0" {
		t.Fatalf("after drain+healthy swap, current = %q, want 2.0.0", b.current)
	}
	// The status file should have been observed as drained (active=0) before the swap.
	if draining, active, ok := readDrainStatus(statusFile); !ok || !draining {
		t.Fatalf("drain status not observed: draining=%v active=%d ok=%v", draining, active, ok)
	}
}

// When the relay never clears, the bootstrap proceeds after the bounded window
// rather than blocking the rollout forever.
func TestDrainBeforeSwapHonorsWindow(t *testing.T) {
	versionsDir := t.TempDir()
	runDir := t.TempDir()
	healthFile := update.WorkerHealthFile(runDir)
	statusFile := filepath.Join(runDir, "relay-drain.status")

	// Current relay drains but NEVER clears (active stays 1); new relay healthy.
	fakeDrainingRelay(t, versionsDir, "1.0.0", healthFile, statusFile, -1)
	fakeRelay(t, versionsDir, "2.0.0", healthFile, true)

	b := newDrainBootstrap(t, versionsDir, runDir, "1.0.0", statusFile)
	b.cfg.DrainWindowSec = 1 // short bounded window for the test
	b.worker = b.startWorker(b.binPath("1.0.0"))
	t.Cleanup(func() { b.worker.Stop(context.Background()) })
	if err := update.HealthGate(context.Background(), healthFile, 5*time.Second); err != nil {
		t.Fatalf("current relay never became healthy: %v", err)
	}

	start := time.Now()
	b.swapWorker(context.Background(), b.binPath("2.0.0"), "2.0.0", time.Now().Unix())
	waited := time.Since(start)

	// It must have waited roughly the window before giving up on the un-clearing drain.
	if waited < 900*time.Millisecond {
		t.Fatalf("swap should have waited out the drain window, took only %s", waited)
	}
	if b.current != "2.0.0" {
		t.Fatalf("after window-elapsed swap, current = %q, want 2.0.0", b.current)
	}
}

// readDrainStatus parses the file the bootstrap polls.
func TestReadDrainStatus(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "s")
	if _, _, ok := readDrainStatus(f); ok {
		t.Fatal("a missing file must not be reported as drained")
	}
	if err := os.WriteFile(f, []byte("draining=true active=0 ts=123\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	draining, active, ok := readDrainStatus(f)
	if !ok || !draining || active != 0 {
		t.Fatalf("parse = draining %v active %d ok %v, want true 0 true", draining, active, ok)
	}
	if err := os.WriteFile(f, []byte("draining=true active=3 ts=123\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, active, ok := readDrainStatus(f); !ok || active != 3 {
		t.Fatalf("active = %d ok %v, want 3 true", active, ok)
	}
}
