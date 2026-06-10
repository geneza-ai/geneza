package update

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestHealthGatePasses(t *testing.T) {
	file := filepath.Join(t.TempDir(), "worker-health")
	since := time.Now()
	go func() {
		time.Sleep(30 * time.Millisecond)
		os.WriteFile(file, []byte("ok"), 0o644)
	}()
	err := healthGate(context.Background(), file, since, 2*time.Second, 5*time.Millisecond, time.Now)
	if err != nil {
		t.Fatalf("health gate should pass once a fresh file appears: %v", err)
	}
}

func TestHealthGatePassesWhenFileBeatsTheGate(t *testing.T) {
	// The worker may write its health file before the bootstrap reaches the
	// gate; `since` captured before the swap makes that count as fresh.
	file := filepath.Join(t.TempDir(), "worker-health")
	since := time.Now().Add(-time.Second)
	if err := os.WriteFile(file, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := healthGate(context.Background(), file, since, time.Second, 5*time.Millisecond, time.Now)
	if err != nil {
		t.Fatalf("pre-written fresh file must pass: %v", err)
	}
}

func TestHealthGateTimesOutWithoutFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "worker-health")
	start := time.Now()
	err := healthGate(context.Background(), file, start, 100*time.Millisecond, 5*time.Millisecond, time.Now)
	if err == nil {
		t.Fatal("health gate passed with no file — MUST fail")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("health gate did not respect timeout")
	}
}

func TestHealthGateRejectsStaleFile(t *testing.T) {
	// A leftover health file with an mtime older than the gate epoch is the
	// old worker's, not the new one's: it must not pass the gate.
	dir := t.TempDir()
	file := filepath.Join(dir, "worker-health")
	if err := os.WriteFile(file, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(file, past, past); err != nil {
		t.Fatal(err)
	}
	since := time.Now()
	err := healthGate(context.Background(), file, since, 100*time.Millisecond, 5*time.Millisecond, time.Now)
	if err == nil {
		t.Fatal("stale health file passed the gate — MUST fail")
	}
}

func TestHealthGateInjectedClock(t *testing.T) {
	// Deadline evaluation uses the injected clock: jumping it past the
	// deadline times the gate out immediately, with no real waiting.
	file := filepath.Join(t.TempDir(), "worker-health")
	base := time.Now()
	var jumped atomic.Bool
	now := func() time.Time {
		if jumped.Load() {
			return base.Add(time.Hour)
		}
		return base
	}
	jumped.Store(true)
	start := time.Now()
	err := healthGate(context.Background(), file, base, 10*time.Minute, time.Millisecond, now)
	if err == nil {
		t.Fatal("expected timeout from injected clock")
	}
	if time.Since(start) > time.Second {
		t.Fatal("injected clock timeout took real time")
	}
}

func TestHealthGateContextCancel(t *testing.T) {
	file := filepath.Join(t.TempDir(), "worker-health")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	err := healthGate(ctx, file, time.Now(), time.Hour, 5*time.Millisecond, time.Now)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}
