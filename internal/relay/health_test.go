package relay

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestServingReadiness proves the bootstrap readiness signal: once the relay's
// listener is bound and accepting, the OnServing hook fires (exactly once) and
// the health file the supervising bootstrap gates on appears fresh.
func TestServingReadiness(t *testing.T) {
	cfg := testConfig()
	healthFile := filepath.Join(t.TempDir(), "worker.health")

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := New(cfg, slog.New(slog.DiscardHandler))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fired := make(chan struct{}, 4)
	r.SetOnServing(func() {
		fired <- struct{}{}
		go RunHealthFile(ctx, healthFile, slog.New(slog.DiscardHandler))
	})

	go r.Serve(ln) //nolint:errcheck
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer scancel()
		_ = r.Shutdown(sctx)
	})

	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("OnServing never fired after the listener was serving")
	}

	// The health file must appear (written by RunHealthFile on serving).
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(healthFile); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("relay health file was never written after serving")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The hook is one-shot: no second fire even though Serve set serving once.
	select {
	case <-fired:
		t.Fatal("OnServing fired more than once")
	case <-time.After(100 * time.Millisecond):
	}
}

// TestHealthFileDisabledNoWrite: an empty health file path (the bare-service,
// non-bootstrap-supervised deployment) writes nothing.
func TestHealthFileDisabledNoWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	RunHealthFile(ctx, "", slog.New(slog.DiscardHandler)) // returns immediately, writes nothing
}

func TestConfigHealthFile(t *testing.T) {
	p := writeTemp(t, `listen: "127.0.0.1:7403"
tls: false
health_file: "/run/geneza/worker.health"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HealthFile != "/run/geneza/worker.health" {
		t.Fatalf("HealthFile = %q", cfg.HealthFile)
	}
}
