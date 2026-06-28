package sessionhost

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func readDrainFile(t *testing.T, path string) (draining bool, active int, ok bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return false, 0, false
	}
	for _, f := range strings.Fields(string(data)) {
		k, v, found := strings.Cut(f, "=")
		if !found {
			continue
		}
		switch k {
		case "draining":
			draining = v == "true"
		case "active":
			active, _ = strconv.Atoi(v)
		}
	}
	return draining, active, true
}

func TestDrainRejectsNewSessions(t *testing.T) {
	h := newHost("vtest", t.TempDir())
	// Before draining, the drain guard does not fire (Create may fail later for an
	// invalid request, but NOT with Unavailable).
	if _, err := h.Create(context.Background(), &genezav1.HostCreateRequest{}); status.Code(err) == codes.Unavailable {
		t.Fatal("Create rejected as draining before drain started")
	}
	h.startDrain()
	if !h.Draining() {
		t.Fatal("Draining() false after startDrain")
	}
	_, err := h.Create(context.Background(), &genezav1.HostCreateRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("Create after drain = %v, want Unavailable", err)
	}
}

func TestDrainIdempotent(t *testing.T) {
	h := newHost("vtest", t.TempDir())
	h.startDrain()
	h.startDrain() // must not panic on a double close of drainCh
	select {
	case <-h.drainCh:
	default:
		t.Fatal("drainCh not closed after startDrain")
	}
}

func TestDrainStatusFile(t *testing.T) {
	h := newHost("vtest", t.TempDir())
	statusFile := t.TempDir() + "/drain.status"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.runDrainStatusFile(ctx, statusFile)

	// Pre-drain: the file is written once with draining=false so the bootstrap
	// never misreads an absent file as drained.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if d, _, ok := readDrainFile(t, statusFile); ok {
			if d {
				t.Fatal("pre-drain status reports draining=true")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("drain-status file never written pre-drain")
		}
		time.Sleep(20 * time.Millisecond)
	}

	h.activeN.Store(2)
	h.startDrain()
	deadline = time.Now().Add(2 * time.Second)
	for {
		if d, a, ok := readDrainFile(t, statusFile); ok && d && a == 2 {
			return // drained file reports draining=true active=2
		}
		if time.Now().After(deadline) {
			d, a, _ := readDrainFile(t, statusFile)
			t.Fatalf("drain-status did not report draining=true active=2 (got draining=%v active=%d)", d, a)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A non-interactive session has no terminal, so the drain banner must be skipped
// (injecting would corrupt its byte stream) — and never panic.
func TestDrainNoticeSkipsPipeSession(t *testing.T) {
	s := &session{ptyMode: false}
	s.sendDrainNotice() // no terminal: no-op, must not panic
}
