package relay

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"geneza.io/internal/wire"
)

// A draining relay refuses every NEW rendezvous (it is shedding for a swap) but
// keeps serving the splices already matched before the drain.
func TestDrainRefusesNewKeepsInFlight(t *testing.T) {
	cfg := testConfig()
	cfg.IdleTimeout = 5 * time.Second
	r, addr := startRelay(t, cfg)

	// Match a pair BEFORE draining; this splice must survive the drain.
	live := newToken(t)
	ci := dialHello(t, addr, live, wire.RoleInitiator)
	cr := dialHello(t, addr, live, wire.RoleResponder)
	for name, c := range map[string]net.Conn{"initiator": ci, "responder": cr} {
		if resp, err := readResp(t, c, 2*time.Second); err != nil || !resp.OK {
			t.Fatalf("%s pre-drain match: resp=%+v err=%v", name, resp, err)
		}
	}

	r.Drain()
	if !r.Draining() {
		t.Fatal("relay should report draining after Drain()")
	}
	select {
	case <-r.DrainSignal():
	default:
		t.Fatal("DrainSignal must be closed after Drain()")
	}

	// A NEW rendezvous is refused outright while draining.
	nc := dialHello(t, addr, newToken(t), wire.RoleInitiator)
	resp, err := readResp(t, nc, 2*time.Second)
	if err != nil {
		t.Fatalf("new rendezvous read: %v", err)
	}
	if resp.OK || resp.Error != "relay draining" {
		t.Fatalf("new rendezvous while draining: resp=%+v, want refused with \"relay draining\"", resp)
	}

	// The in-flight splice still copies both ways after the drain.
	if _, err := ci.Write([]byte("post-drain-payload")); err != nil {
		t.Fatalf("in-flight write: %v", err)
	}
	buf := make([]byte, len("post-drain-payload"))
	cr.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(cr, buf); err != nil {
		t.Fatalf("in-flight read after drain: %v", err)
	}
	if string(buf) != "post-drain-payload" {
		t.Fatalf("in-flight splice corrupted after drain: %q", buf)
	}
}

// Active counts the relay's live splices, and a draining relay's count falls back to
// 0 once its in-flight pair finishes — the drained-gate signal a rollout waits on.
func TestActiveCountReachesZeroOnDrain(t *testing.T) {
	cfg := testConfig()
	cfg.IdleTimeout = 5 * time.Second
	r, addr := startRelay(t, cfg)

	if got := r.Active(); got != 0 {
		t.Fatalf("idle relay Active()=%d, want 0", got)
	}
	tok := newToken(t)
	ci := dialHello(t, addr, tok, wire.RoleInitiator)
	cr := dialHello(t, addr, tok, wire.RoleResponder)
	for _, c := range []net.Conn{ci, cr} {
		if resp, err := readResp(t, c, 2*time.Second); err != nil || !resp.OK {
			t.Fatalf("match: resp=%+v err=%v", resp, err)
		}
	}
	// The matched splice registers as one unit of live work.
	waitFor(t, 2*time.Second, func() bool { return r.Active() == 1 })

	r.Drain()
	if r.Active() != 1 {
		t.Fatalf("draining must KEEP the in-flight splice: Active()=%d, want 1", r.Active())
	}
	// Closing both ends ends the splice; the count drains to 0 — the gate a swap waits on.
	ci.Close()
	cr.Close()
	waitFor(t, 2*time.Second, func() bool { return r.Active() == 0 })
}

// A draining relay rewrites its drain-status file with the live active count, so a
// bootstrap can poll "draining=true active=0" before swapping the binary.
func TestDrainStatusFileReportsCount(t *testing.T) {
	cfg := testConfig()
	cfg.IdleTimeout = 5 * time.Second
	r, addr := startRelay(t, cfg)

	statusFile := filepath.Join(t.TempDir(), "relay-drain.status")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunDrainStatusFile(ctx, statusFile, r, slog.New(slog.DiscardHandler))

	// Before draining the file exists and reports not-draining (so a poller never
	// misreads an absent file).
	waitFor(t, 2*time.Second, func() bool {
		b, err := os.ReadFile(statusFile)
		return err == nil && strings.Contains(string(b), "draining=false")
	})

	tok := newToken(t)
	ci := dialHello(t, addr, tok, wire.RoleInitiator)
	cr := dialHello(t, addr, tok, wire.RoleResponder)
	for _, c := range []net.Conn{ci, cr} {
		if resp, err := readResp(t, c, 2*time.Second); err != nil || !resp.OK {
			t.Fatalf("match: resp=%+v err=%v", resp, err)
		}
	}
	r.Drain()
	// While draining with a live splice the file reports active=1.
	waitFor(t, 2*time.Second, func() bool {
		b, _ := os.ReadFile(statusFile)
		return strings.Contains(string(b), "draining=true") && strings.Contains(string(b), "active=1")
	})
	// Once the splice ends the file reports active=0 — the drained gate.
	ci.Close()
	cr.Close()
	waitFor(t, 2*time.Second, func() bool {
		b, _ := os.ReadFile(statusFile)
		return strings.Contains(string(b), "draining=true") && strings.Contains(string(b), "active=0")
	})
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", d)
}

// Drain is idempotent and safe to call before Serve (the flag is read on every new
// connection and by the registrar).
func TestDrainIdempotent(t *testing.T) {
	r := New(testConfig(), slog.New(slog.DiscardHandler))
	r.Drain()
	r.Drain() // must not panic on the second close
	if !r.Draining() {
		t.Fatal("still draining after repeated Drain()")
	}
	select {
	case <-r.DrainSignal():
	default:
		t.Fatal("DrainSignal must be closed after Drain()")
	}
}
