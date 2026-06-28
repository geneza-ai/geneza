package relay

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"geneza.io/internal/types"
	"geneza.io/internal/wire"
)

// TestRelayLoadSplice drives many concurrent splice pairs through the real relay
// and reports aggregate goodput, per-splice fairness, setup latency and the
// small-frame (per-iteration deadline) tax. It is a load scenario, not a unit
// test — gated behind GENEZA_LOADTEST so the normal suite skips it.
//
//	GENEZA_LOADTEST=1 go test ./internal/relay -run TestRelayLoadSplice -v -timeout 20m
func TestRelayLoadSplice(t *testing.T) {
	if os.Getenv("GENEZA_LOADTEST") == "" {
		t.Skip("set GENEZA_LOADTEST=1 to run the relay load scenario")
	}
	cfg := DefaultConfig()
	cfg.Listen = "127.0.0.1:0"
	cfg.TLS = false
	cfg.MatchTTL = 60 * time.Second
	cfg.IdleTimeout = 120 * time.Second
	cfg.HelloTimeout = 15 * time.Second
	cfg.StatsPeriod = time.Hour
	cfg.DrainTimeout = 2 * time.Second
	cfg.MaxPending = 8192 // conn cap = MaxPending*16 = 131072

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	r := New(cfg, slog.New(slog.DiscardHandler))
	go r.Serve(ln) //nolint:errcheck
	defer ln.Close()
	addr := ln.Addr().String()

	const dur = 3 * time.Second
	t.Logf("relay splice load (loopback, TLS off), %s per point", dur)
	t.Logf("%-7s %-9s %-12s %-14s %-14s %-14s", "PAIRS", "FRAME", "SETUP", "AGG-GOODPUT", "PER-PAIR-med", "PER-PAIR-min")
	for _, frame := range []int{65536, 512} {
		for _, n := range []int{64, 256, 1024, 4096} {
			runRelayLoad(t, addr, n, frame, dur)
		}
	}
}

func loadDial(addr, token, role string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return nil, err
	}
	if err := wire.WriteJSON(c, wire.RelayHello{V: 1, Token: token, Role: role}); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func runRelayLoad(t *testing.T, addr string, n, frame int, dur time.Duration) {
	t.Helper()
	type pair struct{ ini, resp net.Conn }
	pairs := make([]pair, 0, n)
	setupStart := time.Now()
	for i := 0; i < n; i++ {
		tok, err := types.NewToken()
		if err != nil {
			t.Fatal(err)
		}
		ini, err := loadDial(addr, tok, wire.RoleInitiator)
		if err != nil {
			t.Fatalf("dial initiator %d: %v", i, err)
		}
		resp, err := loadDial(addr, tok, wire.RoleResponder)
		if err != nil {
			t.Fatalf("dial responder %d: %v", i, err)
		}
		pairs = append(pairs, pair{ini, resp})
	}
	// Drain the OK response on both ends (sent once a pair is matched + spliced).
	for i, p := range pairs {
		for _, c := range []net.Conn{p.ini, p.resp} {
			c.SetReadDeadline(time.Now().Add(30 * time.Second))
			var rr wire.RelayResp
			if err := wire.ReadJSON(c, &rr); err != nil || !rr.OK {
				t.Fatalf("pair %d not matched: err=%v ok=%v", i, err, rr.OK)
			}
			c.SetReadDeadline(time.Time{})
		}
	}
	setup := time.Since(setupStart)

	// Stream initiator -> responder for dur; the writer stops on the deadline and
	// closes, the reader counts bytes until the relay closes its side (EOF).
	deadline := time.Now().Add(dur)
	perPair := make([]int64, n)
	var wg sync.WaitGroup
	streamStart := time.Now()
	for i := range pairs {
		p := pairs[i]
		idx := i
		wg.Add(2)
		go func() { // writer
			defer wg.Done()
			buf := make([]byte, frame)
			for time.Now().Before(deadline) {
				if _, err := p.ini.Write(buf); err != nil {
					return
				}
			}
			p.ini.Close()
		}()
		go func() { // reader
			defer wg.Done()
			n, _ := io.Copy(io.Discard, p.resp)
			atomic.StoreInt64(&perPair[idx], n)
			p.resp.Close()
		}()
	}
	wg.Wait()
	elapsed := time.Since(streamStart)

	var total int64
	rates := make([]float64, n)
	for i, b := range perPair {
		total += b
		rates[i] = float64(b) / elapsed.Seconds()
	}
	sort.Float64s(rates)
	agg := float64(total) / elapsed.Seconds()
	med := rates[n/2]
	min := rates[0]
	t.Logf("%-7d %-9s %-12s %-14s %-14s %-14s", n, frameName(frame),
		setup.Round(time.Millisecond), mbps(agg), mbps(med), mbps(min))
}

func frameName(f int) string {
	if f >= 1024 {
		return fmt.Sprintf("%dK", f/1024)
	}
	return fmt.Sprintf("%dB", f)
}

func mbps(bytesPerSec float64) string {
	bits := bytesPerSec * 8
	switch {
	case bits >= 1e9:
		return fmt.Sprintf("%.2f Gbit/s", bits/1e9)
	case bits >= 1e6:
		return fmt.Sprintf("%.0f Mbit/s", bits/1e6)
	default:
		return fmt.Sprintf("%.0f Kbit/s", bits/1e3)
	}
}
