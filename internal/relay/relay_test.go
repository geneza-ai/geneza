package relay

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"geneza.io/internal/types"
	"geneza.io/internal/wire"
)

func testConfig() Config {
	cfg := DefaultConfig()
	cfg.Listen = "127.0.0.1:0"
	cfg.TLS = false // unit tests only; production is always TLS
	cfg.MatchTTL = 500 * time.Millisecond
	cfg.IdleTimeout = 2 * time.Second
	cfg.HelloTimeout = time.Second
	cfg.StatsPeriod = time.Hour // keep stats noise out of tests
	cfg.DrainTimeout = time.Second
	cfg.MaxPending = 8
	return cfg
}

func startRelay(t *testing.T, cfg Config) (*Relay, string) {
	t.Helper()
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := New(cfg, slog.New(slog.DiscardHandler))
	go r.Serve(ln) //nolint:errcheck // returns ErrClosed on shutdown
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = r.Shutdown(ctx)
	})
	return r, ln.Addr().String()
}

func newToken(t *testing.T) string {
	t.Helper()
	tok, err := types.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	return tok
}

// dialHello connects, sends a hello, and returns the conn without waiting
// for the response (the response only arrives once a peer matches).
func dialHello(t *testing.T, addr, token, role string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := wire.WriteJSON(c, wire.RelayHello{V: 1, Token: token, Role: role}); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	return c
}

func readResp(t *testing.T, c net.Conn, timeout time.Duration) (wire.RelayResp, error) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(timeout))
	var resp wire.RelayResp
	err := wire.ReadJSON(c, &resp)
	c.SetReadDeadline(time.Time{})
	return resp, err
}

// waitPending blocks until the relay holds at least n waiting endpoints.
// dialHello returns once the hello is written, before the relay has processed
// it, so a test that needs a specific later conn to be the one rejected must
// first wait for the conns it races against to actually register — otherwise
// goroutine ordering decides which conn wins the pending slot, and the loser
// sits unmatched until the match-TTL reaper closes it (read as a bare EOF, not
// the expected rejection).
func waitPending(t *testing.T, r *Relay, n int) {
	t.Helper()
	for i := 0; i < 400; i++ { // up to ~2s
		r.mu.Lock()
		got := len(r.pending)
		r.mu.Unlock()
		if got >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("relay never reached %d pending registration(s)", n)
}

func TestPairAndSpliceBothWays(t *testing.T) {
	_, addr := startRelay(t, testConfig())
	token := newToken(t)

	ci := dialHello(t, addr, token, wire.RoleInitiator)
	cr := dialHello(t, addr, token, wire.RoleResponder)

	for name, c := range map[string]net.Conn{"initiator": ci, "responder": cr} {
		resp, err := readResp(t, c, 2*time.Second)
		if err != nil {
			t.Fatalf("%s: read resp: %v", name, err)
		}
		if !resp.OK || resp.Error != "" {
			t.Fatalf("%s: resp = %+v, want OK", name, resp)
		}
	}

	// Raw opaque bytes both ways: the relay must copy without framing.
	send := func(from, to net.Conn, payload string) {
		t.Helper()
		if _, err := from.Write([]byte(payload)); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, len(payload))
		to.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(to, buf); err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buf) != payload {
			t.Fatalf("got %q, want %q", buf, payload)
		}
	}
	send(ci, cr, "noise-msg-1-from-initiator")
	send(cr, ci, "noise-msg-2-from-responder")
	send(ci, cr, "more \x00\xff binary bytes")

	// Closing one side tears down the other.
	ci.Close()
	cr.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := cr.Read(make([]byte, 1)); err == nil {
		t.Fatal("responder conn still open after initiator close")
	}
}

func TestDuplicateRoleRejected(t *testing.T) {
	cfg := testConfig()
	cfg.MatchTTL = 30 * time.Second // assert rejection + that the original still matches, not reaping
	r, addr := startRelay(t, cfg)
	token := newToken(t)

	first := dialHello(t, addr, token, wire.RoleInitiator)
	waitPending(t, r, 1) // serialize: `dup` must race in only after `first` holds the slot
	dup := dialHello(t, addr, token, wire.RoleInitiator)

	resp, err := readResp(t, dup, 2*time.Second)
	if err != nil {
		t.Fatalf("dup resp: %v", err)
	}
	if resp.OK || resp.Error == "" {
		t.Fatalf("dup resp = %+v, want error", resp)
	}

	// The original waiter must be unaffected and still able to match.
	cr := dialHello(t, addr, token, wire.RoleResponder)
	for name, c := range map[string]net.Conn{"first": first, "responder": cr} {
		resp, err := readResp(t, c, 2*time.Second)
		if err != nil || !resp.OK {
			t.Fatalf("%s: resp=%+v err=%v, want OK", name, resp, err)
		}
	}
}

func TestUnmatchedTokenExpires(t *testing.T) {
	cfg := testConfig()
	cfg.MatchTTL = 150 * time.Millisecond
	r, addr := startRelay(t, cfg)
	token := newToken(t)

	c := dialHello(t, addr, token, wire.RoleResponder)

	// The slot must expire and the conn must be closed without an OK.
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected conn closed after match_ttl")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("conn not closed within deadline (slot never expired)")
	}

	r.mu.Lock()
	waiting := len(r.pending)
	r.mu.Unlock()
	if waiting != 0 {
		t.Fatalf("pending table has %d slots, want 0", waiting)
	}
}

func TestTokenIsSingleUse(t *testing.T) {
	_, addr := startRelay(t, testConfig())
	token := newToken(t)

	ci := dialHello(t, addr, token, wire.RoleInitiator)
	cr := dialHello(t, addr, token, wire.RoleResponder)
	for _, c := range []net.Conn{ci, cr} {
		if resp, err := readResp(t, c, 2*time.Second); err != nil || !resp.OK {
			t.Fatalf("first match: resp=%+v err=%v", resp, err)
		}
	}

	// A replayed hello with the consumed token must be rejected outright —
	// it must neither wait nor pair, even with a fresh opposite-role peer.
	replay := dialHello(t, addr, token, wire.RoleInitiator)
	resp, err := readResp(t, replay, 2*time.Second)
	if err != nil {
		t.Fatalf("replay resp: %v", err)
	}
	if resp.OK || resp.Error == "" {
		t.Fatalf("replay resp = %+v, want rejection", resp)
	}
}

func TestGarbageAndOversizedHelloRejected(t *testing.T) {
	cases := []struct {
		name string
		send func(t *testing.T, c net.Conn)
	}{
		{"garbage json", func(t *testing.T, c net.Conn) {
			if err := wire.WriteFrame(c, []byte("not json at all")); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized frame header", func(t *testing.T, c net.Conn) {
			var hdr [4]byte
			binary.BigEndian.PutUint32(hdr[:], uint32(wire.MaxFrame+1))
			if _, err := c.Write(hdr[:]); err != nil {
				t.Fatal(err)
			}
		}},
		{"wrong version", func(t *testing.T, c net.Conn) {
			tok := newToken(t)
			_ = wire.WriteJSON(c, wire.RelayHello{V: 2, Token: tok, Role: "i"})
		}},
		{"bad role", func(t *testing.T, c net.Conn) {
			tok := newToken(t)
			_ = wire.WriteJSON(c, wire.RelayHello{V: 1, Token: tok, Role: "x"})
		}},
		{"bad token prefix", func(t *testing.T, c net.Conn) {
			_ = wire.WriteJSON(c, wire.RelayHello{V: 1, Token: "zz-0123456789abcdef0123456789abcdef", Role: "i"})
		}},
		{"token too short", func(t *testing.T, c net.Conn) {
			_ = wire.WriteJSON(c, wire.RelayHello{V: 1, Token: "gz-abc", Role: "i"})
		}},
		{"token bad charset", func(t *testing.T, c net.Conn) {
			_ = wire.WriteJSON(c, wire.RelayHello{V: 1, Token: "gz-XYZ!456789abcdef0123456789abcdef", Role: "i"})
		}},
	}
	r, addr := startRelay(t, testConfig())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer c.Close()
			tc.send(t, c)

			// The relay must never answer OK and must close the conn.
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			var resp wire.RelayResp
			if err := wire.ReadJSON(c, &resp); err == nil {
				if resp.OK {
					t.Fatalf("got OK for %s", tc.name)
				}
			}
			if _, err := c.Read(make([]byte, 1)); err == nil {
				t.Fatal("conn left open after rejection")
			}
		})
	}
	r.mu.Lock()
	waiting := len(r.pending)
	r.mu.Unlock()
	if waiting != 0 {
		t.Fatalf("rejected hellos left %d pending slots", waiting)
	}
}

func TestSilentDialerReaped(t *testing.T) {
	cfg := testConfig()
	cfg.HelloTimeout = 150 * time.Millisecond
	_, addr := startRelay(t, cfg)

	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	// Send nothing: the hello deadline must close the conn. The relay may
	// emit a rejection frame first, so drain until EOF; a client-side read
	// timeout means the relay never closed it.
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadAll(c); err != nil {
		t.Fatalf("silent conn still open after hello timeout: %v", err)
	}
}

func TestIdleSpliceReaped(t *testing.T) {
	cfg := testConfig()
	cfg.IdleTimeout = 200 * time.Millisecond
	_, addr := startRelay(t, cfg)
	token := newToken(t)

	ci := dialHello(t, addr, token, wire.RoleInitiator)
	cr := dialHello(t, addr, token, wire.RoleResponder)
	for _, c := range []net.Conn{ci, cr} {
		if resp, err := readResp(t, c, 2*time.Second); err != nil || !resp.OK {
			t.Fatalf("match: resp=%+v err=%v", resp, err)
		}
	}

	// No traffic at all: both sides must be closed within ~idle_timeout.
	ci.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := ci.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle splice not reaped")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("idle splice still open well past idle_timeout")
	}
}

func TestMaxPendingRejects(t *testing.T) {
	cfg := testConfig()
	cfg.MaxPending = 2
	cfg.MatchTTL = 30 * time.Second // keep the two waiters pending so the 3rd is the one rejected
	r, addr := startRelay(t, cfg)

	dialHello(t, addr, newToken(t), wire.RoleInitiator)
	dialHello(t, addr, newToken(t), wire.RoleInitiator)
	waitPending(t, r, 2) // both slots must be filled before the over-capacity conn dials
	over := dialHello(t, addr, newToken(t), wire.RoleInitiator)

	resp, err := readResp(t, over, 2*time.Second)
	if err != nil {
		t.Fatalf("over-capacity resp: %v", err)
	}
	if resp.OK || resp.Error == "" {
		t.Fatalf("over-capacity resp = %+v, want rejection", resp)
	}
}

func TestShutdownClosesWaiters(t *testing.T) {
	cfg := testConfig()
	cfg.MatchTTL = time.Hour // ensure it is shutdown, not expiry, that closes
	r, addr := startRelay(t, cfg)

	c := dialHello(t, addr, newToken(t), wire.RoleInitiator)
	// Give the relay a moment to park the slot.
	deadline := time.Now().Add(time.Second)
	for {
		r.mu.Lock()
		n := len(r.pending)
		r.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slot never registered")
		}
		time.Sleep(5 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := r.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("waiting conn survived shutdown")
	}

	// New connections must be refused (listener closed).
	if cn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond); err == nil {
		// Dial may succeed momentarily on some stacks; the conn must die.
		cn.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := cn.Read(make([]byte, 1)); err == nil {
			t.Fatal("relay still serving after shutdown")
		}
		cn.Close()
	}
}
