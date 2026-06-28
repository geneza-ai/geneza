package agentd

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"geneza.io/internal/wire"
)

// fakeRelay accepts funnel-reg (acks, then signals one dial-back) and funnel-data
// (acks, then hands the conn to publicData as the "public side").
func fakeRelay(ln net.Listener, publicData chan net.Conn) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			var h wire.RelayHello
			if err := wire.ReadJSON(c, &h); err != nil {
				c.Close()
				return
			}
			switch h.Kind {
			case wire.RelayKindFunnelReg:
				_ = wire.WriteJSON(c, wire.RelayResp{OK: true})
				_ = wire.WriteJSON(c, wire.FunnelDial{Token: "fz-test"})
				io.Copy(io.Discard, c) // drain keepalives until close
			case wire.RelayKindFunnelData:
				_ = wire.WriteJSON(c, wire.RelayResp{OK: true})
				publicData <- c // hand the public side to the test; do not close
			default:
				c.Close()
			}
		}(c)
	}
}

func TestSafeLocalDialRefusesLinkLocal(t *testing.T) {
	// Cloud metadata + link-local must be refused even if the controller pushes them.
	for _, target := range []string{"169.254.169.254:80", "169.254.0.1:8080", "0.0.0.0:80"} {
		if c, err := safeLocalDial(context.Background(), target); err == nil {
			if c != nil {
				c.Close()
			}
			t.Errorf("%s should be refused", target)
		}
	}
	// A loopback target (the normal funnel case) is allowed.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { c, _ := ln.Accept(); _ = c }()
	c, err := safeLocalDial(context.Background(), ln.Addr().String())
	if err != nil {
		t.Errorf("loopback funnel target should be allowed: %v", err)
	}
	if c != nil {
		c.Close()
	}
}

func TestFunnelClientProxies(t *testing.T) {
	// Local echo service the funnel proxies to.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()

	relayLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relayLn.Close()
	publicData := make(chan net.Conn, 1)
	go fakeRelay(relayLn, publicData)

	fc := &funnelClient{
		log:       slog.Default(),
		relayAddr: relayLn.Addr().String(),
		hostname:  "app.acme.geneza.app",
		target:    echoLn.Addr().String(),
		relayDial: func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fc.run(ctx)

	// The client should register, get the dial-back, and splice a data leg to the
	// echo; the fake relay hands us that data leg as the public side.
	select {
	case dc := <-publicData:
		defer dc.Close()
		dc.SetDeadline(time.Now().Add(5 * time.Second))
		const msg = "hello-via-funnel-client"
		if _, err := dc.Write([]byte(msg)); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(dc, buf); err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buf) != msg {
			t.Fatalf("echo mismatch: %q", buf)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("funnel client never dialed back / proxied")
	}
}
