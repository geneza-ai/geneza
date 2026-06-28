package relay

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"geneza.io/internal/nodeseal"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/wire"
)

func testRelayConfig() Config {
	return Config{
		Listen:        "127.0.0.1:0",
		TLS:           false, // rendezvous in the clear for the test; funnel listener is still TLS
		HelloTimeout:  5 * time.Second,
		MatchTTL:      5 * time.Second,
		IdleTimeout:   10 * time.Second,
		MaxPending:    16,
		MaxControlMux: 16,
		StatsPeriod:   time.Hour,
	}
}

// fakeFunnelAgent registers for host over the relay rendezvous and, on each
// dial-back, opens a data leg and echoes whatever the public side sends.
func fakeFunnelAgent(t *testing.T, relayAddr, host, token string) {
	t.Helper()
	conn, err := net.Dial("tcp", relayAddr)
	if err != nil {
		t.Errorf("agent dial: %v", err)
		return
	}
	if err := wire.WriteJSON(conn, wire.RelayHello{V: 1, Kind: wire.RelayKindFunnelReg, Host: host, RegToken: token}); err != nil {
		t.Errorf("agent register: %v", err)
		return
	}
	var resp wire.RelayResp
	if err := wire.ReadJSON(conn, &resp); err != nil || !resp.OK {
		t.Errorf("agent register resp: %v ok=%v", err, resp.OK)
		return
	}
	for {
		var fd wire.FunnelDial
		if err := wire.ReadJSON(conn, &fd); err != nil {
			return
		}
		go func(token string) {
			dc, err := net.Dial("tcp", relayAddr)
			if err != nil {
				return
			}
			defer dc.Close()
			_ = wire.WriteJSON(dc, wire.RelayHello{V: 1, Kind: wire.RelayKindFunnelData, Token: token})
			var r wire.RelayResp
			if err := wire.ReadJSON(dc, &r); err != nil || !r.OK {
				return
			}
			io.Copy(dc, dc) // echo: the "local service"
		}(fd.Token)
	}
}

func TestFunnelEndToEnd(t *testing.T) {
	const host = "app.acme.geneza.app"
	r := New(testRelayConfig(), slog.Default())

	const regToken = "controller-authorized-secret"
	// Inject a funnel cert for host, sealed to the relay's own key (the controller path).
	sealed, err := nodeseal.Seal(makeBundle(t, host), r.funnel.sealPub())
	if err != nil {
		t.Fatal(err)
	}
	r.funnel.apply([]*genezav1.SealedCert{{Zone: host, Sealed: sealed, Epoch: 1, RegToken: regToken}})

	rdv, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go r.Serve(rdv)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		r.Shutdown(ctx) // force-close drain window so the test exits promptly
	}()

	fln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: r.funnel.GetCertificate})
	if err != nil {
		t.Fatal(err)
	}
	defer fln.Close()
	go r.serveFunnel(fln)

	// An agent with the WRONG token must be rejected (the authz red-line).
	bad, err := net.Dial("tcp", rdv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = wire.WriteJSON(bad, wire.RelayHello{V: 1, Kind: wire.RelayKindFunnelReg, Host: host, RegToken: "wrong"})
	var badResp wire.RelayResp
	if err := wire.ReadJSON(bad, &badResp); err != nil || badResp.OK {
		t.Fatalf("unauthorized registration must be rejected, got resp=%+v err=%v", badResp, err)
	}
	bad.Close()
	if r.funnelReg.get(host) != nil {
		t.Fatal("a rejected registration must not be recorded")
	}

	go fakeFunnelAgent(t, rdv.Addr().String(), host, regToken)

	// Wait for the authorized agent's registration to land on the relay.
	deadline := time.Now().Add(3 * time.Second)
	for r.funnelReg.get(host) == nil {
		if time.Now().After(deadline) {
			t.Fatal("agent never registered with the relay")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Public client: TLS to the funnel listener with SNI=host. The relay selects
	// the cert by SNI, terminates TLS, and splices to the agent → echo.
	pc, err := tls.Dial("tcp", fln.Addr().String(), &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("public dial: %v", err)
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := pc.Write([]byte("ping-through-funnel")); err != nil {
		t.Fatalf("public write: %v", err)
	}
	buf := make([]byte, len("ping-through-funnel"))
	if _, err := io.ReadFull(pc, buf); err != nil {
		t.Fatalf("public read: %v", err)
	}
	if string(buf) != "ping-through-funnel" {
		t.Fatalf("echo mismatch: %q", buf)
	}
}

func TestFunnelUnknownHostHandshakeFails(t *testing.T) {
	r := New(testRelayConfig(), slog.Default())
	// No cert applied → GetCertificate has nothing for any SNI.
	fln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: r.funnel.GetCertificate})
	if err != nil {
		t.Fatal(err)
	}
	defer fln.Close()
	go r.serveFunnel(fln)

	pc, err := tls.Dial("tcp", fln.Addr().String(), &tls.Config{ServerName: "nope.example.com", InsecureSkipVerify: true})
	if err == nil {
		pc.Close()
		t.Fatal("handshake should fail when no funnel cert matches the SNI")
	}
}
