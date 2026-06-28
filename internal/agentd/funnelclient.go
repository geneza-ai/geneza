package agentd

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"time"

	"geneza.io/internal/wire"
)

// dialRelayFunnel dials a relay's rendezvous endpoint with TLS, pinning the relay
// leaf to the signed fleet (same pin set the control-mux dial uses). The funnel
// client sends its own funnel hello after; the relay sees only SNI + ciphertext
// on this leg until it terminates the public TLS at its funnel listener.
func (w *Worker) dialRelayFunnel(ctx context.Context, addr string) (net.Conn, error) {
	tlsCfg := &tls.Config{RootCAs: w.rootPool(), MinVersion: tls.VersionTLS12}
	if pins := w.relayCertPubs(); len(pins) > 0 {
		tlsCfg.VerifyPeerCertificate = pinRelayCert(pins)
	}
	d := &tls.Dialer{Config: tlsCfg}
	return d.DialContext(ctx, "tcp", addr)
}

// funnelClient maintains an agent's funnel registration with ONE relay for ONE
// hostname and serves the per-request dial-backs. The agent dials OUT to the
// relay (no inbound), registers "I serve Host", and whenever the relay signals a
// public client arrived, dials a data connection back and splices it to the
// local target. The agent — never the relay — reaches the actual service, so a
// compromised relay can pivot to nothing but this one local target.
type funnelClient struct {
	log       *slog.Logger
	relayAddr string
	hostname  string
	target    string // local host:port the agent proxies funnel traffic to
	regToken  string // controller-minted secret authorizing this registration
	// relayDial dials the relay's rendezvous endpoint (TLS + relay-cert pin in
	// production; injected so tests can use a plain dialer).
	relayDial func(ctx context.Context, addr string) (net.Conn, error)
	// localDial dials the local target (defaults to a plain net dialer).
	localDial func(ctx context.Context, addr string) (net.Conn, error)
}

// run keeps the registration up, reconnecting with backoff until ctx is done.
func (fc *funnelClient) run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		if err := fc.session(ctx); err != nil && ctx.Err() == nil {
			fc.log.Debug("funnel registration ended", "host", fc.hostname, "relay", fc.relayAddr, "err", err)
		}
		if time.Since(start) > 30*time.Second {
			backoff = time.Second // a long-lived registration resets the backoff
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 15*time.Second {
			backoff *= 2
		}
	}
}

// session registers once and serves dial-backs until the connection drops.
func (fc *funnelClient) session(ctx context.Context) error {
	conn, err := fc.relayDial(ctx, fc.relayAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	// Close the conn when the route ctx is cancelled, so the blocking ReadJSON
	// below returns promptly instead of leaking until the relay's idle reaper.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := wire.WriteJSON(conn, wire.RelayHello{V: 1, Kind: wire.RelayKindFunnelReg, Host: fc.hostname, RegToken: fc.regToken}); err != nil {
		return err
	}
	var resp wire.RelayResp
	if err := wire.ReadJSON(conn, &resp); err != nil {
		return err
	}
	if !resp.OK {
		return &funnelRejected{resp.Error}
	}
	conn.SetDeadline(time.Time{})
	fc.log.Info("funnel registered", "host", fc.hostname, "relay", fc.relayAddr)

	// Keepalive so the relay's idle reaper sees us as alive.
	kctx, kcancel := context.WithCancel(ctx)
	defer kcancel()
	go fc.keepalive(kctx, conn)

	for {
		var fd wire.FunnelDial
		if err := wire.ReadJSON(conn, &fd); err != nil {
			return err
		}
		go fc.handleDial(ctx, fd.Token)
	}
}

func (fc *funnelClient) keepalive(ctx context.Context, conn net.Conn) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := wire.WriteFrame(conn, nil); err != nil {
				return
			}
			conn.SetWriteDeadline(time.Time{})
		}
	}
}

// handleDial answers one relay dial-back: open a data leg, splice it to the local
// target, so the public request reaches the service.
func (fc *funnelClient) handleDial(ctx context.Context, token string) {
	dc, err := fc.relayDial(ctx, fc.relayAddr)
	if err != nil {
		fc.log.Warn("funnel data dial", "host", fc.hostname, "err", err)
		return
	}
	defer dc.Close()
	dc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := wire.WriteJSON(dc, wire.RelayHello{V: 1, Kind: wire.RelayKindFunnelData, Token: token}); err != nil {
		return
	}
	var resp wire.RelayResp
	if err := wire.ReadJSON(dc, &resp); err != nil || !resp.OK {
		return
	}
	dc.SetDeadline(time.Time{})

	dial := fc.localDial
	if dial == nil {
		dial = safeLocalDial
	}
	lc, err := dial(ctx, fc.target)
	if err != nil {
		fc.log.Warn("funnel local dial", "host", fc.hostname, "target", fc.target, "err", err)
		return
	}
	defer lc.Close()
	spliceConns(dc, lc, 5*time.Minute)
}

// safeLocalDial dials a funnel target, refusing addresses an agent should never
// be made to proxy to — cloud metadata / link-local, unspecified, and multicast.
// Loopback and private addresses are allowed (a funnel target is normally a local
// or LAN service). It resolves once and dials the resolved IP literal so a DNS
// rebind cannot move the target after the check (no TOCTOU).
func safeLocalDial(ctx context.Context, target string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	var resolver net.Resolver
	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	for _, ip := range ips {
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
			continue // refuse metadata/link-local/unspecified/multicast
		}
		c, derr := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if derr == nil {
			return c, nil
		}
		err = derr
	}
	if err == nil {
		err = &funnelRejected{"funnel target resolves only to refused addresses"}
	}
	return nil, err
}

// spliceConns copies bytes both ways until either side closes or both go idle for
// the given window (so a doubly-silent splice cannot pin the sockets forever).
func spliceConns(a, b net.Conn, idle time.Duration) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		buf := make([]byte, 32*1024)
		for {
			_ = src.SetReadDeadline(time.Now().Add(idle))
			n, rerr := src.Read(buf)
			if n > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(idle))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		a.Close()
		b.Close()
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

type funnelRejected struct{ msg string }

func (e *funnelRejected) Error() string {
	if e.msg == "" {
		return "funnel registration rejected"
	}
	return e.msg
}
