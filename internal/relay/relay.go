package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"geneza.io/internal/wire"
)

// ErrClosed is returned by Serve/ListenAndServe after Shutdown.
var ErrClosed = errors.New("relay: closed")

// controlMuxIdle reaps a control mux that has gone fully silent in BOTH directions.
// It is sized above the inner stream's gRPC keepalive (a healthy mux carries a ping
// every ~15s, so it is never falsely reaped), but far below the long session-idle
// timeout — a half-dead mux is torn by keepalive within ~20s, and a doubly-silent
// one (both ends gone with no FIN/RST, e.g. a relay partitioned from both) is reaped
// here in ~90s instead of lingering as a zombie for the full session idle window.
const controlMuxIdle = 90 * time.Second

// slot is one endpoint waiting for its peer. The accepting goroutine exits
// after registering it; ownership of the conn passes to whichever fires
// first — the match path or the expiry timer.
type slot struct {
	conn  net.Conn
	role  string
	since time.Time
	timer *time.Timer
}

// Relay is the rendezvous server. It is safe for a single Serve loop plus
// concurrent Shutdown.
type Relay struct {
	cfg Config
	log *slog.Logger

	mu      sync.Mutex
	ln      net.Listener
	pending map[string]*slot      // token -> waiting endpoint
	used    map[string]struct{}   // tokens already matched (single-use)
	conns   map[net.Conn]struct{} // ephemeral conns (hello-wait + token splice), capped by MaxPending*16
	// muxConns are the LONG-LIVED control-mux legs (agent + controller), tracked and
	// capped SEPARATELY from conns so durable muxes and brief token splices cannot
	// starve each other's connection budget. Both maps are force-closed on shutdown.
	muxConns map[net.Conn]struct{}
	closed   bool
	serving  bool

	active atomic.Int64 // live splices, for the stats log
	wg     sync.WaitGroup
	done   chan struct{}

	// draining marks the relay as shedding: it keeps serving in-flight splices and
	// control muxes but refuses every NEW rendezvous, and its registrar heartbeat
	// advertises healthy=false so the controller steers new sessions elsewhere. This is
	// a distinct, earlier state than Shutdown: a swap drains first (sessions migrate
	// to healthy relays) and only then force-closes. drainCh is closed once on the
	// first Drain so the registrar breaks its current stream and re-registers unhealthy.
	draining  atomic.Bool
	drainCh   chan struct{}
	drainOnce sync.Once

	turn *turnRelay // embedded pion/turn server: the overlay relay floor (nil if disabled)

	// funnel holds the narrow leaf certs this relay terminates public TLS for,
	// pushed (sealed) by the controller over the registrar watch stream. nil only if
	// key generation failed at startup.
	funnel *funnelCerts
	// funnelReg tracks agent funnel registrations and parked public connections.
	funnelReg *funnelRegistry
	// funnelLn is the public funnel TLS listener (nil if FunnelListen is empty).
	funnelLn net.Listener

	// gwNodeControl is the signed controller-id -> NodeControl dial-address table a
	// control mux routes against, refreshed from the registrar's verified watch.
	// Empty until the relay holds its first signed, signature-verified map, so a
	// control mux fails closed before then.
	gwMu          sync.RWMutex
	gwNodeControl map[string][]string

	// dialControlController dials a controller's NodeControl address for a control mux;
	// the default runs the SSRF safety check then a plain-TCP dial. Tests override
	// it to reach a loopback fake controller without tripping the loopback guard.
	dialControlController func(addr string) (net.Conn, error)

	// onServing, if set, is invoked exactly once the rendezvous listener is bound
	// and accepting — the relay is actually serving. A bootstrap-supervised relay
	// uses it to start writing its update health file, so the bootstrap's health
	// gate sees the new relay come up (and rolls back a relay that never does).
	onServing     func()
	onServingOnce sync.Once
}

// SetOnServing registers a one-shot callback fired when the rendezvous listener
// is bound and accepting. It must be set before Serve/ListenAndServe.
func (r *Relay) SetOnServing(fn func()) { r.onServing = fn }

// New builds a Relay; cfg must already be validated (Load does this).
func New(cfg Config, log *slog.Logger) *Relay {
	if log == nil {
		log = slog.Default()
	}
	r := &Relay{
		cfg:      cfg,
		log:      log,
		pending:  make(map[string]*slot),
		used:     make(map[string]struct{}),
		conns:    make(map[net.Conn]struct{}),
		muxConns: make(map[net.Conn]struct{}),
		done:     make(chan struct{}),
		drainCh:  make(chan struct{}),
	}
	r.dialControlController = r.defaultDialControlController
	r.funnelReg = newFunnelRegistry()
	if fc, err := newFunnelCerts(log); err != nil {
		log.Error("relay: funnel key generation failed; funnel disabled", "err", err)
	} else {
		r.funnel = fc
	}
	return r
}

// ListenAndServe opens the configured listener (TLS unless cfg.TLS is false,
// which is reserved for unit tests) and serves until Shutdown.
func (r *Relay) ListenAndServe() error {
	var ln net.Listener
	var err error
	if r.cfg.TLS {
		var cert tls.Certificate
		cert, err = tls.LoadX509KeyPair(r.cfg.CertFile, r.cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("relay: load TLS keypair: %w", err)
		}
		ln, err = tls.Listen("tcp", r.cfg.Listen, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13, // only Geneza's own Go binaries dial in
		})
	} else {
		r.log.Warn("relay: TLS disabled — test mode only")
		ln, err = net.Listen("tcp", r.cfg.Listen)
	}
	if err != nil {
		return fmt.Errorf("relay: listen %s: %w", r.cfg.Listen, err)
	}
	// Start the embedded pion/turn server (the overlay's blind relay floor)
	// alongside the TCP rendezvous (separate UDP listener; the TCP splice path is
	// untouched). turn.Server runs its own read loop on the socket.
	if r.cfg.DataListen != "" && len(r.cfg.Secrets) > 0 {
		tr, terr := newTURNRelay(r.cfg.DataListen, r.cfg.Realm, r.cfg.Region, r.cfg.Secrets, r.cfg.PublicIP, os.Stderr)
		if terr != nil {
			ln.Close()
			return fmt.Errorf("relay: turn server on %s: %w", r.cfg.DataListen, terr)
		}
		r.mu.Lock()
		r.turn = tr
		r.mu.Unlock()
		r.log.Info("relay: turn floor listening", "addr", r.cfg.DataListen, "realm", r.cfg.Realm, "advertised", r.cfg.PublicIP)
	}
	// Public funnel listener (the one place the relay terminates public TLS), with
	// per-SNI cert selection from the controller-pushed funnel leaves. Always TLS,
	// even when the rendezvous listener is plain (test mode), since it faces the
	// public internet. MinVersion 1.2 because the peers are arbitrary browsers,
	// unlike the internal-only 1.3 rendezvous floor.
	if r.cfg.FunnelListen != "" && r.funnel != nil {
		fln, ferr := tls.Listen("tcp", r.cfg.FunnelListen, &tls.Config{
			GetCertificate: r.funnel.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		})
		if ferr != nil {
			ln.Close()
			return fmt.Errorf("relay: funnel listen %s: %w", r.cfg.FunnelListen, ferr)
		}
		r.mu.Lock()
		r.funnelLn = fln
		r.mu.Unlock()
		r.wg.Add(1)
		go func() { defer r.wg.Done(); r.serveFunnel(fln) }()
		r.log.Info("relay: funnel listener", "addr", r.cfg.FunnelListen)
	}
	return r.Serve(ln)
}

// Serve accepts connections on ln until Shutdown or a fatal accept error.
// It takes ownership of ln.
func (r *Relay) Serve(ln net.Listener) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		ln.Close()
		return ErrClosed
	}
	r.ln = ln
	startStats := !r.serving
	r.serving = true
	r.mu.Unlock()

	if startStats {
		r.wg.Add(1)
		go r.statsLoop()
	}
	// The listener is bound and the accept loop is about to run: the relay is
	// serving. Fire the readiness hook once so a supervising bootstrap can start
	// gating on the relay's health file.
	if r.onServing != nil {
		r.onServingOnce.Do(r.onServing)
	}
	r.log.Info("relay: listening", "addr", ln.Addr().String(), "tls", r.cfg.TLS)

	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-r.done:
				return ErrClosed
			default:
			}
			// Transient accept errors (EMFILE etc.) must not kill the relay.
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return fmt.Errorf("relay: accept: %w", err)
		}
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			c.Close()
			return ErrClosed
		}
		// Global connection cap: bound total in-flight conns (hello-wait +
		// splice) so a pre-hello / slowloris flood cannot exhaust sockets and
		// goroutines. Derived from MaxPending; shed load past the cap.
		maxConns := r.cfg.MaxPending * 16
		if maxConns <= 0 {
			maxConns = 16384
		}
		if len(r.conns) >= maxConns {
			r.mu.Unlock()
			c.Close()
			r.log.Warn("relay: connection cap reached, shedding", "cap", maxConns)
			continue
		}
		r.conns[c] = struct{}{}
		r.mu.Unlock()
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer r.untrack(c)
			r.handleConn(c)
		}()
	}
}

// Addr reports the bound listener address (nil before Serve), for tests.
func (r *Relay) Addr() net.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ln == nil {
		return nil
	}
	return r.ln.Addr()
}

// Drain puts the relay into the draining state: it keeps serving every in-flight
// splice and control mux but refuses NEW rendezvous, and signals the registrar to
// re-register with healthy=false so the controller stops minting new sessions onto it.
// It does NOT stop the listener (a draining relay still answers, only to reject new
// work) — Shutdown is the later, force-closing step. Idempotent; safe before Serve
// (the flag is read on every new connection and by the registrar).
func (r *Relay) Drain() {
	r.draining.Store(true)
	r.drainOnce.Do(func() { close(r.drainCh) })
	r.log.Info("relay: draining — refusing new rendezvous, serving in-flight")
}

// Draining reports whether the relay is shedding new work.
func (r *Relay) Draining() bool { return r.draining.Load() }

// Active reports the relay's live work count: in-flight token splices plus
// established control-mux pairs. It is the drained-gate signal — once a draining
// relay reaches 0 its sessions have migrated off and the binary is safe to swap.
func (r *Relay) Active() int64 { return r.active.Load() }

// DrainSignal is closed once on the first Drain, so the registrar can break its
// current stream and re-register advertising healthy=false without polling.
func (r *Relay) DrainSignal() <-chan struct{} { return r.drainCh }

// Shutdown stops accepting, closes waiting slots, and lets live splices
// drain until ctx expires, after which they are force-closed. Idempotent.
func (r *Relay) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	close(r.done)
	ln := r.ln
	fln := r.funnelLn
	tr := r.turn
	for token, s := range r.pending {
		delete(r.pending, token)
		s.timer.Stop()
		s.conn.Close()
	}
	r.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	if fln != nil {
		fln.Close()
	}
	r.funnelReg.closeAll() // force-close parked public conns awaiting a dial-back
	if tr != nil {
		tr.close() // stops the turn server + closes its UDP socket
	}

	drained := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
		r.log.Info("relay: shutdown complete")
		return nil
	case <-ctx.Done():
	}
	// Drain window elapsed: force-close every remaining conn; the copy
	// loops error out immediately and the WaitGroup unblocks.
	r.mu.Lock()
	n := len(r.conns) + len(r.muxConns)
	for c := range r.conns {
		c.Close()
	}
	for c := range r.muxConns {
		c.Close()
	}
	r.mu.Unlock()
	<-drained
	r.log.Info("relay: shutdown forced", "closed_conns", n)
	return ctx.Err()
}

func (r *Relay) untrack(c net.Conn) {
	r.mu.Lock()
	delete(r.conns, c)
	delete(r.muxConns, c)
	r.mu.Unlock()
}

// handleConn reads and validates the single hello frame, then either parks
// the conn in the pending table or matches it with the waiting peer.
func (r *Relay) handleConn(c net.Conn) {
	peer := c.RemoteAddr().String()
	// One deadline covers the TLS handshake (lazy, on first read) plus the
	// hello frame: a silent dialer cannot hold a socket open.
	c.SetDeadline(time.Now().Add(r.cfg.HelloTimeout))

	var hello wire.RelayHello
	if err := wire.ReadJSON(c, &hello); err != nil {
		r.log.Info("relay: bad hello frame", "peer", peer, "err", err)
		r.reject(c, "bad hello")
		return
	}
	if err := validateHello(hello); err != nil {
		r.log.Info("relay: invalid hello", "peer", peer, "err", err)
		r.reject(c, err.Error())
		return
	}
	// A funnel data leg completes an IN-FLIGHT public request (the relay already
	// parked the public conn), so it is allowed even while draining.
	if hello.Kind == wire.RelayKindFunnelData {
		r.handleFunnelData(c, hello.Token)
		return
	}
	// A draining relay refuses every NEW rendezvous (token splice or control mux): it
	// is shedding for a swap, so a new session must land on a healthy relay. Already-
	// matched splices and established muxes are untouched — they ride out the drain.
	if r.draining.Load() {
		r.log.Info("relay: refusing new rendezvous while draining", "peer", peer, "kind", hello.Kind)
		r.reject(c, "relay draining")
		return
	}
	if hello.Kind == wire.RelayKindControl {
		r.handleControlMux(c, hello.ControllerID)
		return
	}
	if hello.Kind == wire.RelayKindFunnelReg {
		r.handleFunnelReg(c, hello.Host, hello.RegToken)
		return
	}
	tp := tokenPrefix(hello.Token)

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		r.reject(c, "relay shutting down")
		return
	}
	if _, ok := r.used[hello.Token]; ok {
		r.mu.Unlock()
		r.log.Info("relay: token already used", "token", tp, "peer", peer)
		r.reject(c, "token already used")
		return
	}
	s, ok := r.pending[hello.Token]
	switch {
	case ok && s.role == hello.Role:
		// Same role twice: keep the original waiter, reject the newcomer.
		r.mu.Unlock()
		r.log.Info("relay: duplicate role for token", "token", tp,
			"role", hello.Role, "peer", peer)
		r.reject(c, "endpoint with this role already waiting")
		return

	case ok:
		// Match. Tokens are single-use: drop the slot now and remember the
		// token for MatchTTL so a replayed hello cannot pair a second time.
		delete(r.pending, hello.Token)
		s.timer.Stop()
		r.used[hello.Token] = struct{}{}
		time.AfterFunc(r.cfg.MatchTTL, func() {
			r.mu.Lock()
			delete(r.used, hello.Token)
			r.mu.Unlock()
		})
		// The waiter's conn left the pending table; track it so forced
		// shutdown can still reach it during the splice.
		r.conns[s.conn] = struct{}{}
		r.mu.Unlock()
		defer r.untrack(s.conn)

		ic, rc := s.conn, c // initiator, responder
		if hello.Role == wire.RoleInitiator {
			ic, rc = c, s.conn
		}
		waited := time.Since(s.since)
		r.splice(tp, ic, rc, waited)
		return

	default:
		if len(r.pending) >= r.cfg.MaxPending {
			r.mu.Unlock()
			r.log.Warn("relay: pending table full", "token", tp, "peer", peer,
				"max_pending", r.cfg.MaxPending)
			r.reject(c, "relay busy")
			return
		}
		ns := &slot{conn: c, role: hello.Role, since: time.Now()}
		// While parked, the deadline spans the whole match window so the
		// match-time resp write cannot block forever on a dead peer either.
		c.SetDeadline(time.Now().Add(r.cfg.MatchTTL + r.cfg.HelloTimeout))
		ns.timer = time.AfterFunc(r.cfg.MatchTTL, func() {
			r.expire(hello.Token, ns, tp)
		})
		r.pending[hello.Token] = ns
		r.mu.Unlock()
		r.log.Info("relay: waiting for peer", "token", tp,
			"role", hello.Role, "peer", peer)
		return // slot owns the conn now
	}
}

// expire removes an unmatched slot and closes its conn. A concurrent match
// wins: it removes the slot from the table first, so the pointer check here
// fails and the conn is left alone.
func (r *Relay) expire(token string, s *slot, tp string) {
	r.mu.Lock()
	cur, ok := r.pending[token]
	if !ok || cur != s {
		r.mu.Unlock()
		return
	}
	delete(r.pending, token)
	r.mu.Unlock()
	r.log.Info("relay: rendezvous expired", "token", tp, "role", s.role,
		"peer", s.conn.RemoteAddr().String(), "after", r.cfg.MatchTTL.String())
	s.conn.Close()
}

// splice confirms the match to both endpoints and then copies raw bytes in
// both directions until either side errors or goes idle. Blindness
// invariant: from here on, not a single byte is parsed — only copied.
func (r *Relay) splice(tp string, ic, rc net.Conn, waited time.Duration) {
	for _, c := range []net.Conn{ic, rc} {
		c.SetDeadline(time.Now().Add(r.cfg.HelloTimeout))
		if err := wire.WriteJSON(c, wire.RelayResp{OK: true}); err != nil {
			r.log.Info("relay: match resp failed", "token", tp,
				"peer", c.RemoteAddr().String(), "err", err)
			ic.Close()
			rc.Close()
			return
		}
	}
	// Clear hello deadlines; the copy loops set their own per-read idle
	// deadlines from here on.
	ic.SetDeadline(time.Time{})
	rc.SetDeadline(time.Time{})

	r.active.Add(1)
	defer r.active.Add(-1)
	start := time.Now()
	r.log.Info("relay: matched", "token", tp,
		"initiator", ic.RemoteAddr().String(),
		"responder", rc.RemoteAddr().String(),
		"waited", waited.Round(time.Millisecond).String())

	iToR, rToI := r.pump(ic, rc, r.cfg.IdleTimeout)

	r.log.Info("relay: splice closed", "token", tp,
		"initiator", ic.RemoteAddr().String(),
		"responder", rc.RemoteAddr().String(),
		"bytes_i_to_r", iToR, "bytes_r_to_i", rToI,
		"duration", time.Since(start).Round(time.Millisecond).String())
}

// pump copies bytes both ways between a and b until either side errors or stays
// idle for the given window, closing both on the first finish. Blind by
// construction: from here on not a single byte is parsed, only copied. aToB counts
// a->b, bToA counts b->a.
func (r *Relay) pump(a, b net.Conn, idle time.Duration) (aToB, bToA int64) {
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			a.Close()
			b.Close()
		})
	}
	half := make(chan struct{})
	go func() {
		defer close(half)
		bToA = r.copyHalf(a, b, idle)
		closeBoth() // first direction to finish tears down both
	}()
	aToB = r.copyHalf(b, a, idle)
	closeBoth()
	<-half
	return aToB, bToA
}

// setControllerNodeControl replaces the control-mux routing table with a freshly
// verified controller-id -> NodeControl-address map (the registrar watch calls this
// after verifying each signed map).
func (r *Relay) setControllerNodeControl(m map[string][]string) {
	r.gwMu.Lock()
	r.gwNodeControl = m
	r.gwMu.Unlock()
}

// nodeControlAddrs resolves a controller-id routing label to its signed NodeControl
// dial addresses; ok is false for an unknown id, so the relay dials nothing.
func (r *Relay) nodeControlAddrs(controllerID string) ([]string, bool) {
	r.gwMu.RLock()
	defer r.gwMu.RUnlock()
	a, ok := r.gwNodeControl[controllerID]
	return a, ok && len(a) > 0
}

// haveSignedControllers reports whether the relay holds a verified controller set; a
// control mux is refused until it does (fail closed with no map to validate the
// agent's routing label against).
func (r *Relay) haveSignedControllers() bool {
	r.gwMu.RLock()
	defer r.gwMu.RUnlock()
	return len(r.gwNodeControl) > 0
}

// handleControlMux forwards a persistent, payload-blind control connection to the
// controller the agent named. The agent runs its end-to-end mTLS control stream
// straight through, so the relay terminates no inner TLS and the controller
// authenticates the agent's own node cert. The controller id is an untrusted routing
// LABEL: the relay resolves it to a dial address ONLY from its own signed,
// signature-verified map, dials that address itself (never an agent-supplied one),
// and refuses unsafe targets — so a hostile label can neither smuggle an address
// nor point the relay at an internal service.
func (r *Relay) handleControlMux(c net.Conn, controllerID string) {
	peer := c.RemoteAddr().String()
	if !r.cfg.ControlMux || !r.haveSignedControllers() {
		r.log.Info("relay: control mux unavailable", "peer", peer, "enabled", r.cfg.ControlMux)
		r.reject(c, "control mux unavailable")
		return
	}
	addrs, ok := r.nodeControlAddrs(controllerID)
	if !ok {
		r.log.Info("relay: control mux for unknown controller", "gw", controllerID, "peer", peer)
		r.reject(c, "unknown controller")
		return
	}
	// Admit under the dedicated control-mux cap and MOVE the agent leg out of the
	// ephemeral accept cap into the durable mux accounting, so a relay full of homed
	// agents cannot starve brief token rendezvous (and vice-versa). Each mux holds
	// two legs, so the leg ceiling is 2*MaxControlMux.
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		r.reject(c, "relay shutting down")
		return
	}
	if len(r.muxConns) >= 2*r.cfg.MaxControlMux {
		r.mu.Unlock()
		r.log.Warn("relay: control-mux capacity reached, shedding", "max", r.cfg.MaxControlMux, "gw", controllerID, "peer", peer)
		r.reject(c, "relay at control-mux capacity")
		return
	}
	delete(r.conns, c)
	r.muxConns[c] = struct{}{}
	r.mu.Unlock()

	gw, target, err := r.dialControllerControl(addrs)
	if err != nil {
		// c is now in muxConns; the Serve goroutine's deferred untrack(c) frees it.
		r.log.Info("relay: control mux dial failed", "gw", controllerID, "peer", peer, "err", err)
		r.reject(c, "controller unreachable")
		return
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		gw.Close()
		r.reject(c, "relay shutting down")
		return
	}
	r.muxConns[gw] = struct{}{}
	r.mu.Unlock()
	defer r.untrack(gw)
	r.spliceControl(controllerID, target, c, gw)
}

// dialControllerControl dials the controller's NodeControl listener over PLAIN TCP — no
// TLS on this leg, so the agent's inner mTLS ClientHello reaches the controller
// verbatim and the controller authenticates the agent directly through the splice. It
// tries the signed addresses in order.
func (r *Relay) dialControllerControl(addrs []string) (net.Conn, string, error) {
	var lastErr error
	for _, a := range addrs {
		c, err := r.dialControlController(a)
		if err != nil {
			lastErr = err
			continue
		}
		return c, a, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no controller addresses")
	}
	return nil, "", lastErr
}

func (r *Relay) defaultDialControlController(addr string) (net.Conn, error) {
	dialAddr, err := safeDialTarget(addr)
	if err != nil {
		return nil, err
	}
	return net.DialTimeout("tcp", dialAddr, r.cfg.HelloTimeout)
}

// safeDialTarget vets a control-mux target and returns the exact address to dial —
// a literal IP:port — so the safety check and the dial agree on ONE address and a
// short-TTL or rebinding name cannot flip to a denied IP between two resolutions.
// It refuses loopback, link-local (incl. the cloud metadata endpoint), multicast,
// and unspecified addresses: belt-and-braces against a misconfigured signed map
// turning the relay into an internal-port probe.
func safeDialTarget(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return "", fmt.Errorf("bad target %q", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		resolved, lerr := net.LookupIP(host)
		if lerr != nil || len(resolved) == 0 {
			return "", fmt.Errorf("resolve %q: %v", host, lerr)
		}
		// Every resolved IP must pass; dial the first one as a LITERAL so the dial
		// cannot re-resolve to a different (denied) address.
		for _, cand := range resolved {
			if unsafeIP(cand) {
				return "", fmt.Errorf("refused unsafe target %s", cand)
			}
		}
		ip = resolved[0]
	} else if unsafeIP(ip) {
		return "", fmt.Errorf("refused unsafe target %s", ip)
	}
	return net.JoinHostPort(ip.String(), port), nil
}

func unsafeIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified()
}

// spliceControl confirms the mux to the agent, then copies raw bytes between the
// agent and the controller, blind. The controller leg gets NO RelayResp: it expects the
// agent's TLS ClientHello immediately, which this forwards verbatim.
func (r *Relay) spliceControl(controllerID, target string, agent, gw net.Conn) {
	agent.SetDeadline(time.Now().Add(r.cfg.HelloTimeout))
	if err := wire.WriteJSON(agent, wire.RelayResp{OK: true}); err != nil {
		r.log.Info("relay: control mux ack failed", "gw", controllerID, "err", err)
		agent.Close()
		gw.Close()
		return
	}
	agent.SetDeadline(time.Time{})
	gw.SetDeadline(time.Time{})
	r.active.Add(1)
	defer r.active.Add(-1)
	start := time.Now()
	r.log.Info("relay: control mux up", "gw", controllerID, "target", target,
		"agent", agent.RemoteAddr().String())
	aToG, gToA := r.pump(agent, gw, controlMuxIdle)
	r.log.Info("relay: control mux closed", "gw", controllerID,
		"bytes_a_to_g", aToG, "bytes_g_to_a", gToA,
		"duration", time.Since(start).Round(time.Millisecond).String())
}

// copyHalf shuttles src->dst, refreshing deadlines on every iteration so a
// splice with no traffic for the idle window (or a peer that stops reading) is
// reaped rather than leaking forever. Errors are terminal by design: the
// caller closes both conns on the first failure in either direction.
func (r *Relay) copyHalf(dst, src net.Conn, idle time.Duration) int64 {
	buf := make([]byte, 32*1024)
	var n int64
	// Coalesce the idle deadline. Resetting it on every read/write costs two
	// setsockopt-class syscalls per frame, which dominates a busy splice pushing
	// small (interactive SSH) frames; refresh only once the current deadline is
	// within half of expiring. The idle-reap window is unchanged — a stalled peer
	// still trips the deadline within idle.
	half := idle / 2
	if half <= 0 {
		half = idle
	}
	var rDeadline, wDeadline time.Time
	for {
		if now := time.Now(); rDeadline.Sub(now) < half {
			rDeadline = now.Add(idle)
			src.SetReadDeadline(rDeadline)
		}
		nr, rerr := src.Read(buf)
		if nr > 0 {
			if now := time.Now(); wDeadline.Sub(now) < half {
				wDeadline = now.Add(idle)
				dst.SetWriteDeadline(wDeadline)
			}
			nw, werr := dst.Write(buf[:nr])
			n += int64(nw)
			if werr != nil {
				return n
			}
			if nw != nr {
				return n
			}
		}
		if rerr != nil {
			return n
		}
	}
}

// reject answers with a RelayResp error (best effort) and closes the conn.
func (r *Relay) reject(c net.Conn, msg string) {
	c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_ = wire.WriteJSON(c, wire.RelayResp{OK: false, Error: msg})
	c.Close()
}

func (r *Relay) statsLoop() {
	defer r.wg.Done()
	t := time.NewTicker(r.cfg.StatsPeriod)
	defer t.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-t.C:
			r.mu.Lock()
			waiting := len(r.pending)
			muxes := len(r.muxConns) / 2
			r.mu.Unlock()
			r.log.Info("relay: stats",
				"active_splices", r.active.Load(), "waiting_slots", waiting, "control_muxes", muxes)
		}
	}
}

// Token shape produced by types.NewToken: "gz-" + 32 lowercase hex chars.
// The relay tolerates 16..64 hex chars so the token length can grow without
// a relay redeploy, but anything else is rejected outright.
const (
	tokenPrefixStr = "gz-"
	tokenMinHex    = 16
	tokenMaxHex    = 64
)

func validateHello(h wire.RelayHello) error {
	if h.V != 1 {
		return fmt.Errorf("unsupported hello version %d", h.V)
	}
	switch h.Kind {
	case wire.RelayKindControl:
		// A control mux is a direct forward, not a token-paired rendezvous: it carries
		// a controller routing label and never a token or role.
		if h.Token != "" || h.Role != "" {
			return errors.New("control hello must not carry a token or role")
		}
		if !validControllerID(h.ControllerID) {
			return errors.New("invalid controller id")
		}
		return nil
	case wire.RelayKindFunnelReg:
		// An agent registering to serve a funnel hostname: carries a host, no token/role.
		if h.Host == "" {
			return errors.New("funnel registration requires a host")
		}
		if len(h.Host) > 253 {
			return errors.New("funnel host too long")
		}
		return nil
	case wire.RelayKindFunnelData:
		// An agent's per-request funnel data leg, matched by a relay-minted token
		// (fz-<hex>); reject malformed probes early.
		if !strings.HasPrefix(h.Token, "fz-") || len(h.Token) < 8 || len(h.Token) > 128 {
			return errors.New("funnel data requires a valid token")
		}
		return nil
	case "":
		// Single-use token rendezvous (the only thing legacy peers send).
	default:
		return fmt.Errorf("unknown hello kind %q", h.Kind)
	}
	if h.Role != wire.RoleInitiator && h.Role != wire.RoleResponder {
		return errors.New("invalid role")
	}
	if !strings.HasPrefix(h.Token, tokenPrefixStr) {
		return errors.New("invalid token")
	}
	body := h.Token[len(tokenPrefixStr):]
	if len(body) < tokenMinHex || len(body) > tokenMaxHex {
		return errors.New("invalid token length")
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return errors.New("invalid token charset")
		}
	}
	return nil
}

// validControllerID bounds the agent-supplied routing label to a sane charset before
// the relay looks it up in its signed map; the map match is the real gate. Controller
// ids are configured strings or hostnames (alnum, dash, dot, underscore).
func validControllerID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') &&
			c != '-' && c != '.' && c != '_' {
			return false
		}
	}
	return true
}

// tokenPrefix is the only part of a token that ever reaches the logs.
func tokenPrefix(token string) string {
	if len(token) <= 8 {
		return token
	}
	return token[:8]
}
