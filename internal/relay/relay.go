package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"osie.cloud/geneza/internal/wire"
)

// ErrClosed is returned by Serve/ListenAndServe after Shutdown.
var ErrClosed = errors.New("relay: closed")

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
	conns   map[net.Conn]struct{} // conns in hello/splice, for forced shutdown
	closed  bool
	serving bool

	active atomic.Int64 // live splices, for the stats log
	wg     sync.WaitGroup
	done   chan struct{}
}

// New builds a Relay; cfg must already be validated (Load does this).
func New(cfg Config, log *slog.Logger) *Relay {
	if log == nil {
		log = slog.Default()
	}
	return &Relay{
		cfg:     cfg,
		log:     log,
		pending: make(map[string]*slot),
		used:    make(map[string]struct{}),
		conns:   make(map[net.Conn]struct{}),
		done:    make(chan struct{}),
	}
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
	for token, s := range r.pending {
		delete(r.pending, token)
		s.timer.Stop()
		s.conn.Close()
	}
	r.mu.Unlock()
	if ln != nil {
		ln.Close()
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
	n := len(r.conns)
	for c := range r.conns {
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

	var iToR, rToI int64
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			ic.Close()
			rc.Close()
		})
	}
	half := make(chan struct{})
	go func() {
		defer close(half)
		rToI = r.copyHalf(ic, rc)
		closeBoth() // first direction to finish tears down both
	}()
	iToR = r.copyHalf(rc, ic)
	closeBoth()
	<-half

	r.log.Info("relay: splice closed", "token", tp,
		"initiator", ic.RemoteAddr().String(),
		"responder", rc.RemoteAddr().String(),
		"bytes_i_to_r", iToR, "bytes_r_to_i", rToI,
		"duration", time.Since(start).Round(time.Millisecond).String())
}

// copyHalf shuttles src->dst, refreshing deadlines on every iteration so a
// splice with no traffic for IdleTimeout (or a peer that stops reading) is
// reaped rather than leaking forever. Errors are terminal by design: the
// caller closes both conns on the first failure in either direction.
func (r *Relay) copyHalf(dst, src net.Conn) int64 {
	buf := make([]byte, 32*1024)
	var n int64
	for {
		src.SetReadDeadline(time.Now().Add(r.cfg.IdleTimeout))
		nr, rerr := src.Read(buf)
		if nr > 0 {
			dst.SetWriteDeadline(time.Now().Add(r.cfg.IdleTimeout))
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
			r.mu.Unlock()
			r.log.Info("relay: stats",
				"active_splices", r.active.Load(), "waiting_slots", waiting)
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

// tokenPrefix is the only part of a token that ever reaches the logs.
func tokenPrefix(token string) string {
	if len(token) <= 8 {
		return token
	}
	return token[:8]
}
