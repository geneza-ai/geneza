package relay

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"time"

	"geneza.io/internal/wire"
)

// Funnel public proxy: a SEPARATE listener from the payload-blind rendezvous
// splice. A public client connects with SNI=H; the relay terminates TLS with the
// funnel leaf cert (this is the one place the relay is not payload-blind, by
// explicit funnel opt-in), finds the agent registered to serve H, mints a one-
// time token, signals the agent over its registration connection, and splices the
// decrypted bytes to the per-request data connection the agent dials back. The
// agent — never the relay — proxies to the actual overlay target.

// funnelRegistry tracks agent funnel registrations and parked public connections
// awaiting their agent dial-back.
type funnelRegistry struct {
	mu      sync.Mutex
	regs    map[string]*funnelReg // hostname -> agent registration
	pending map[string]net.Conn   // token -> parked TLS-terminated public conn
}

// funnelDialBackTTL bounds how long a public conn waits parked for the agent to
// dial back. Short (vs the 60s rendezvous MatchTTL) because the dial-back is a
// single agent RTT, and a public listener must not let stalled clients pin the
// park table.
const funnelDialBackTTL = 15 * time.Second

func newFunnelRegistry() *funnelRegistry {
	return &funnelRegistry{regs: map[string]*funnelReg{}, pending: map[string]net.Conn{}}
}

// closeAll force-closes every parked public conn (relay shutdown).
func (fr *funnelRegistry) closeAll() {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	for token, c := range fr.pending {
		delete(fr.pending, token)
		c.Close()
	}
}

// funnelReg is one agent's persistent registration connection for a hostname; the
// relay writes FunnelDial requests over it (serialized by wmu).
type funnelReg struct {
	wmu  sync.Mutex
	conn net.Conn
}

func (reg *funnelReg) signal(token string) error {
	reg.wmu.Lock()
	defer reg.wmu.Unlock()
	reg.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err := wire.WriteJSON(reg.conn, wire.FunnelDial{Token: token})
	reg.conn.SetWriteDeadline(time.Time{})
	return err
}

func (fr *funnelRegistry) set(host string, reg *funnelReg) {
	fr.mu.Lock()
	fr.regs[host] = reg
	fr.mu.Unlock()
}

func (fr *funnelRegistry) del(host string, reg *funnelReg) {
	fr.mu.Lock()
	if fr.regs[host] == reg { // only if still ours (a newer registration may have replaced it)
		delete(fr.regs, host)
	}
	fr.mu.Unlock()
}

func (fr *funnelRegistry) get(host string) *funnelReg {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	return fr.regs[host]
}

// park stores a public conn under a token, bounded by max to resist a flood.
func (fr *funnelRegistry) park(token string, c net.Conn, max int) bool {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	if len(fr.pending) >= max {
		return false
	}
	fr.pending[token] = c
	return true
}

func (fr *funnelRegistry) take(token string) net.Conn {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	c := fr.pending[token]
	delete(fr.pending, token)
	return c
}

func funnelToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "fz-" + hex.EncodeToString(b[:])
}

// serveFunnel accepts public TLS connections on the funnel listener and proxies
// each to the agent registered for its SNI host. Returns when the listener closes.
func (r *Relay) serveFunnel(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		r.wg.Add(1)
		go func() { defer r.wg.Done(); r.serveFunnelPublic(c) }()
	}
}

func (r *Relay) serveFunnelPublic(c net.Conn) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		c.Close()
		return
	}
	tc.SetDeadline(time.Now().Add(r.cfg.HelloTimeout))
	if err := tc.Handshake(); err != nil {
		tc.Close()
		return
	}
	host := strings.ToLower(strings.TrimSuffix(tc.ConnectionState().ServerName, "."))
	if r.draining.Load() {
		tc.Close() // shed new public traffic while draining; in-flight splices ride out
		return
	}
	reg := r.funnelReg.get(host)
	if reg == nil {
		r.log.Info("funnel: no agent registered", "host", host, "peer", tc.RemoteAddr())
		tc.Close()
		return
	}
	token := funnelToken()
	if !r.funnelReg.park(token, tc, r.cfg.MaxPending) {
		r.log.Warn("funnel: pending table full", "host", host)
		tc.Close()
		return
	}
	// Bound the parked conn's idle time to the dial-back window (no unbounded
	// no-deadline gap); the data handler resets the deadline when it takes over.
	tc.SetDeadline(time.Now().Add(funnelDialBackTTL))
	// Reap the parked public conn if the agent never dials back.
	timer := time.AfterFunc(funnelDialBackTTL, func() {
		if pc := r.funnelReg.take(token); pc != nil {
			r.log.Info("funnel: dial-back timeout", "host", host)
			pc.Close()
		}
	})
	if err := reg.signal(token); err != nil {
		timer.Stop()
		if pc := r.funnelReg.take(token); pc != nil {
			pc.Close()
		}
		r.log.Info("funnel: signal agent failed; deregistering", "host", host, "err", err)
		r.funnelReg.del(host, reg)
		return
	}
}

// handleFunnelData splices a parked public conn to the agent's per-request data
// connection, matched by the relay-minted token.
func (r *Relay) handleFunnelData(c net.Conn, token string) {
	pc := r.funnelReg.take(token)
	if pc == nil {
		r.reject(c, "funnel token unknown or expired")
		return
	}
	c.SetDeadline(time.Now().Add(r.cfg.HelloTimeout))
	if err := wire.WriteJSON(c, wire.RelayResp{OK: true}); err != nil {
		pc.Close()
		c.Close()
		return
	}
	c.SetDeadline(time.Time{})
	pc.SetDeadline(time.Time{})
	// Track both legs so a relay shutdown force-closes an in-flight funnel splice
	// (the parked conn left the pending table when it was taken above).
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		pc.Close()
		c.Close()
		return
	}
	r.conns[c] = struct{}{}
	r.conns[pc] = struct{}{}
	r.mu.Unlock()
	defer r.untrack(c)
	defer r.untrack(pc)
	r.active.Add(1)
	defer r.active.Add(-1)
	r.pump(pc, c, r.cfg.IdleTimeout)
}

// handleFunnelReg holds an agent's persistent funnel registration. The relay
// authorizes it against the controller-pushed registration token for the host
// (so an unauthorized agent cannot claim another tenant's public hostname),
// records it, and keeps the connection open, reading to detect the disconnect.
func (r *Relay) handleFunnelReg(c net.Conn, host, token string) {
	if r.funnel == nil {
		r.reject(c, "funnel not enabled on this relay")
		return
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if !r.funnel.authorizeReg(host, token) {
		r.log.Warn("funnel: unauthorized registration rejected", "host", host, "peer", c.RemoteAddr())
		r.reject(c, "funnel registration not authorized")
		return
	}
	reg := &funnelReg{conn: c}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		r.reject(c, "relay shutting down")
		return
	}
	if len(r.muxConns) >= 2*r.cfg.MaxControlMux {
		r.mu.Unlock()
		r.reject(c, "relay funnel capacity reached")
		return
	}
	r.muxConns[c] = struct{}{}
	r.mu.Unlock()

	r.funnelReg.set(host, reg)
	defer func() {
		r.funnelReg.del(host, reg)
		r.mu.Lock()
		delete(r.muxConns, c)
		r.mu.Unlock()
		c.Close()
	}()

	c.SetDeadline(time.Now().Add(r.cfg.HelloTimeout))
	if err := wire.WriteJSON(c, wire.RelayResp{OK: true}); err != nil {
		return
	}
	r.log.Info("funnel: agent registered", "host", host, "peer", c.RemoteAddr())

	// Hold the conn open; the agent sends periodic keepalive frames. A read error
	// or idle timeout means the agent is gone — deregister so its host stops being
	// advertised here.
	buf := make([]byte, 256)
	for {
		c.SetReadDeadline(time.Now().Add(controlMuxIdle))
		if _, err := c.Read(buf); err != nil {
			return
		}
	}
}
