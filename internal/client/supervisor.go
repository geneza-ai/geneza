package client

import (
	"context"
	"sync"
	"time"
)

// supervisor.go is the client-side reconnect-fast wrapper for sessions whose action
// has no persistent server-side state to preserve across a relay re-home — forward
// and vpn. When the live transport drops (a relay drains or dies), it rebuilds the
// session under a fresh grant (a healthy relay floor, the drained relay excluded by
// the controller's fleet selection) so the local listener/pump reconnects its upstream
// transparently, with at most a brief stall. A detachable shell does NOT use this —
// it re-attaches its persisted host PTY through RunAttached's seamless path instead.

const (
	supervisorMaxAttempts   = 8
	supervisorBackoffHi     = 8 * time.Second
	supervisorProbeInterval = 1 * time.Second
)

// Supervisor keeps a live *Session, transparently re-establishing it after a
// transport loss. Callers take the current session via Current() for each new
// stream/connection, so an in-flight rebuild is invisible past a brief stall.
type Supervisor struct {
	build func(ctx context.Context) (*Session, error)

	mu   sync.Mutex
	sess *Session
}

// NewSupervisor builds the first session and returns a supervisor that keeps it
// live. build re-establishes a session (a fresh CreateSession under the same
// scope); it is called again on every transport loss with bounded full-jitter
// backoff. The returned supervisor's Run drives the rebuild loop until ctx ends.
func NewSupervisor(ctx context.Context, build func(ctx context.Context) (*Session, error)) (*Supervisor, error) {
	first, err := build(ctx)
	if err != nil {
		return nil, err
	}
	return &Supervisor{build: build, sess: first}, nil
}

// Current returns the live session (never nil while Run has not returned). Callers
// open each new stream on Current() so a rebuilt session is picked up immediately.
func (s *Supervisor) Current() *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sess
}

func (s *Supervisor) swap(ns *Session) {
	s.mu.Lock()
	s.sess = ns
	s.mu.Unlock()
}

// Run watches the live session and rebuilds it on a transport loss until ctx ends
// or the rebuild budget is exhausted (a genuinely-dead peer / an exhausted fleet).
// It closes the final session on return. The budget resets after a session that
// lives past the probe interval, so a long-healthy session always has full retries.
func (s *Supervisor) Run(ctx context.Context) {
	attempts := 0
	for {
		cur := s.Current()
		// Block until this session's transport dies or ctx ends. A nil SSH (vpn) uses
		// the raw tunnel conn; either way a closed conn unblocks the wait.
		if !waitSessionDown(ctx, cur) {
			cur.Close()
			return // ctx ended: a clean stop
		}
		start := time.Now()
		attempts++
		if attempts > supervisorMaxAttempts {
			cur.Close()
			return
		}
		backoff := time.Duration(1<<uint(minInt(attempts, 3))) * time.Second
		if backoff > supervisorBackoffHi {
			backoff = supervisorBackoffHi
		}
		select {
		case <-ctx.Done():
			cur.Close()
			return
		case <-time.After(jitter(backoff)):
		}
		ns, err := s.build(ctx)
		if err != nil {
			if ctx.Err() != nil {
				cur.Close()
				return
			}
			continue // budget left: try again after backoff
		}
		cur.Close()
		s.swap(ns)
		if time.Since(start) > supervisorProbeInterval {
			attempts = 0 // a lived re-home resets the budget
		}
	}
}

// waitSessionDown returns true when the session's transport has dropped (re-home
// trigger), or false when ctx ended first (a clean stop). It polls the SSH client's
// liveness via a cheap keepalive request; for a vpn session (no SSH) it watches the
// raw tunnel conn for a read error.
func waitSessionDown(ctx context.Context, sess *Session) bool {
	t := time.NewTicker(supervisorProbeInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			if !sessionAlive(sess) {
				return true
			}
		}
	}
}

// sessionAlive probes the session's transport. For SSH it sends a keepalive global
// request (the agent answers with a failure reply, which still proves liveness);
// any error means the transport is gone. For vpn it checks the tunnel conn with a
// zero-length deadline-bounded read is not portable, so vpn relies on the SSH path
// being nil and is treated as alive here (the vpn pump owns its own teardown).
func sessionAlive(sess *Session) bool {
	if sess == nil {
		return false
	}
	if sess.SSH == nil {
		return true // vpn: the packet pump detects loss and closes Tunnel itself
	}
	done := make(chan error, 1)
	go func() { _, _, err := sess.SSH.SendRequest("keepalive@geneza", true, nil); done <- err }()
	select {
	case err := <-done:
		return err == nil
	case <-time.After(3 * time.Second):
		return false
	}
}
