package sessionhost

import (
	"testing"

	"github.com/hinshun/vt10x"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

// A PTY client that falls behind must be coalesced (kept attached, repainted
// from a snapshot), NOT dropped — dropping forced a reconnect+repaint on every
// output burst and was the cause of "flaky" interactive sessions.
func TestPtyClientLagCoalescesInsteadOfDropping(t *testing.T) {
	cl := newAttachedClient()
	cl.ch = make(chan *genezav1.HostToClient, 2) // tiny, to overflow fast
	s := &session{
		client:     cl,
		state:      stateAttached,
		detachable: true,
		ptyMode:    true,
		vt:         vt10x.New(vt10x.WithSize(20, 5)),
		cols:       20,
		rows:       5,
		ring:       newRing(1 << 16),
	}
	_, _ = s.vt.Write([]byte("hello world"))

	// Mimic the pump producing more frames than the client drains.
	s.mu.Lock()
	for i := 0; i < 6; i++ {
		s.seq++
		s.deliverLocked(chunkFrame(s.seq, false, []byte("x")))
	}
	s.mu.Unlock()

	if s.client == nil {
		t.Fatal("regression: PTY client was dropped on overflow")
	}
	if !cl.lagged.Load() {
		t.Fatal("client should be flagged lagged after overflow")
	}

	snap := s.catchUpSnapshot(cl)
	if snap == nil || snap.GetSnapshot() == nil {
		t.Fatal("catch-up should return a vt snapshot")
	}
	if cl.lagged.Load() {
		t.Fatal("lagged flag should be cleared after catch-up")
	}
	if len(cl.ch) != 0 {
		t.Fatalf("stale backlog should be drained, %d frames left", len(cl.ch))
	}
	if s.client == nil {
		t.Fatal("client must remain attached after catch-up")
	}
}

// A pipe-mode (exec/sftp) client has no screen to repaint and is a lossless
// byte stream, so it is still dropped on overflow (the safe choice there).
func TestPipeClientStillDroppedOnOverflow(t *testing.T) {
	cl := newAttachedClient()
	cl.ch = make(chan *genezav1.HostToClient, 1)
	s := &session{
		client:     cl,
		state:      stateAttached,
		detachable: false,
		ptyMode:    false, // pipe mode: vt is nil
		exited:     true,  // short-circuit the teardown goroutine; we assert only the drop
		ring:       newRing(1 << 16),
	}
	s.mu.Lock()
	for i := 0; i < 4; i++ {
		s.seq++
		s.deliverLocked(chunkFrame(s.seq, false, []byte("x")))
	}
	s.mu.Unlock()
	if s.client != nil {
		t.Fatal("pipe-mode client should be dropped on overflow (lossless stream)")
	}
}
