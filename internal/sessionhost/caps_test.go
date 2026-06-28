package sessionhost

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// TestSetCapsReadOnlyGatesStdin proves the session-host is the authoritative
// read-only point — once SetCaps{read_only} lands, stdin is dropped before
// reaching the PTY (even though the client is still acked), and re-enabling
// restores it. Ordering-based so it cannot race: VISIBLE is sent after SECRET,
// so if SECRET were going to echo it would precede VISIBLE in the stream.
func TestSetCapsReadOnlyGatesStdin(t *testing.T) {
	c, _ := newTestHost(t)
	ctx := testCtx(t)
	id := mustCreate(t, ctx, c, &genezav1.HostCreateRequest{
		SessionId: "gw-ro", User: "alice", Action: "exec",
		Command: "cat", Pty: true, Cols: 80, Rows: 24,
	})
	st := openAttach(t, ctx, c, id, 0)
	col := &collected{}
	recvUntil(t, st, col, func(c *collected) bool { return len(c.frames) >= 1 })

	// Read-only: this keystroke must be dropped at the host (no PTY echo) but acked.
	if _, err := c.SetCaps(ctx, &genezav1.HostSetCapsRequest{HostSessionId: id, ReadOnly: true}); err != nil {
		t.Fatalf("set read-only: %v", err)
	}
	sendInput(t, st, 1, "SECRET\n")
	recvUntil(t, st, col, func(c *collected) bool { return c.ackCount(1) >= 1 })

	// Re-enable and send a visible marker; when it echoes, any (wrongly) written
	// SECRET would already be in the transcript before it.
	if _, err := c.SetCaps(ctx, &genezav1.HostSetCapsRequest{HostSessionId: id, ReadOnly: false}); err != nil {
		t.Fatalf("clear read-only: %v", err)
	}
	sendInput(t, st, 2, "VISIBLE\n")
	recvUntil(t, st, col, func(c *collected) bool { return strings.Contains(c.transcript(), "VISIBLE") })

	if strings.Contains(col.transcript(), "SECRET") {
		t.Fatalf("read-only keystroke reached the PTY (transcript contains SECRET): %q", col.transcript())
	}
}

func TestSetCapsUnknownSessionNotFound(t *testing.T) {
	c, _ := newTestHost(t)
	ctx := testCtx(t)
	_, err := c.SetCaps(ctx, &genezav1.HostSetCapsRequest{HostSessionId: "h-doesnotexist", ReadOnly: true})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("SetCaps on unknown session: got %v, want NotFound", err)
	}
}
