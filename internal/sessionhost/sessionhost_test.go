package sessionhost

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

func newTestHost(t *testing.T) (genezav1.SessionHostClient, *host) {
	t.Helper()
	h := newHost("test", t.TempDir())
	gs := grpc.NewServer()
	genezav1.RegisterSessionHostServer(gs, h)
	lis := bufconn.Listen(1 << 20)
	go gs.Serve(lis)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc client: %v", err)
	}
	t.Cleanup(func() {
		conn.Close()
		gs.Stop()
		h.shutdown(3 * time.Second) // no stray cats after the test binary exits
	})
	return genezav1.NewSessionHostClient(conn), h
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func mustCreate(t *testing.T, ctx context.Context, c genezav1.SessionHostClient, req *genezav1.HostCreateRequest) string {
	t.Helper()
	resp, err := c.Create(ctx, req)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !strings.HasPrefix(resp.HostSessionId, "h-") || len(resp.HostSessionId) != 14 {
		t.Fatalf("bad host_session_id %q", resp.HostSessionId)
	}
	return resp.HostSessionId
}

func openAttach(t *testing.T, ctx context.Context, c genezav1.SessionHostClient, id string, lastSeen uint64) genezav1.SessionHost_AttachClient {
	t.Helper()
	st, err := c.Attach(ctx)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	err = st.Send(&genezav1.ClientToHost{Msg: &genezav1.ClientToHost_Open{
		Open: &genezav1.AttachOpen{HostSessionId: id, LastSeenSeq: lastSeen},
	}})
	if err != nil {
		t.Fatalf("send open: %v", err)
	}
	return st
}

func sendInput(t *testing.T, st genezav1.SessionHost_AttachClient, seq uint64, data string) {
	t.Helper()
	err := st.Send(&genezav1.ClientToHost{Msg: &genezav1.ClientToHost_Input{
		Input: &genezav1.Input{Seq: seq, Data: []byte(data)},
	}})
	if err != nil {
		t.Fatalf("send input: %v", err)
	}
}

// collected accumulates frames from one attach stream.
type collected struct {
	frames []*genezav1.HostToClient
}

func (c *collected) transcript() string {
	var b bytes.Buffer
	for _, f := range c.frames {
		if o := f.GetOutput(); o != nil {
			b.Write(o.Data)
		}
		if e := f.GetStderr(); e != nil {
			b.Write(e.Data)
		}
	}
	return b.String()
}

func (c *collected) ackCount(seq uint64) int {
	n := 0
	for _, f := range c.frames {
		if a := f.GetInputAck(); a != nil && a.Seq == seq {
			n++
		}
	}
	return n
}

func (c *collected) exit() *genezav1.Exit {
	for _, f := range c.frames {
		if e := f.GetExit(); e != nil {
			return e
		}
	}
	return nil
}

func (c *collected) maxOutputSeq() uint64 {
	var max uint64
	for _, f := range c.frames {
		if o := f.GetOutput(); o != nil && o.Seq > max {
			max = o.Seq
		}
		if e := f.GetStderr(); e != nil && e.Seq > max {
			max = e.Seq
		}
	}
	return max
}

func recvUntil(t *testing.T, st genezav1.SessionHost_AttachClient, col *collected, cond func(*collected) bool) {
	t.Helper()
	for !cond(col) {
		m, err := st.Recv()
		if err != nil {
			t.Fatalf("recv: %v (transcript so far: %q)", err, col.transcript())
		}
		col.frames = append(col.frames, m)
	}
}

func detachAndDrain(t *testing.T, st genezav1.SessionHost_AttachClient) {
	t.Helper()
	err := st.Send(&genezav1.ClientToHost{Msg: &genezav1.ClientToHost_Detach{Detach: &genezav1.Detach{}}})
	if err != nil {
		t.Fatalf("send detach: %v", err)
	}
	// Frames still in flight at detach are discarded, exactly like a real
	// client that never rendered (and so never acked) them.
	for {
		if _, err := st.Recv(); err != nil {
			return
		}
	}
}

func TestPtyCatEchoRoundtripAndKill(t *testing.T) {
	c, _ := newTestHost(t)
	ctx := testCtx(t)
	id := mustCreate(t, ctx, c, &genezav1.HostCreateRequest{
		SessionId: "gw-cat", User: "alice", Action: "exec",
		Command: "cat", Pty: true, Cols: 80, Rows: 24,
	})
	st := openAttach(t, ctx, c, id, 0)
	col := &collected{}
	recvUntil(t, st, col, func(c *collected) bool { return len(c.frames) >= 1 })
	if col.frames[0].GetSnapshot() == nil {
		t.Fatalf("fresh pty attach must start with a snapshot, got %v", col.frames[0])
	}
	sendInput(t, st, 1, "hello\n")
	recvUntil(t, st, col, func(c *collected) bool {
		return strings.Contains(c.transcript(), "hello") && c.ackCount(1) >= 1
	})
	if _, err := c.Kill(ctx, &genezav1.HostKillRequest{HostSessionId: id}); err != nil {
		t.Fatalf("kill: %v", err)
	}
	recvUntil(t, st, col, func(c *collected) bool { return c.exit() != nil })
	if got := col.exit().Reason; got != reasonKilled {
		t.Fatalf("exit reason = %q, want %q", got, reasonKilled)
	}
}

func TestInputSeqDedupePipe(t *testing.T) {
	c, _ := newTestHost(t)
	ctx := testCtx(t)
	id := mustCreate(t, ctx, c, &genezav1.HostCreateRequest{
		SessionId: "gw-dedupe", Command: "cat", Pty: false,
	})
	st := openAttach(t, ctx, c, id, 0)
	col := &collected{}
	recvUntil(t, st, col, func(c *collected) bool { return len(c.frames) >= 1 })
	if s := col.frames[0].GetSnapshot(); s == nil {
		t.Fatalf("pipe attach must start with a snapshot marker, got %v", col.frames[0])
	}
	sendInput(t, st, 1, "tok-alpha\n")
	recvUntil(t, st, col, func(c *collected) bool {
		return strings.Contains(c.transcript(), "tok-alpha\n") && c.ackCount(1) >= 1
	})
	// Reconnect-style duplicate: must be acked again but never re-applied.
	sendInput(t, st, 1, "tok-alpha\n")
	recvUntil(t, st, col, func(c *collected) bool { return c.ackCount(1) >= 2 })
	sendInput(t, st, 2, "tok-beta\n")
	recvUntil(t, st, col, func(c *collected) bool {
		return strings.Contains(c.transcript(), "tok-beta\n")
	})
	err := st.Send(&genezav1.ClientToHost{Msg: &genezav1.ClientToHost_StdinEof{StdinEof: &genezav1.Stdin_EOF{}}})
	if err != nil {
		t.Fatalf("send stdin_eof: %v", err)
	}
	recvUntil(t, st, col, func(c *collected) bool { return c.exit() != nil })
	if e := col.exit(); e.Code != 0 || e.Reason != "exited" {
		t.Fatalf("exit = %+v, want code 0 reason exited", e)
	}
	out := col.transcript()
	if n := strings.Count(out, "tok-alpha\n"); n != 1 {
		t.Fatalf("tok-alpha applied %d times, want exactly 1 (out=%q)", n, out)
	}
	if n := strings.Count(out, "tok-beta\n"); n != 1 {
		t.Fatalf("tok-beta applied %d times, want exactly 1 (out=%q)", n, out)
	}
	if strings.Index(out, "tok-alpha") > strings.Index(out, "tok-beta") {
		t.Fatalf("input order violated: %q", out)
	}
}

func TestDetachReattachDeltaReplay(t *testing.T) {
	c, _ := newTestHost(t)
	ctx := testCtx(t)
	// Wait for input, then emit 30 paced lines and stay alive on cat. The
	// pacing busy-loop keeps output flowing after detach so the pump's
	// drain-while-detached behavior is what fills the ring.
	script := `read x; i=0; while [ $i -lt 30 ]; do i=$((i+1)); j=0; while [ $j -lt 300 ]; do j=$((j+1)); done; echo line$i; done; echo ALLDONE; cat`
	id := mustCreate(t, ctx, c, &genezav1.HostCreateRequest{
		SessionId: "gw-delta", Command: script,
		Pty: true, Detachable: true, Cols: 120, Rows: 40,
	})
	st1 := openAttach(t, ctx, c, id, 0)
	col1 := &collected{}
	recvUntil(t, st1, col1, func(c *collected) bool { return len(c.frames) >= 1 })
	if col1.frames[0].GetSnapshot() == nil {
		t.Fatal("fresh pty attach must start with a snapshot")
	}
	sendInput(t, st1, 1, "go\n")
	recvUntil(t, st1, col1, func(c *collected) bool {
		return strings.Contains(c.transcript(), "line5")
	})
	lastSeen := col1.maxOutputSeq()
	if lastSeen == 0 {
		t.Fatal("no output seq observed before detach")
	}
	detachAndDrain(t, st1)
	time.Sleep(300 * time.Millisecond) // generator keeps writing while detached

	st2 := openAttach(t, ctx, c, id, lastSeen)
	col2 := &collected{}
	recvUntil(t, st2, col2, func(c *collected) bool {
		return strings.Contains(c.transcript(), "ALLDONE")
	})
	for _, f := range col2.frames {
		if f.GetSnapshot() != nil {
			t.Fatal("reattach within ring coverage must take the delta path, got a snapshot")
		}
	}
	// Delta must continue exactly at lastSeen+1 with no gaps.
	want := lastSeen + 1
	for _, f := range col2.frames {
		o := f.GetOutput()
		if o == nil {
			continue
		}
		if o.Seq != want {
			t.Fatalf("output seq %d, want %d (gap or duplicate)", o.Seq, want)
		}
		want++
	}
	// Every line delivered exactly once across the detach boundary.
	all := col1.transcript() + col2.transcript()
	for i := 1; i <= 30; i++ {
		needle := fmt.Sprintf("line%d\r", i)
		if n := strings.Count(all, needle); n != 1 {
			t.Fatalf("%q seen %d times, want exactly 1", needle, n)
		}
	}
	if n := strings.Count(all, "ALLDONE"); n != 1 {
		t.Fatalf("ALLDONE seen %d times, want exactly 1", n)
	}
}

func TestReattachSnapshotWhenRingEvicted(t *testing.T) {
	c, _ := newTestHost(t)
	ctx := testCtx(t)
	// Tiny ring for sessions created after this policy push.
	if _, err := c.ApplyPolicy(ctx, &genezav1.HostPolicy{RingBufferBytes: 64}); err != nil {
		t.Fatalf("apply policy: %v", err)
	}
	id := mustCreate(t, ctx, c, &genezav1.HostCreateRequest{
		SessionId: "gw-snap", Command: "cat",
		Pty: true, Detachable: true, Cols: 80, Rows: 24,
	})
	st1 := openAttach(t, ctx, c, id, 0)
	col1 := &collected{}
	recvUntil(t, st1, col1, func(c *collected) bool { return len(c.frames) >= 1 })
	big := strings.Repeat("x", 100)
	for k := uint64(1); k <= 3; k++ {
		sendInput(t, st1, k, big+"\n")
		kk := k
		recvUntil(t, st1, col1, func(c *collected) bool {
			return c.ackCount(kk) >= 1 && len(c.transcript()) >= int(kk)*100
		})
	}
	detachAndDrain(t, st1)

	// Frame 2 fell out of the 64-byte ring long ago: snapshot path required.
	st2 := openAttach(t, ctx, c, id, 1)
	col2 := &collected{}
	recvUntil(t, st2, col2, func(c *collected) bool { return len(c.frames) >= 1 })
	snap := col2.frames[0].GetSnapshot()
	if snap == nil {
		t.Fatalf("expected snapshot fallback, got %v", col2.frames[0])
	}
	if snap.Seq <= 1 {
		t.Fatalf("snapshot seq %d must be the current seq, not the stale one", snap.Seq)
	}
	if snap.Cols != 80 || snap.Rows != 24 {
		t.Fatalf("snapshot size %dx%d, want 80x24", snap.Cols, snap.Rows)
	}
	if !bytes.Contains(snap.Data, []byte("xxx")) {
		t.Fatalf("snapshot repaint missing session content: %q", snap.Data)
	}
}

func TestPipeExitCodeEnvAndTombstone(t *testing.T) {
	c, _ := newTestHost(t)
	ctx := testCtx(t)
	id := mustCreate(t, ctx, c, &genezav1.HostCreateRequest{
		SessionId: "gw-exit",
		Command:   `read x; printf 'S:%s\n' "$GENEZA_SESSION"; exit 7`,
		Pty:       false,
	})
	st := openAttach(t, ctx, c, id, 0)
	col := &collected{}
	sendInput(t, st, 1, "go\n")
	recvUntil(t, st, col, func(c *collected) bool { return c.exit() != nil })
	if e := col.exit(); e.Code != 7 || e.Reason != "exited" {
		t.Fatalf("exit = %+v, want code 7 reason exited", e)
	}
	if !strings.Contains(col.transcript(), "S:gw-exit") {
		t.Fatalf("GENEZA_SESSION not propagated: %q", col.transcript())
	}
	// The tombstone stays listable as "exited".
	resp, err := c.List(ctx, &genezav1.HostListRequest{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, info := range resp.Sessions {
		if info.HostSessionId == id {
			found = true
			if info.State != stateExited {
				t.Fatalf("tombstone state = %q, want exited", info.State)
			}
		}
	}
	if !found {
		t.Fatal("exited session missing from List tombstones")
	}
	// Attaching to a tombstone reports the exit again.
	st2 := openAttach(t, ctx, c, id, 0)
	col2 := &collected{}
	recvUntil(t, st2, col2, func(c *collected) bool { return c.exit() != nil })
	if e := col2.exit(); e.Code != 7 {
		t.Fatalf("tombstone attach exit = %+v", e)
	}
}

func TestRecorderSpoolContract(t *testing.T) {
	c, h := newTestHost(t)
	ctx := testCtx(t)
	id := mustCreate(t, ctx, c, &genezav1.HostCreateRequest{
		SessionId: "gw-rec",
		Command:   `read x; printf 'hi-there\n'`,
		Pty:       false, Record: true,
	})
	st := openAttach(t, ctx, c, id, 0)
	col := &collected{}
	sendInput(t, st, 1, "go\n")
	recvUntil(t, st, col, func(c *collected) bool { return c.exit() != nil })

	// Observing Exit guarantees the spool files are complete (finalize order).
	castPath := filepath.Join(h.spoolDir, id+".cast")
	cast, err := os.ReadFile(castPath)
	if err != nil {
		t.Fatalf("read cast: %v", err)
	}
	lines := strings.SplitN(string(cast), "\n", 2)
	var hdr castHeader
	if err := json.Unmarshal([]byte(lines[0]), &hdr); err != nil {
		t.Fatalf("cast header: %v (%q)", err, lines[0])
	}
	if hdr.Version != 2 || hdr.Width != 80 || hdr.Height != 24 {
		t.Fatalf("cast header = %+v", hdr)
	}
	if !strings.Contains(string(cast), "hi-there") {
		t.Fatalf("cast missing output events: %q", cast)
	}
	done, err := os.ReadFile(filepath.Join(h.spoolDir, id+".done"))
	if err != nil {
		t.Fatalf("read done sidecar: %v", err)
	}
	var sidecar struct {
		SessionID string `json:"session_id"`
		Cast      string `json:"cast"`
	}
	if err := json.Unmarshal(done, &sidecar); err != nil {
		t.Fatalf("done sidecar: %v (%q)", err, done)
	}
	if sidecar.SessionID != "gw-rec" || sidecar.Cast != castPath {
		t.Fatalf("done sidecar = %+v, want session gw-rec cast %s", sidecar, castPath)
	}
}

func TestRunServesAndStopsOnSignal(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "session-host.sock")
	spool := filepath.Join(dir, "spool")
	done := make(chan error, 1)
	go func() { done <- Run("vtest", sock, spool) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket never appeared")
		}
		time.Sleep(10 * time.Millisecond)
	}
	conn, err := grpc.NewClient("unix://"+sock,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	hr, err := genezav1.NewSessionHostClient(conn).Health(testCtx(t), &genezav1.HostEmpty{})
	conn.Close()
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if !hr.Ok || hr.Version != "vtest" || hr.Active != 0 {
		t.Fatalf("health = %+v", hr)
	}

	// Run's NotifyContext is registered by now (Health worked), so SIGTERM
	// reaches it instead of killing the test binary.
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("kill: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v on graceful stop", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop on SIGTERM")
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket not cleaned up: %v", err)
	}
}

func TestCreateGuardrails(t *testing.T) {
	c, _ := newTestHost(t)
	ctx := testCtx(t)

	_, err := c.Create(ctx, &genezav1.HostCreateRequest{
		Command: "cat", Pty: false, OsUser: "no-such-user-zz",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("foreign os_user: got %v, want PermissionDenied", err)
	}

	_, err = c.Create(ctx, &genezav1.HostCreateRequest{
		Command: "cat", Pty: false, Detachable: true,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("detachable without pty: got %v, want InvalidArgument", err)
	}

	if _, err := c.ApplyPolicy(ctx, &genezav1.HostPolicy{ForbidDetach: true}); err != nil {
		t.Fatalf("apply policy: %v", err)
	}
	_, err = c.Create(ctx, &genezav1.HostCreateRequest{
		Command: "cat", Pty: true, Detachable: true,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("forbid_detach: got %v, want PermissionDenied", err)
	}
}
