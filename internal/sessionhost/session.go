package sessionhost

import (
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/hinshun/vt10x"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

const (
	stateAttached = "attached"
	stateDetached = "detached"
	stateExited   = "exited"

	reasonKilled = "killed"
	reasonReaped = "reaped"

	pumpBufSize     = 32 * 1024
	clientChanDepth = 256
	drainGrace      = 2 * time.Second
	killEscalation  = 5 * time.Second
)

var signalByName = map[string]syscall.Signal{
	"INT":  syscall.SIGINT,
	"TERM": syscall.SIGTERM,
	"HUP":  syscall.SIGHUP,
	"QUIT": syscall.SIGQUIT,
	"KILL": syscall.SIGKILL,
	"USR1": syscall.SIGUSR1,
	"USR2": syscall.SIGUSR2,
}

func sigName(sig syscall.Signal) string {
	for name, s := range signalByName {
		if s == sig {
			return name
		}
	}
	return strings.ToUpper(strings.TrimPrefix(sig.String(), "signal "))
}

// attachedClient is the live-delivery endpoint of the (at most one) client
// attached to a session. ch is drained by the per-stream writer goroutine;
// stop is closed exactly once to preempt/drop the client.
type attachedClient struct {
	ch       chan *genezav1.HostToClient
	stop     chan struct{}
	stopOnce sync.Once
}

func newAttachedClient() *attachedClient {
	return &attachedClient{
		ch:   make(chan *genezav1.HostToClient, clientChanDepth),
		stop: make(chan struct{}),
	}
}

func (c *attachedClient) close() { c.stopOnce.Do(func() { close(c.stop) }) }

// session owns one shell/exec process, its PTY (or pipes), the scrollback
// ring, the virtual terminal, and the optional recorder. It outlives any
// attach stream: the pump drains output whether or not anyone is watching.
type session struct {
	hostID     string
	sessionID  string // gateway session id (audit correlation, GENEZA_SESSION)
	user       string
	action     string
	ptyMode    bool
	detachable bool
	srv        *host

	cmd   *exec.Cmd
	ptmx  *os.File       // pty mode
	stdin io.WriteCloser // pipe mode
	outR  *os.File       // pipe mode read ends; force-closed to unstick pumps
	errR  *os.File

	mu              sync.Mutex
	state           string
	started         time.Time
	lastActivity    time.Time // last output or input
	detachedSince   time.Time
	detachedCounted bool // this session currently counts toward max_detached
	cols, rows      uint32
	vt              vt10x.Terminal // pty mode only; nil after exit
	ring            *ring
	seq             uint64 // last assigned output seq (output+stderr shared)
	lastInputSeq    uint64
	stdinClosed     bool
	client          *attachedClient
	rec             *recorder
	exited          bool
	exitCode        int32
	exitReason      string
	killReason      string // set by Kill/reaper/disconnect before signaling

	pumps sync.WaitGroup
	done  chan struct{} // closed after finalize completes
}

func snapshotFrame(data []byte, seq uint64, cols, rows uint32) *genezav1.HostToClient {
	return &genezav1.HostToClient{Msg: &genezav1.HostToClient_Snapshot{
		Snapshot: &genezav1.Snapshot{Data: data, Seq: seq, Cols: cols, Rows: rows},
	}}
}

func chunkFrame(seq uint64, stderr bool, data []byte) *genezav1.HostToClient {
	if stderr {
		return &genezav1.HostToClient{Msg: &genezav1.HostToClient_Stderr{
			Stderr: &genezav1.Stderr{Seq: seq, Data: data},
		}}
	}
	return &genezav1.HostToClient{Msg: &genezav1.HostToClient_Output{
		Output: &genezav1.Output{Seq: seq, Data: data},
	}}
}

func exitFrame(code int32, reason string) *genezav1.HostToClient {
	return &genezav1.HostToClient{Msg: &genezav1.HostToClient_Exit{
		Exit: &genezav1.Exit{Code: code, Reason: reason},
	}}
}

func ackFrame(seq uint64) *genezav1.HostToClient {
	return &genezav1.HostToClient{Msg: &genezav1.HostToClient_InputAck{
		InputAck: &genezav1.InputAck{Seq: seq},
	}}
}

// pump reads the PTY master (or one pipe) forever — attached or not — so the
// child never blocks on write. This is THE correctness property of the
// session host. Each chunk gets the next shared seq, lands in the ring, feeds
// the virtual terminal and the recorder, and is delivered to the attached
// client without ever blocking: a slow client is dropped from live delivery
// and must resync from the ring/snapshot on reattach.
func (s *session) pump(r io.Reader, isStderr bool) {
	defer s.pumps.Done()
	buf := make([]byte, pumpBufSize)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			s.mu.Lock()
			s.seq++
			seq := s.seq
			s.ring.add(seq, isStderr, data)
			if s.vt != nil {
				_, _ = s.vt.Write(data) // vt locks itself and never blocks
			}
			if s.rec != nil {
				s.rec.output(data)
			}
			s.lastActivity = time.Now()
			s.deliverLocked(chunkFrame(seq, isStderr, data))
			s.mu.Unlock()
		}
		if err != nil {
			// EIO (pty after child exit), EOF (pipes) or forced close.
			return
		}
	}
}

// deliverLocked enqueues a frame for the attached client without blocking.
// If the client cannot keep up it is dropped from live delivery (never block
// the pump); a detachable session becomes detached, a non-detachable one is
// terminated, matching the disconnect rules.
func (s *session) deliverLocked(m *genezav1.HostToClient) {
	cl := s.client
	if cl == nil {
		return
	}
	select {
	case cl.ch <- m:
	default:
		s.client = nil
		cl.close()
		if s.exited {
			return
		}
		if s.detachable {
			s.markDetachedLocked()
			return
		}
		s.state = stateDetached
		s.detachedSince = time.Now()
		go s.terminate(reasonKilled, syscall.SIGHUP)
	}
}

// markDetachedLocked transitions to detached state and maintains the
// max_detached accounting (only detachable sessions count).
func (s *session) markDetachedLocked() {
	s.state = stateDetached
	s.detachedSince = time.Now()
	if s.detachable && !s.detachedCounted {
		s.detachedCounted = true
		s.srv.detachedN.Add(1)
	}
}

// attach registers cl as the attached client (preempting any current one,
// tmux attach -d semantics) and computes the initial frames atomically with
// registration so no output frame is lost or duplicated: frames produced
// after the computed point land in cl.ch and are sent after the initial set.
//
// Reply rules: pty mode with last_seen_seq > 0 and an intact ring range gets
// a pure delta (no repaint); otherwise a vt10x snapshot. Pipe mode has no
// screen to repaint, so it gets a delta whenever the ring covers
// (last_seen, cur] — prefixed by an empty Snapshot marker on a fresh attach —
// and an empty Snapshot carrying the current seq when data was lost.
func (s *session) attach(cl *attachedClient, lastSeen uint64) (initial []*genezav1.HostToClient, registered bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exited {
		// Tombstone: report how the session ended, do not register.
		return []*genezav1.HostToClient{exitFrame(s.exitCode, s.exitReason)}, false
	}
	if old := s.client; old != nil {
		old.close()
	} else if s.detachedCounted {
		s.detachedCounted = false
		s.srv.detachedN.Add(-1)
	}
	s.client = cl
	s.state = stateAttached
	s.detachedSince = time.Time{}

	cur := s.seq
	chunks, ok := s.ring.deltaFrom(lastSeen, cur)
	if ok && (lastSeen > 0 || !s.ptyMode) {
		if !s.ptyMode && lastSeen == 0 {
			initial = append(initial, snapshotFrame(nil, 0, s.cols, s.rows))
		}
		for _, c := range chunks {
			initial = append(initial, chunkFrame(c.seq, c.stderr, c.data))
		}
		return initial, true
	}
	var data []byte
	if s.vt != nil {
		data = renderSnapshot(s.vt)
	}
	return []*genezav1.HostToClient{snapshotFrame(data, cur, s.cols, s.rows)}, true
}

// clientGone applies the disconnect rules when an attach stream ends without
// an accepted Detach: detachable sessions persist (unless over the detached
// cap, in which case we fail closed and reap), non-detachable sessions die
// with their connection (ssh semantics). No-op if cl is no longer the
// registered client (preempted/dropped/detached elsewhere).
func (s *session) clientGone(cl *attachedClient) {
	s.mu.Lock()
	if s.client != cl {
		s.mu.Unlock()
		return
	}
	s.client = nil
	cl.close()
	if s.exited {
		s.mu.Unlock()
		return
	}
	if s.detachable {
		pol := s.srv.currentPolicy()
		if s.srv.detachedN.Load() < int64(pol.maxDetached) {
			s.markDetachedLocked()
			s.mu.Unlock()
			return
		}
		s.state = stateDetached
		s.detachedSince = time.Now()
		s.mu.Unlock()
		s.terminate(reasonReaped, syscall.SIGHUP)
		return
	}
	s.state = stateDetached
	s.detachedSince = time.Now()
	s.mu.Unlock()
	s.terminate(reasonKilled, syscall.SIGHUP)
}

// detachRequest handles an explicit Detach message. On success the session
// keeps running with the pump draining; the stream is closed by the caller.
func (s *session) detachRequest(cl *attachedClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != cl || s.exited {
		return nil // stale client or already over; nothing to do
	}
	if !s.detachable {
		return status.Error(codes.FailedPrecondition, "session is not detachable")
	}
	if s.srv.detachedN.Load() >= int64(s.srv.currentPolicy().maxDetached) {
		// Rejecting still ends the stream; clientGone then reaps rather than
		// letting an over-cap session linger detached. Fail closed.
		return status.Error(codes.ResourceExhausted, "max detached sessions reached")
	}
	s.client = nil
	s.markDetachedLocked()
	return nil
}

// handleInput applies sequence-numbered input. Frames with seq <= the last
// applied seq are deduped (reconnect replays), but every frame is acked so a
// reconnecting client can advance. The write happens outside s.mu: a full
// kernel PTY input buffer must never be able to block the pump.
func (s *session) handleInput(cl *attachedClient, in *genezav1.Input) {
	s.mu.Lock()
	if s.client != cl || s.exited {
		s.mu.Unlock()
		return
	}
	apply := in.Seq > s.lastInputSeq
	if apply {
		s.lastInputSeq = in.Seq
	}
	var w io.Writer
	if s.ptyMode {
		w = s.ptmx
	} else if !s.stdinClosed {
		w = s.stdin
	}
	s.lastActivity = time.Now()
	s.mu.Unlock()

	if apply && w != nil && len(in.Data) > 0 {
		_, _ = w.Write(in.Data) // a write error means the process is exiting
	}

	s.mu.Lock()
	if s.client == cl {
		s.deliverLocked(ackFrame(in.Seq))
	}
	s.mu.Unlock()
}

func (s *session) handleResize(cl *attachedClient, cols, rows uint32) {
	if cols == 0 || rows == 0 {
		return
	}
	s.mu.Lock()
	if s.client != cl || s.exited {
		s.mu.Unlock()
		return
	}
	s.cols, s.rows = cols, rows
	ptmx := s.ptmx
	if s.vt != nil {
		s.vt.Resize(int(cols), int(rows))
	}
	if s.rec != nil {
		s.rec.resizeEvent(cols, rows)
	}
	s.mu.Unlock()
	if ptmx != nil {
		_ = pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
	}
}

func (s *session) handleSignal(cl *attachedClient, name string) {
	sig, ok := signalByName[strings.TrimPrefix(strings.ToUpper(name), "SIG")]
	if !ok {
		s.srv.log.Warn("ignoring unknown signal", "signal", name, "host_session_id", s.hostID)
		return
	}
	s.mu.Lock()
	var proc *os.Process
	if s.client == cl && !s.exited {
		proc = s.cmd.Process
	}
	s.mu.Unlock()
	if proc != nil {
		_ = proc.Signal(sig)
	}
}

func (s *session) handleStdinEOF(cl *attachedClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != cl || s.exited || s.ptyMode || s.stdinClosed || s.stdin == nil {
		return
	}
	s.stdinClosed = true
	s.stdin.Close()
}

// terminate signals the process and escalates to SIGKILL after a grace
// period. The first caller's reason wins and overrides the wait status in the
// final Exit frame.
func (s *session) terminate(reason string, sig syscall.Signal) {
	s.mu.Lock()
	if s.exited {
		s.mu.Unlock()
		return
	}
	if s.killReason == "" {
		s.killReason = reason
	}
	proc := s.cmd.Process
	s.mu.Unlock()
	if proc == nil {
		return
	}
	_ = proc.Signal(sig)
	if sig == syscall.SIGKILL {
		return
	}
	go func() {
		select {
		case <-s.done:
		case <-time.After(killEscalation):
			_ = proc.Signal(syscall.SIGKILL)
		}
	}()
}

// waiter reaps the process, lets the pumps drain the output tail, force-closes
// the fds if a grandchild keeps them open, and finalizes the session.
func (s *session) waiter() {
	_ = s.cmd.Wait() // exit details come from ProcessState in finalize
	pumpsDone := make(chan struct{})
	go func() {
		s.pumps.Wait()
		close(pumpsDone)
	}()
	select {
	case <-pumpsDone:
	case <-time.After(drainGrace):
		s.forceCloseReaders()
		<-pumpsDone
	}
	s.finalize()
}

func (s *session) forceCloseReaders() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ptmx != nil {
		s.ptmx.Close()
	}
	if s.outR != nil {
		s.outR.Close()
	}
	if s.errR != nil {
		s.errR.Close()
	}
}

func exitStatus(cmd *exec.Cmd) (int32, string) {
	ps := cmd.ProcessState
	if ps == nil {
		return -1, "exited"
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		sig := ws.Signal()
		return int32(128 + int(sig)), "signaled:" + sigName(sig)
	}
	return int32(ps.ExitCode()), "exited"
}

// finalize records the exit, finishes the recording (the .done sidecar must
// exist before the Exit frame can be observed by the worker), zeroizes the
// buffers (they held plaintext), notifies the attached client, and schedules
// the tombstone removal. Runs exactly once, from waiter.
func (s *session) finalize() {
	code, reason := exitStatus(s.cmd)
	s.mu.Lock()
	if s.killReason != "" {
		reason = s.killReason
	}
	s.exited = true
	s.state = stateExited
	s.exitCode, s.exitReason = code, reason
	if s.detachedCounted {
		s.detachedCounted = false
		s.srv.detachedN.Add(-1)
	}
	if s.rec != nil {
		if err := s.rec.finalize(s.sessionID); err != nil {
			s.srv.log.Warn("finalize recording", "host_session_id", s.hostID, "error", err)
		}
		s.rec = nil
	}
	s.ring.zeroize()
	if s.vt != nil {
		// RIS best-effort overwrites the main grid with blanks before the
		// reference is dropped; the alt screen may retain data (v1 gap).
		_, _ = s.vt.Write([]byte("\x1bc"))
		s.vt = nil
	}
	if s.ptmx != nil {
		s.ptmx.Close()
	}
	if s.stdin != nil && !s.stdinClosed {
		s.stdinClosed = true
		s.stdin.Close()
	}
	s.deliverLocked(exitFrame(code, reason))
	s.mu.Unlock()

	s.srv.activeN.Add(-1)
	close(s.done)
	s.srv.log.Info("session exited",
		"host_session_id", s.hostID, "session_id", s.sessionID,
		"code", code, "reason", reason)
	// Keep a tombstone visible in List for a while so the worker can observe
	// the exit across its own restarts.
	time.AfterFunc(tombstoneTTL, func() { s.srv.remove(s.hostID) })
}

func (s *session) info() *genezav1.HostSessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &genezav1.HostSessionInfo{
		HostSessionId:    s.hostID,
		SessionId:        s.sessionID,
		User:             s.user,
		Action:           s.action,
		State:            s.state,
		Detachable:       s.detachable,
		StartedUnix:      s.started.Unix(),
		LastActivityUnix: s.lastActivity.Unix(),
		Cols:             s.cols,
		Rows:             s.rows,
	}
}
