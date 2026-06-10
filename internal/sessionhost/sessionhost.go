// Package sessionhost implements the geneza session host: the small, stable
// process that owns live PTYs and their buffers so worker restarts (binary
// updates) never kill live sessions (ARCHITECTURE.md §8). It serves the
// geneza.v1.SessionHost gRPC API over a unix socket; the worker bridges
// tunnel channels to it.
//
// v1 scope: sessions survive any client/worker/network failure but NOT the
// death of this process (no FD handoff yet) and not node reboot. A graceful
// stop therefore just stops serving, HUPs the children so shells wind down
// cleanly, flushes recordings, and exits.
package sessionhost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/hinshun/vt10x"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"osie.cloud/geneza/internal/defaults"
	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

// Policy defaults (overridable via ApplyPolicy; zero values in a pushed
// HostPolicy fall back to these, except idle_reap_sec where 0 means never).
const (
	defaultMaxSessions = 64
	defaultMaxDetached = 16
	defaultRingBytes   = 262144
	defaultDetachedTTL = 86400 * time.Second
)

// Test seams.
var (
	tombstoneTTL = 60 * time.Second
	reapInterval = 5 * time.Second
)

type policySettings struct {
	forbidDetach bool
	maxSessions  int
	maxDetached  int
	ringBytes    int
	detachedTTL  time.Duration
	idleReap     time.Duration // 0 = never
}

func defaultPolicy() *policySettings {
	return &policySettings{
		maxSessions: defaultMaxSessions,
		maxDetached: defaultMaxDetached,
		ringBytes:   defaultRingBytes,
		detachedTTL: defaultDetachedTTL,
	}
}

func normalizePolicy(p *genezav1.HostPolicy) *policySettings {
	pol := defaultPolicy()
	pol.forbidDetach = p.ForbidDetach
	if p.MaxSessions > 0 {
		pol.maxSessions = int(p.MaxSessions)
	}
	if p.MaxDetached > 0 {
		pol.maxDetached = int(p.MaxDetached)
	}
	if p.RingBufferBytes > 0 {
		pol.ringBytes = int(p.RingBufferBytes)
	}
	if p.DetachedTtlSec > 0 {
		pol.detachedTTL = time.Duration(p.DetachedTtlSec) * time.Second
	}
	pol.idleReap = time.Duration(p.IdleReapSec) * time.Second
	return pol
}

// host implements genezav1.SessionHostServer.
type host struct {
	genezav1.UnimplementedSessionHostServer

	version  string
	spoolDir string
	log      *slog.Logger

	pol       atomic.Pointer[policySettings]
	activeN   atomic.Int64 // running (non-exited) sessions
	detachedN atomic.Int64 // detachable sessions currently without a client

	mu       sync.Mutex
	sessions map[string]*session
}

func newHost(version, spoolDir string) *host {
	h := &host{
		version:  version,
		spoolDir: spoolDir,
		log:      slog.Default().With("component", "sessionhost"),
		sessions: make(map[string]*session),
	}
	h.pol.Store(defaultPolicy())
	return h
}

func (h *host) currentPolicy() *policySettings { return h.pol.Load() }

func (h *host) lookup(id string) *session {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[id]
}

func (h *host) remove(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.sessions, id)
}

func newHostID() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("host id entropy: %w", err)
	}
	return "h-" + hex.EncodeToString(b[:]), nil
}

// sessionUser resolves the OS account a session runs as. v1 supports only the
// agent's own user; anything else is rejected (no privilege transitions in
// this process).
func sessionUser(osUser string) (*user.User, error) {
	cur, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("resolve current user: %w", err)
	}
	if osUser != "" && osUser != cur.Username {
		return nil, fmt.Errorf("os_user %q not supported: v1 runs sessions only as the agent user %q", osUser, cur.Username)
	}
	return cur, nil
}

// loginShell picks the user's shell: $SHELL (we run as that user), then the
// /etc/passwd entry, then /bin/bash, then /bin/sh.
func loginShell(u *user.User) string {
	if sh := os.Getenv("SHELL"); sh != "" {
		return sh
	}
	if sh := passwdShell(u.Username); sh != "" {
		return sh
	}
	if _, err := os.Stat("/bin/bash"); err == nil {
		return "/bin/bash"
	}
	return "/bin/sh"
}

func passwdShell(username string) string {
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 7 && f[0] == username && f[6] != "" {
			return f[6]
		}
	}
	return ""
}

// minimalEnv builds the deliberately small child environment: PATH, HOME,
// USER, LANG inherited, TERM from the request, and GENEZA_SESSION for audit
// correlation. Nothing else from the host process leaks into sessions.
func minimalEnv(u *user.User, term, sessionID string) []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	env := []string{
		"PATH=" + path,
		"HOME=" + u.HomeDir,
		"USER=" + u.Username,
		"GENEZA_SESSION=" + sessionID,
	}
	if lang := os.Getenv("LANG"); lang != "" {
		env = append(env, "LANG="+lang)
	}
	if term != "" {
		env = append(env, "TERM="+term)
	}
	return env
}

func (h *host) Create(ctx context.Context, req *genezav1.HostCreateRequest) (*genezav1.HostCreateResponse, error) {
	pol := h.currentPolicy()
	if req.Detachable {
		if pol.forbidDetach {
			return nil, status.Error(codes.PermissionDenied, "detachable sessions are forbidden by policy")
		}
		if !req.Pty {
			return nil, status.Error(codes.InvalidArgument, "detachable sessions require pty mode")
		}
		// A detachable session is born unattached, i.e. actually detached,
		// so it counts toward max_detached from the start.
		if h.detachedN.Load() >= int64(pol.maxDetached) {
			return nil, status.Error(codes.ResourceExhausted, "max detached sessions reached")
		}
	}
	if h.activeN.Load() >= int64(pol.maxSessions) {
		return nil, status.Error(codes.ResourceExhausted, "max sessions reached")
	}
	u, err := sessionUser(req.OsUser)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	s, err := h.startSession(req, u, pol)
	if err != nil {
		if status.Code(err) != codes.Unknown {
			return nil, err
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	h.log.Info("session created",
		"host_session_id", s.hostID, "session_id", s.sessionID,
		"user", s.user, "action", s.action, "pty", s.ptyMode,
		"detachable", s.detachable, "record", req.Record)
	return &genezav1.HostCreateResponse{HostSessionId: s.hostID}, nil
}

func (h *host) startSession(req *genezav1.HostCreateRequest, u *user.User, pol *policySettings) (*session, error) {
	cols, rows := req.Cols, req.Rows
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}

	var cmd *exec.Cmd
	shellName := "/bin/sh"
	switch {
	case req.Pty && req.Command == "":
		sh := loginShell(u)
		shellName = sh
		cmd = exec.Command(sh, "-l")
	case req.Pty:
		cmd = exec.Command("/bin/sh", "-lc", req.Command)
	default:
		if req.Command == "" {
			return nil, status.Error(codes.InvalidArgument, "pipe mode requires a command")
		}
		cmd = exec.Command("/bin/sh", "-lc", req.Command)
	}
	term := req.Env["TERM"]
	if term == "" && req.Pty {
		term = "xterm-256color" // a pty session without TERM breaks every app
	}
	cmd.Env = minimalEnv(u, term, req.SessionId)
	if st, err := os.Stat(u.HomeDir); err == nil && st.IsDir() {
		cmd.Dir = u.HomeDir
	} else {
		cmd.Dir = "/"
	}

	hostID, err := newHostID()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	s := &session{
		hostID:        hostID,
		sessionID:     req.SessionId,
		user:          req.User,
		action:        req.Action,
		ptyMode:       req.Pty,
		detachable:    req.Detachable,
		srv:           h,
		cmd:           cmd,
		state:         stateDetached, // born unattached
		started:       now,
		lastActivity:  now,
		detachedSince: now,
		cols:          cols,
		rows:          rows,
		ring:          newRing(pol.ringBytes),
		done:          make(chan struct{}),
	}
	if req.Record {
		rec, err := newRecorder(h.spoolDir, hostID, cols, rows, term, shellName)
		if err != nil {
			return nil, err
		}
		s.rec = rec
	}

	if req.Pty {
		s.vt = vt10x.New(vt10x.WithSize(int(cols), int(rows)))
		ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
		if err != nil {
			if s.rec != nil {
				s.rec.abort()
			}
			return nil, fmt.Errorf("start pty session: %w", err)
		}
		s.ptmx = ptmx
		s.pumps.Add(1)
	} else {
		stdin, err := cmd.StdinPipe()
		if err != nil {
			if s.rec != nil {
				s.rec.abort()
			}
			return nil, err
		}
		// Manual pipes for stdout/stderr: exec.Cmd passes *os.File straight
		// through, so Wait has no copy goroutines and our pumps fully own
		// the read side until EOF.
		outR, outW, err := os.Pipe()
		if err != nil {
			if s.rec != nil {
				s.rec.abort()
			}
			return nil, err
		}
		errR, errW, err := os.Pipe()
		if err != nil {
			outR.Close()
			outW.Close()
			if s.rec != nil {
				s.rec.abort()
			}
			return nil, err
		}
		cmd.Stdout, cmd.Stderr = outW, errW
		if err := cmd.Start(); err != nil {
			outR.Close()
			outW.Close()
			errR.Close()
			errW.Close()
			if s.rec != nil {
				s.rec.abort()
			}
			return nil, fmt.Errorf("start pipe session: %w", err)
		}
		outW.Close() // child holds the write ends now
		errW.Close()
		s.stdin = stdin
		s.outR, s.errR = outR, errR
		s.pumps.Add(2)
	}

	h.mu.Lock()
	h.sessions[hostID] = s
	h.mu.Unlock()
	h.activeN.Add(1)
	if req.Detachable {
		s.detachedCounted = true
		h.detachedN.Add(1)
	}

	if req.Pty {
		go s.pump(s.ptmx, false)
	} else {
		go s.pump(s.outR, false)
		go s.pump(s.errR, true)
	}
	go s.waiter()
	return s, nil
}

func (h *host) List(ctx context.Context, _ *genezav1.HostListRequest) (*genezav1.HostListResponse, error) {
	h.mu.Lock()
	list := make([]*session, 0, len(h.sessions))
	for _, s := range h.sessions {
		list = append(list, s)
	}
	h.mu.Unlock()
	infos := make([]*genezav1.HostSessionInfo, 0, len(list))
	for _, s := range list {
		infos = append(infos, s.info())
	}
	sort.Slice(infos, func(i, j int) bool {
		if infos[i].StartedUnix != infos[j].StartedUnix {
			return infos[i].StartedUnix < infos[j].StartedUnix
		}
		return infos[i].HostSessionId < infos[j].HostSessionId
	})
	return &genezav1.HostListResponse{Sessions: infos}, nil
}

func (h *host) Kill(ctx context.Context, req *genezav1.HostKillRequest) (*genezav1.HostEmpty, error) {
	s := h.lookup(req.HostSessionId)
	if s == nil {
		return nil, status.Error(codes.NotFound, "unknown host session "+req.HostSessionId)
	}
	// SIGHUP first (interactive shells ignore SIGTERM), SIGKILL after grace.
	s.terminate(reasonKilled, syscall.SIGHUP)
	return &genezav1.HostEmpty{}, nil
}

func (h *host) Health(ctx context.Context, _ *genezav1.HostEmpty) (*genezav1.HostHealthResponse, error) {
	return &genezav1.HostHealthResponse{
		Ok:       true,
		Active:   uint32(h.activeN.Load()),
		Detached: uint32(h.detachedN.Load()),
		Version:  h.version,
	}, nil
}

func (h *host) ApplyPolicy(ctx context.Context, p *genezav1.HostPolicy) (*genezav1.HostEmpty, error) {
	pol := normalizePolicy(p)
	h.pol.Store(pol)
	h.log.Info("policy applied",
		"forbid_detach", pol.forbidDetach, "max_sessions", pol.maxSessions,
		"max_detached", pol.maxDetached, "ring_buffer_bytes", pol.ringBytes,
		"detached_ttl", pol.detachedTTL, "idle_reap", pol.idleReap)
	return &genezav1.HostEmpty{}, nil
}

// reaper enforces detached_ttl_sec, idle_reap_sec and (after policy changes)
// the max_detached cap on sessions running without a client.
func (h *host) reaper(ctx context.Context) {
	t := time.NewTicker(reapInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.reapPass(time.Now())
		}
	}
}

func (h *host) reapPass(now time.Time) {
	pol := h.currentPolicy()
	h.mu.Lock()
	list := make([]*session, 0, len(h.sessions))
	for _, s := range h.sessions {
		list = append(list, s)
	}
	h.mu.Unlock()

	type cand struct {
		s     *session
		since time.Time
	}
	var counted []cand
	for _, s := range list {
		s.mu.Lock()
		if s.exited || s.client != nil {
			s.mu.Unlock()
			continue
		}
		since := s.detachedSince
		idle := s.lastActivity
		isCounted := s.detachedCounted
		s.mu.Unlock()

		switch {
		case pol.detachedTTL > 0 && now.Sub(since) > pol.detachedTTL:
			h.log.Info("reaping detached session (ttl)", "host_session_id", s.hostID)
			s.terminate(reasonReaped, syscall.SIGHUP)
		case pol.idleReap > 0 && now.Sub(idle) > pol.idleReap:
			h.log.Info("reaping detached session (idle)", "host_session_id", s.hostID)
			s.terminate(reasonReaped, syscall.SIGHUP)
		default:
			if isCounted {
				counted = append(counted, cand{s, since})
			}
		}
	}
	over := int(h.detachedN.Load()) - pol.maxDetached
	if over <= 0 {
		return
	}
	sort.Slice(counted, func(i, j int) bool { return counted[i].since.Before(counted[j].since) })
	for i := 0; i < over && i < len(counted); i++ {
		h.log.Info("reaping detached session (over cap)", "host_session_id", counted[i].s.hostID)
		counted[i].s.terminate(reasonReaped, syscall.SIGHUP)
	}
}

// shutdown HUPs every running session and waits briefly for finalization so
// recordings land in the spool with their .done sidecars before we exit.
func (h *host) shutdown(grace time.Duration) {
	h.mu.Lock()
	list := make([]*session, 0, len(h.sessions))
	for _, s := range h.sessions {
		list = append(list, s)
	}
	h.mu.Unlock()
	for _, s := range list {
		s.terminate(reasonReaped, syscall.SIGHUP)
	}
	deadline := time.After(grace)
	for _, s := range list {
		select {
		case <-s.done:
		case <-deadline:
			return
		}
	}
}

// Run creates the socket directory (0700), removes any stale socket, listens,
// and serves the SessionHost service until SIGTERM/SIGINT. Live sessions
// cannot survive this process's death in v1 (no PTY FD handoff), so a
// graceful stop means: stop serving, HUP the children, flush recordings,
// exit. Exactly one instance per socket is assumed (the agent bootstrap
// supervises us).
func Run(version, socketPath, spoolDir string) error {
	logger := slog.Default().With("component", "sessionhost")
	if socketPath == "" {
		socketPath = defaults.SessionHostSock
	}
	if spoolDir == "" {
		spoolDir = filepath.Join(defaults.VarDir, "spool")
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		return fmt.Errorf("create spool dir: %w", err)
	}
	spoolAbs, err := filepath.Abs(spoolDir)
	if err != nil {
		return fmt.Errorf("resolve spool dir: %w", err)
	}
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", socketPath, err)
	}
	// Only the agent user may drive sessions; fail closed if we can't pin it.
	if err := os.Chmod(socketPath, 0o600); err != nil {
		ln.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	h := newHost(version, spoolAbs)
	h.log = logger
	gs := grpc.NewServer()
	genezav1.RegisterSessionHostServer(gs, h)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go h.reaper(ctx)

	serveErr := make(chan error, 1)
	go func() { serveErr <- gs.Serve(ln) }()
	logger.Info("session host serving",
		"socket", socketPath, "spool", spoolAbs, "version", version)

	var runErr error
	select {
	case <-ctx.Done():
		logger.Info("signal received, stopping session host")
		gs.Stop() // attach streams cannot outlive us; no point draining them
		<-serveErr
		h.shutdown(3 * time.Second)
	case runErr = <-serveErr:
	}
	os.Remove(socketPath)
	return runErr
}
