package update

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// SupervisorOpts tunes a Supervisor; zero values take the documented
// defaults (1s..30s restart backoff, 10s SIGTERM grace).
type SupervisorOpts struct {
	MinBackoff        time.Duration // first restart delay (default 1s)
	MaxBackoff        time.Duration // backoff cap (default 30s)
	BackoffResetAfter time.Duration // uptime that resets backoff to min (default 30s)
	Grace             time.Duration // SIGTERM -> SIGKILL window in Stop (default 10s)
	Stdout            io.Writer     // child stdout (default os.Stdout)
	Stderr            io.Writer     // child stderr (default os.Stderr)
}

func (o *SupervisorOpts) withDefaults() SupervisorOpts {
	out := SupervisorOpts{}
	if o != nil {
		out = *o
	}
	if out.MinBackoff <= 0 {
		out.MinBackoff = time.Second
	}
	if out.MaxBackoff <= 0 {
		out.MaxBackoff = 30 * time.Second
	}
	if out.BackoffResetAfter <= 0 {
		out.BackoffResetAfter = 30 * time.Second
	}
	if out.Grace <= 0 {
		out.Grace = 10 * time.Second
	}
	if out.Stdout == nil {
		out.Stdout = os.Stdout
	}
	if out.Stderr == nil {
		out.Stderr = os.Stderr
	}
	return out
}

// Supervisor runs one child process in a restart-with-backoff loop. It is
// single-use: Start once, Stop once. The command line is produced by a
// function so a long-lived child (the session host) can be restarted from
// whatever version directory is current at the time it dies, even if the
// directory it was originally started from has since been pruned.
type Supervisor struct {
	name  string
	cmdFn func() (path string, args []string)
	log   *slog.Logger
	opts  SupervisorOpts

	mu       sync.Mutex
	proc     *os.Process
	stopping bool
	started  bool
	stopCh   chan struct{}
	done     chan struct{}
}

// NewSupervisor builds a supervisor for the named child; cmdFn is consulted
// before every (re)start.
func NewSupervisor(name string, cmdFn func() (string, []string), log *slog.Logger, opts *SupervisorOpts) *Supervisor {
	return &Supervisor{
		name:   name,
		cmdFn:  cmdFn,
		log:    log,
		opts:   opts.withDefaults(),
		stopCh: make(chan struct{}),
		done:   make(chan struct{}),
	}
}

// StartSupervised is the fixed-argv convenience: supervise `path args...`
// with default options, already running.
func StartSupervised(name, path string, args []string, log *slog.Logger) *Supervisor {
	s := NewSupervisor(name, func() (string, []string) { return path, args }, log, nil)
	s.Start()
	return s
}

// Start launches the supervision loop.
func (s *Supervisor) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.stopping {
		return
	}
	s.started = true
	go s.run()
}

func (s *Supervisor) run() {
	defer close(s.done)
	backoff := s.opts.MinBackoff
	for {
		// Start under the lock so Stop either sees the live process or the
		// stopping flag prevents a new one — no window where a fresh child
		// escapes the SIGTERM.
		s.mu.Lock()
		if s.stopping {
			s.mu.Unlock()
			return
		}
		path, args := s.cmdFn()
		cmd := exec.Command(path, args...)
		cmd.Stdout = s.opts.Stdout
		cmd.Stderr = s.opts.Stderr
		// When Stdout/Stderr are not *os.File, exec uses pipes and Wait
		// blocks until they close — which a misbehaving grandchild that
		// inherited them can defer forever. Bound that wait.
		cmd.WaitDelay = s.opts.Grace
		startErr := cmd.Start()
		if startErr == nil {
			s.proc = cmd.Process
		}
		s.mu.Unlock()

		startedAt := time.Now()
		if startErr != nil {
			s.log.Error("child failed to start", "child", s.name, "path", path, "err", startErr, "retry_in", backoff)
		} else {
			s.log.Info("child started", "child", s.name, "path", path, "pid", cmd.Process.Pid)
			werr := cmd.Wait()
			s.mu.Lock()
			s.proc = nil
			stopping := s.stopping
			s.mu.Unlock()
			if stopping {
				s.log.Info("child stopped", "child", s.name, "exit", exitString(werr))
				return
			}
			uptime := time.Since(startedAt)
			if uptime >= s.opts.BackoffResetAfter {
				backoff = s.opts.MinBackoff
			}
			s.log.Error("child exited unexpectedly; restarting",
				"child", s.name, "exit", exitString(werr), "uptime", uptime, "retry_in", backoff)
		}

		select {
		case <-s.stopCh:
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > s.opts.MaxBackoff {
			backoff = s.opts.MaxBackoff
		}
	}
}

// Stop terminates the supervision loop and the child: SIGTERM, wait up to
// Grace (or ctx), then SIGKILL. Blocks until the loop has fully exited.
func (s *Supervisor) Stop(ctx context.Context) {
	s.mu.Lock()
	if s.stopping {
		started := s.started
		s.mu.Unlock()
		if started {
			<-s.done
		}
		return
	}
	s.stopping = true
	close(s.stopCh)
	started := s.started
	p := s.proc
	s.mu.Unlock()

	if !started {
		return
	}
	if p != nil {
		s.log.Info("stopping child", "child", s.name, "pid", p.Pid, "grace", s.opts.Grace)
		_ = p.Signal(syscall.SIGTERM)
	}
	select {
	case <-s.done:
		return
	case <-time.After(s.opts.Grace):
	case <-ctx.Done():
	}
	s.mu.Lock()
	p = s.proc
	s.mu.Unlock()
	if p != nil {
		s.log.Warn("child did not exit within grace; killing", "child", s.name, "pid", p.Pid)
		_ = p.Kill()
	}
	<-s.done
}

func exitString(err error) string {
	if err == nil {
		return "exit status 0"
	}
	return err.Error()
}
