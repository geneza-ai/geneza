package agentd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const hostProbePeriod = 10 * time.Second

// superviseSessionHost keeps a session host answering on the unix socket:
// if nothing healthy responds within ~5s, spawn our own executable as
// 'session-host' and supervise it with backoff.
//
// The child is deliberately NOT tied to our lifetime (no kill on shutdown,
// own session via Setsid): live PTY sessions must survive worker restarts —
// that is the whole point of the separate session-host process.
func (w *Worker) superviseSessionHost(ctx context.Context) {
	backoff := reconnectBackoffLo
	for {
		if ctx.Err() != nil {
			return
		}
		if _, ok := w.hostHealth(ctx); ok {
			backoff = reconnectBackoffLo
			select {
			case <-ctx.Done():
				return
			case <-time.After(hostProbePeriod):
			}
			continue
		}

		exe, err := os.Executable()
		if err != nil {
			w.log.Error("cannot locate own executable to spawn session host", "err", err)
			return
		}
		if err := os.MkdirAll(filepath.Dir(w.cfg.SessionHostSocket), 0o755); err != nil {
			w.log.Error("create session host socket dir", "err", err)
		}
		if err := os.MkdirAll(w.cfg.SpoolDir, 0o700); err != nil {
			w.log.Error("create spool dir", "err", err)
		}

		cmd := exec.Command(exe, "session-host",
			"--socket", w.cfg.SessionHostSocket,
			"--spool", w.cfg.SpoolDir)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			w.log.Error("spawn session host", "err", err)
		} else {
			w.log.Info("spawned session host", "pid", cmd.Process.Pid, "socket", w.cfg.SessionHostSocket)
			// Give it a moment to bind, then push current policy.
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			if _, ok := w.hostHealth(ctx); ok {
				w.applyHostPolicy(ctx)
				backoff = reconnectBackoffLo
			}
			err = cmd.Wait() // blocks while the child runs
			w.log.Warn("session host exited", "err", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > reconnectBackoffHi {
			backoff = reconnectBackoffHi
		}
	}
}
