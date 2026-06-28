//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// watchWindowSize forwards local terminal resizes to the remote PTY for the
// lifetime of the exec session: on every SIGWINCH it reads the new geometry and
// sends an ssh window-change request. The watcher stops when the process exits
// (exec runs a single command and returns). Windows has no SIGWINCH; see the
// no-op in winsize_windows.go.
func watchWindowSize(s *ssh.Session) {
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	go func() {
		for range winch {
			if cw, chh, gerr := term.GetSize(int(os.Stdout.Fd())); gerr == nil {
				s.WindowChange(chh, cw) //nolint:errcheck
			}
		}
	}()
}
