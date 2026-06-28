//go:build !windows

package client

import (
	"os"
	"os/signal"
	"syscall"
)

// notifyWinch wires terminal window-resize (SIGWINCH) notifications to ch so an
// interactive session forwards the new geometry to the host as the local window
// changes. Windows has no equivalent signal; see notifyWinch in
// attachrun_windows.go.
func notifyWinch(ch chan os.Signal) {
	signal.Notify(ch, syscall.SIGWINCH)
}
