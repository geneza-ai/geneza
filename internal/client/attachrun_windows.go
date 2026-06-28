//go:build windows

package client

import "os"

// notifyWinch is a no-op on Windows, which has no window-resize signal. The
// host receives the terminal geometry once at attach time; live resizes during
// a session are not propagated. The session otherwise behaves identically.
func notifyWinch(ch chan os.Signal) {}
