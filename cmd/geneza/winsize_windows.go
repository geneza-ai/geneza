//go:build windows

package main

import "golang.org/x/crypto/ssh"

// watchWindowSize is a no-op on Windows, which has no window-resize signal. The
// remote PTY is sized once from the initial geometry at session start; live
// resizes are not propagated.
func watchWindowSize(s *ssh.Session) {}
