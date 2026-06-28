//go:build freebsd || openbsd || netbsd || dragonfly

package platform

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// detect uses sysctl (kern.ostype / kern.osrelease) — available on every BSD —
// to avoid the per-platform struct-field variance of uname(2).
func detect() Info {
	sys, _ := unix.Sysctl("kern.ostype")    // "FreeBSD", "OpenBSD", …
	rel, _ := unix.Sysctl("kern.osrelease") // "13.2-RELEASE", "7.4", …
	if sys == "" {
		sys = runtime.GOOS
	}
	pretty := sys
	if rel != "" {
		pretty += " " + rel
	}
	return Info{Distro: runtime.GOOS, Version: rel, Pretty: pretty}
}
