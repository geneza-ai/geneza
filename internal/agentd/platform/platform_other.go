//go:build !linux && !darwin && !windows && !freebsd && !openbsd && !netbsd && !dragonfly

package platform

import "runtime"

// detect is the fallback for platforms without a native probe: report the Go
// runtime OS as the distro so the console still shows something sensible.
func detect() Info { return Info{Distro: runtime.GOOS} }
