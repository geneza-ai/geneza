// Package platform probes the host operating-system identity — the distribution
// and its version — in a cross-platform way, for node inventory and the console's
// per-machine iconography. It reads native sources (os-release on Linux, the
// SystemVersion plist on macOS, the registry on Windows, sysctl on the BSDs) and
// never shells out.
package platform

// Info is the host's OS identity. Every field is best-effort and may be empty
// when the platform can't be determined; callers fall back to runtime.GOOS.
type Info struct {
	// Distro is a normalized lowercase id used for grouping/icons, e.g.
	// "ubuntu", "debian", "fedora", "macos", "windows", "freebsd".
	Distro string
	// Version is the release string, e.g. "22.04", "14.5", "11", "13.2-RELEASE".
	Version string
	// Pretty is the human label, e.g. "Ubuntu 22.04.4 LTS", "macOS 14.5".
	Pretty string
}

// Detect probes the running host. It never errors: an undeterminable platform
// yields a mostly-empty Info.
func Detect() Info { return detect() }
