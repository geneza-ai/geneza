//go:build !windows

package selfupdate

import "os"

// replaceBinary swaps the running executable for the freshly-written one. On
// Unix the kernel keeps the old inode alive for the running process, so a plain
// rename over it is safe and atomic.
func replaceBinary(tmpPath, exePath string) error {
	return os.Rename(tmpPath, exePath)
}

// CleanupStaleUpdate is a no-op on Unix — there is no sidecar to reclaim (the
// Windows path leaves a ".old" file behind that this clears on its platform).
func CleanupStaleUpdate() {}
