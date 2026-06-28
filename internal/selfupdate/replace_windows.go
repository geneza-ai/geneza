//go:build windows

package selfupdate

import (
	"fmt"
	"os"
	"path/filepath"
)

// oldSuffix names the running binary moved aside during an update.
const oldSuffix = ".old"

// replaceBinary swaps the running executable on Windows, where an open .exe
// can't be overwritten but can be renamed: move the running binary aside, rename
// the new one into place, and restore the original if that fails. The leftover
// .old is reclaimed on the next run via CleanupStaleUpdate.
func replaceBinary(tmpPath, exePath string) error {
	oldPath := exePath + oldSuffix
	_ = os.Remove(oldPath) // clear any stale leftover; a lingering lock surfaces below
	if err := os.Rename(exePath, oldPath); err != nil {
		return fmt.Errorf("move running binary aside: %w", err)
	}
	if err := os.Rename(tmpPath, exePath); err != nil {
		if rerr := os.Rename(oldPath, exePath); rerr != nil {
			return fmt.Errorf("install new binary: %w (and failed to restore original: %v)", err, rerr)
		}
		return fmt.Errorf("install new binary: %w", err)
	}
	return nil
}

// CleanupStaleUpdate removes a leftover ".old" binary from a previous Windows
// update (a running .exe can't delete itself, so the swap leaves one behind
// until the next run). No-op on Unix.
func CleanupStaleUpdate() {
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = resolved
	}
	_ = os.Remove(exePath + oldSuffix)
}
