package update

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// Prune removes version directories under versionsDir whose names are not in
// keep (typically {current, previous} — the on-disk rollback pair). Only
// directories are considered; stray top-level files are left alone. Empty
// keep entries are ignored. A running session host started from a pruned
// directory keeps running (the inode survives on unix); its supervisor
// restarts it from the current version when it eventually dies.
func Prune(versionsDir string, keep []string) error {
	ents, err := os.ReadDir(versionsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name != "" && slices.Contains(keep, name) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(versionsDir, name)); err != nil {
			errs = append(errs, fmt.Errorf("prune %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}
