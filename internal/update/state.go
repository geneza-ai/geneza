package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
)

// State is the bootstrap's persisted view of the worker version lifecycle.
// Current/Previous are the rollback pair kept on disk; Bad lists versions
// that failed their post-swap health gate and must not be retried until the
// gateway's desired version moves to a different value.
type State struct {
	Current  string   `json:"current"`
	Previous string   `json:"previous,omitempty"`
	Bad      []string `json:"bad,omitempty"`
}

// LoadState reads the state file. A missing file yields an empty state (a
// fresh node), not an error; a corrupt file is an error so the caller can
// decide (and log) how to recover.
func LoadState(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &State{}, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	return &s, nil
}

// Save writes the state atomically (temp file + rename) so a crash mid-write
// can never leave a half-written state file: the bootstrap's rollback
// decisions depend on this file being either old or new, never garbage.
func (s *State) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// IsBad reports whether v previously failed its health gate.
func (s *State) IsBad(v string) bool {
	return slices.Contains(s.Bad, v)
}

// MarkBad records v as health-gate-failed (idempotent).
func (s *State) MarkBad(v string) {
	if !s.IsBad(v) {
		s.Bad = append(s.Bad, v)
	}
}

// ResetBadOnChange clears the bad list when the gateway's desired version
// has moved to a different value than the last one observed. This is what
// allows an operator to re-push a previously failed version deliberately
// (point at something else, then back) while preventing a crash-loop of
// retrying the same broken build every poll. Returns true if the state
// changed and must be persisted. A lastDesired of "" (first observation
// after bootstrap start) never resets: skip stays skip across restarts.
func (s *State) ResetBadOnChange(desired, lastDesired string) bool {
	if lastDesired == "" || desired == lastDesired || len(s.Bad) == 0 {
		return false
	}
	s.Bad = nil
	return true
}
