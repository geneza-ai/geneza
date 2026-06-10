package sessionhost

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// recorder writes an asciicast v2 file incrementally to the spool directory.
// On finalize it drops a sidecar <host_session_id>.done JSON file containing
// the gateway session id and the absolute cast path; the worker uploads and
// deletes both. That contract is fixed.
type recorder struct {
	mu     sync.Mutex
	f      *os.File
	start  time.Time
	cast   string // absolute path to the .cast file
	done   string // absolute path to the .done sidecar
	closed bool
}

type castHeader struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Env       map[string]string `json:"env"`
}

func newRecorder(spoolDir, hostID string, cols, rows uint32, term, shell string) (*recorder, error) {
	abs, err := filepath.Abs(spoolDir)
	if err != nil {
		return nil, fmt.Errorf("resolve spool dir: %w", err)
	}
	cast := filepath.Join(abs, hostID+".cast")
	f, err := os.OpenFile(cast, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open cast file: %w", err)
	}
	r := &recorder{
		f:     f,
		start: time.Now(),
		cast:  cast,
		done:  filepath.Join(abs, hostID+".done"),
	}
	hdr := castHeader{
		Version:   2,
		Width:     int(cols),
		Height:    int(rows),
		Timestamp: r.start.Unix(),
		Env:       map[string]string{"TERM": term, "SHELL": shell},
	}
	b, err := json.Marshal(hdr)
	if err != nil {
		f.Close()
		os.Remove(cast)
		return nil, err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		os.Remove(cast)
		return nil, fmt.Errorf("write cast header: %w", err)
	}
	return r, nil
}

// event appends one [elapsed, kind, payload] line. Errors are swallowed:
// recording must never break a live session, and a truncated cast is still
// uploadable evidence.
func (r *recorder) event(kind, payload string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	line, err := json.Marshal([]any{time.Since(r.start).Seconds(), kind, payload})
	if err != nil {
		return
	}
	_, _ = r.f.Write(append(line, '\n'))
}

func (r *recorder) output(data []byte) { r.event("o", string(data)) }

func (r *recorder) resizeEvent(cols, rows uint32) {
	r.event("r", fmt.Sprintf("%dx%d", cols, rows))
}

// finalize closes the cast and writes the .done sidecar the worker watches
// for. The .done file must only ever appear after the cast is complete.
func (r *recorder) finalize(sessionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if err := r.f.Close(); err != nil {
		return fmt.Errorf("close cast: %w", err)
	}
	b, err := json.Marshal(struct {
		SessionID string `json:"session_id"`
		Cast      string `json:"cast"`
	}{SessionID: sessionID, Cast: r.cast})
	if err != nil {
		return err
	}
	if err := os.WriteFile(r.done, b, 0o600); err != nil {
		return fmt.Errorf("write done sidecar: %w", err)
	}
	return nil
}

// abort discards a recording whose session failed to start.
func (r *recorder) abort() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	r.f.Close()
	os.Remove(r.cast)
}
