package sessionhost

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// drainStatusPeriod is how often a draining host rewrites its drain-status file
// so the supervising bootstrap observes the active count fall promptly.
const drainStatusPeriod = 250 * time.Millisecond

// startDrain puts the host into draining mode: Create refuses new sessions, the
// drain-status file begins reporting the live active count, and attached clients
// are warned. Live sessions keep running until they end or the bootstrap's drain
// window forces the swap. Idempotent.
func (h *host) startDrain() {
	h.drainOnce.Do(func() {
		h.draining.Store(true)
		close(h.drainCh)
		h.log.Info("session host draining", "active", h.activeN.Load())
		h.notifyClientsDraining()
	})
}

func (h *host) Draining() bool { return h.draining.Load() }
func (h *host) Active() int64  { return h.activeN.Load() }

// notifyClientsDraining warns every attached client that the host is draining and
// about to be swapped, so the CLI/console can surface it and reconnect. The push
// itself rides the attach bridge (see the drain-notice frame).
func (h *host) notifyClientsDraining() {
	h.mu.Lock()
	sessions := make([]*session, 0, len(h.sessions))
	for _, s := range h.sessions {
		sessions = append(sessions, s)
	}
	h.mu.Unlock()
	for _, s := range sessions {
		s.sendDrainNotice()
	}
}

// drainBanner is the in-band notice shown to an interactive client when the host
// begins draining for an update — the warning before the forced close, the way a
// terminal user expects to be told (like a wall/SIGTERM heads-up). It rides the
// normal output path, so it reaches the CLI and the console web-shell alike, lands
// in the ring (a reattaching client still sees it), and in the recording.
var drainBanner = []byte("\r\n\x1b[1;33m[geneza] this machine is updating — your session will close shortly; reconnect to resume.\x1b[0m\r\n")

// sendDrainNotice injects the drain banner into an interactive session's output.
// Pipe/exec sessions have no terminal (injecting would corrupt their byte stream),
// so they get no banner — they are short-lived and the drain window covers them.
func (s *session) sendDrainNotice() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exited || !s.ptyMode {
		return
	}
	s.seq++
	seq := s.seq
	s.ring.add(seq, false, drainBanner)
	if s.vt != nil {
		_, _ = s.vt.Write(drainBanner)
	}
	if s.rec != nil {
		s.rec.output(drainBanner)
	}
	s.deliverLocked(chunkFrame(seq, false, drainBanner))
}

// runDrainStatusFile mirrors the relay's writer: it writes the file once up front
// (so the bootstrap never misreads an absent file), then idles until draining
// begins and rewrites it on a fast cadence with the live active count. Format
// matches the relay's so the bootstrap parses both with one reader:
// "draining=<bool> active=<n> ts=<ms>".
func (h *host) runDrainStatusFile(ctx context.Context, statusFile string) {
	if statusFile == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(statusFile), 0o755); err != nil {
		h.log.Error("session host: create drain-status dir", "path", statusFile, "err", err)
	}
	write := func() {
		content := fmt.Sprintf("draining=%t active=%d ts=%d\n", h.Draining(), h.Active(), time.Now().UnixMilli())
		if err := os.WriteFile(statusFile, []byte(content), 0o644); err != nil {
			h.log.Error("session host: write drain-status", "path", statusFile, "err", err)
		}
	}
	write()
	select {
	case <-ctx.Done():
		return
	case <-h.drainCh:
	}
	write()
	t := time.NewTicker(drainStatusPeriod)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			write()
		}
	}
}
