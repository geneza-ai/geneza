//go:build unix

package sessionhost

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// watchDrainSignal handles the bootstrap's pre-swap signals. SIGUSR2 is the
// warn-only heads-up sent BEFORE the worker swap (which disconnects attached
// clients) — it banners clients while they are still connected, without refusing
// new sessions. SIGUSR1 is the full drain before the session-host's own swap:
// refuse new sessions and report the active count. Unix-only; the gate is absent
// on Windows.
func (h *host) watchDrainSignal(ctx context.Context) {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGUSR1, syscall.SIGUSR2)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-ch:
			if sig == syscall.SIGUSR2 {
				h.notifyClientsDraining() // warn only; clients still attached
				continue
			}
			h.startDrain() // SIGUSR1: full drain, then the swap follows
			return
		}
	}
}
