//go:build unix

package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// notifyDrainSignal wires SIGUSR1 to the relay's drain. SIGUSR1 exists only on
// unix, so the handler lives behind a build tag (with a no-op fallback elsewhere);
// the relay runs on unix hosts, where the bootstrap sends it to drain a relay
// before a swap while keeping the listener up for in-flight flows.
func notifyDrainSignal(ctx context.Context, log *slog.Logger, drain func()) {
	drainSig := make(chan os.Signal, 1)
	signal.Notify(drainSig, syscall.SIGUSR1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-drainSig:
				log.Info("relay: SIGUSR1 — draining without shutdown (bootstrap swap)")
				drain()
			}
		}
	}()
}
