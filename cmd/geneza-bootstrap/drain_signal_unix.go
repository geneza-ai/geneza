//go:build unix

package main

import "syscall"

// signalWorkerDrain sends the relay worker the drain signal (SIGUSR1 — shed new
// work, keep serving in-flight) before a swap. SIGUSR1 is unix-only; the relay
// runs on unix hosts, so the drain gate is a no-op on platforms without it.
func (b *bootstrap) signalWorkerDrain() bool {
	return b.worker.Signal(syscall.SIGUSR1)
}

// signalSessionHostDrain sends the agent session host the drain signal before its
// swap, so it refuses new sessions and reports the active count falling to zero.
func (b *bootstrap) signalSessionHostDrain() bool {
	if b.sessionHost == nil {
		return false
	}
	return b.sessionHost.Signal(syscall.SIGUSR1)
}

// signalSessionHostWarn sends the warn-only heads-up (SIGUSR2) so the session host
// banners attached clients BEFORE the worker swap disconnects them.
func (b *bootstrap) signalSessionHostWarn() bool {
	if b.sessionHost == nil {
		return false
	}
	return b.sessionHost.Signal(syscall.SIGUSR2)
}
