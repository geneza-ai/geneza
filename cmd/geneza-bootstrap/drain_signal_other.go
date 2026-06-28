//go:build !unix

package main

// signalWorkerDrain is a no-op where SIGUSR1 does not exist (e.g. Windows). The
// relay — the only product with a drain gate — runs on unix, so the drain-before-
// swap step is simply skipped elsewhere.
func (b *bootstrap) signalWorkerDrain() bool { return false }

// signalSessionHostDrain is a no-op where SIGUSR1 does not exist.
func (b *bootstrap) signalSessionHostDrain() bool { return false }

// signalSessionHostWarn is a no-op where SIGUSR2 does not exist.
func (b *bootstrap) signalSessionHostWarn() bool { return false }
