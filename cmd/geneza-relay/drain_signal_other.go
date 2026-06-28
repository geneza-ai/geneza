//go:build !unix

package main

import (
	"context"
	"log/slog"
)

// notifyDrainSignal is a no-op where SIGUSR1 does not exist (e.g. Windows). The
// relay runs on unix hosts, so the drain signal is only meaningful there; this
// keeps the operator-tools cross-compile building on every target.
func notifyDrainSignal(context.Context, *slog.Logger, func()) {}
