package update

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fastOpts() *SupervisorOpts {
	return &SupervisorOpts{
		MinBackoff:        10 * time.Millisecond,
		MaxBackoff:        20 * time.Millisecond,
		BackoffResetAfter: time.Hour,
		Grace:             2 * time.Second,
		Stdout:            io.Discard,
		Stderr:            io.Discard,
	}
}

func TestSupervisorRestartsExitedChild(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "runs")
	script := fmt.Sprintf("echo x >> %s; exit 0", marker)
	s := NewSupervisor("test", func() (string, []string) {
		return "/bin/sh", []string{"-c", script}
	}, testLogger(), fastOpts())
	s.Start()
	defer s.Stop(context.Background())

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(marker)
		if err == nil {
			runs := 0
			for _, c := range b {
				if c == 'x' {
					runs++
				}
			}
			if runs >= 2 {
				return // restarted at least once
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("child was not restarted within the deadline")
}

func TestSupervisorStopSendsSIGTERM(t *testing.T) {
	// `sleep & wait` so the shell's TERM trap fires immediately (a plain
	// foreground sleep would defer trap execution in some shells).
	s := NewSupervisor("test", func() (string, []string) {
		return "/bin/sh", []string{"-c", `trap 'exit 0' TERM; sleep 30 & wait $!`}
	}, testLogger(), fastOpts())
	s.Start()
	time.Sleep(100 * time.Millisecond) // let the child come up

	done := make(chan struct{})
	go func() {
		s.Stop(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return after SIGTERM-aware child")
	}
}

func TestSupervisorStopKillsStubbornChild(t *testing.T) {
	// Child ignores SIGTERM; Stop must escalate to SIGKILL after grace.
	opts := fastOpts()
	opts.Grace = 100 * time.Millisecond
	s := NewSupervisor("test", func() (string, []string) {
		return "/bin/sh", []string{"-c", `trap '' TERM; sleep 30 & wait $!; sleep 30`}
	}, testLogger(), opts)
	s.Start()
	time.Sleep(100 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		s.Stop(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not escalate to SIGKILL")
	}
}

func TestSupervisorStopBeforeStart(t *testing.T) {
	s := NewSupervisor("test", func() (string, []string) {
		return "/bin/true", nil
	}, testLogger(), fastOpts())
	done := make(chan struct{})
	go func() {
		s.Stop(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop before Start must not block")
	}
	// Start after Stop must be a no-op (no orphan child loop).
	s.Start()
}
