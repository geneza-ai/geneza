package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"geneza.io/internal/attachproto"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// jitter returns a full-jitter delay in [0, d], de-correlating a fleet of clients
// re-homing off one drained relay at the same instant.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(d) + 1))
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// OpenAttachChannel opens the persistent-session channel. Which host session
// it lands on is decided by the agent from the signed grant; the params only
// carry terminal geometry and the resume sequence number.
func (s *Session) OpenAttachChannel(params *attachproto.AttachOpenParams) (ssh.Channel, error) {
	ch, reqs, err := s.SSH.OpenChannel(attachproto.ChannelTypeAttach, params.Marshal())
	if err != nil {
		var oce *ssh.OpenChannelError
		if errors.As(err, &oce) {
			return nil, fmt.Errorf("agent refused session: %s", oce.Message)
		}
		return nil, fmt.Errorf("open session channel: %w", err)
	}
	go ssh.DiscardRequests(reqs)
	return ch, nil
}

// AttachOptions controls RunAttached.
type AttachOptions struct {
	PTY              bool
	Detachable       bool
	ControllerSessionID string // for the reattach hint
	// Reattach re-establishes the session (action=attach) after a tunnel failure —
	// the seamless client side of IN-SESSION relay re-home: the host PTY persists,
	// so re-opening the attach channel with the last-seen seq replays missed output
	// and the live shell continues. nil disables the auto-retry. It is retried with
	// bounded full-jitter backoff (so a relay that drops every session does not
	// stampede the survivor), and a clean detach/close never retries.
	Reattach func(ctx context.Context) (*Session, error)
	Stderr   io.Writer
}

const (
	// maxClientReattach bounds a re-home burst; a lived session resets the budget.
	maxClientReattach = 6
	// clientReattachBackoffHi caps the full-jitter backoff between re-home attempts.
	clientReattachBackoffHi = 8 * time.Second
)

type hostEvent struct {
	msg *genezav1.HostToClient
	err error
}

func readHostLoop(ch ssh.Channel, out chan<- hostEvent) {
	for {
		m, err := attachproto.ReadHostMsg(ch)
		if err != nil {
			out <- hostEvent{err: err}
			return
		}
		out <- hostEvent{msg: m}
	}
}

func termSize() (cols, rows uint32) {
	if w, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 && h > 0 {
		return uint32(w), uint32(h)
	}
	return 80, 24
}

// RunAttached pumps the local terminal against the remote session over the
// attach channel and returns the remote exit code. It owns raw-mode handling
// and the ssh-style escape sequences (~d detach, ~. close, ~~ literal).
//
// Sequence-number bookkeeping: lastSeq tracks the last *rendered* output seq
// (from Snapshot/Output) and survives the one-shot auto-reattach, so the host
// can offer a delta instead of a full repaint. inputSeq likewise continues
// across the retry so the host never double-applies keystrokes in flight.
func RunAttached(ctx context.Context, sess *Session, opts AttachOptions) (exitCode int, err error) {
	stderr := opts.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	// sess is reassigned on auto-reattach; close whichever is current when
	// we leave (the caller's defer on the original is then a no-op).
	defer func() { sess.Close() }()

	stdinFd := int(os.Stdin.Fd())
	interactive := opts.PTY && term.IsTerminal(stdinFd)

	// notify prints client-side status lines; in raw mode the terminal needs
	// explicit CR.
	notify := func(format string, a ...any) {
		nl := "\n"
		if interactive {
			nl = "\r\n"
		}
		fmt.Fprintf(stderr, "\r"+format+nl, a...)
	}

	if interactive {
		oldState, rawErr := term.MakeRaw(stdinFd)
		if rawErr != nil {
			return 1, fmt.Errorf("raw mode: %w", rawErr)
		}
		restore := func() { term.Restore(stdinFd, oldState) } //nolint:errcheck
		defer restore()
		// Safety net: an external SIGTERM/SIGHUP/SIGINT must not leave the
		// terminal in raw mode (defers do not run on os.Exit elsewhere, and
		// signals bypass defers entirely).
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGHUP, os.Interrupt)
		defer signal.Stop(sigCh)
		sigDone := make(chan struct{})
		defer close(sigDone)
		go func() {
			select {
			case <-sigCh:
				restore()
				os.Exit(1)
			case <-sigDone:
			}
		}()
	}

	openParams := func(resume uint64) *attachproto.AttachOpenParams {
		p := &attachproto.AttachOpenParams{LastSeenSeq: resume}
		if opts.PTY {
			p.Cols, p.Rows = termSize()
			p.Term = os.Getenv("TERM")
		}
		return p
	}

	ch, err := sess.OpenAttachChannel(openParams(0))
	if err != nil {
		return 1, err
	}
	events := make(chan hostEvent, 8)
	go readHostLoop(ch, events)

	// Single stdin reader for the whole run (it survives reattach: a blocked
	// Read cannot be cancelled, so the consumer side switches channels).
	stdinCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 8192)
		for {
			n, rerr := os.Stdin.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				stdinCh <- b
			}
			if rerr != nil {
				close(stdinCh)
				return
			}
		}
	}()

	var winchCh chan os.Signal
	if interactive {
		winchCh = make(chan os.Signal, 1)
		notifyWinch(winchCh)
		defer signal.Stop(winchCh)
	}

	var (
		esc      EscapeDetector
		inputSeq uint64
		lastSeq  uint64
		attempts int
	)

	send := func(m *genezav1.ClientToHost) error { return attachproto.WriteClientMsg(ch, m) }

	// reattach recovers a detachable session after a tunnel failure — the seamless
	// client side of relay re-home. It re-establishes (an attach to the persisted
	// host PTY) and re-opens the attach channel with the last-seen seq so the host
	// replays missed output. It retries with bounded full-jitter backoff so a relay
	// that drops many sessions at once does not stampede the survivor; a budget keeps
	// a genuinely-dead session from looping forever. lastSeq + inputSeq carry across
	// every attempt so output never repaints fully and keystrokes never double-apply.
	reattach := func(cause error) error {
		if opts.Reattach == nil {
			return fmt.Errorf("connection lost: %v", cause)
		}
		sess.Close()
		for {
			if attempts >= maxClientReattach {
				return fmt.Errorf("connection lost: %v (re-home exhausted)", cause)
			}
			attempts++
			backoff := time.Duration(1<<uint(minInt(attempts, 3))) * time.Second
			if backoff > clientReattachBackoffHi {
				backoff = clientReattachBackoffHi
			}
			notify("[geneza] connection lost (%v); re-homing (attempt %d)...", cause, attempts)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(jitter(backoff)):
			}
			ns, rerr := opts.Reattach(ctx)
			if rerr != nil {
				cause = rerr
				continue
			}
			nch, rerr := ns.OpenAttachChannel(openParams(lastSeq))
			if rerr != nil {
				ns.Close()
				cause = rerr
				continue
			}
			sess, ch = ns, nch
			events = make(chan hostEvent, 8)
			go readHostLoop(ch, events)
			attempts = 0 // a lived re-home resets the budget
			notify("[geneza] re-homed")
			return nil
		}
	}

	detachHint := func() {
		id := opts.ControllerSessionID
		if id == "" {
			id = "<session-id>"
		}
		notify("[geneza] detached — reattach with: geneza attach %s", id)
	}

	for {
		select {
		case <-ctx.Done():
			return 1, ctx.Err()

		case b, open := <-stdinCh:
			if !open {
				stdinCh = nil // stop selecting on it
				if serr := send(&genezav1.ClientToHost{Msg: &genezav1.ClientToHost_StdinEof{StdinEof: &genezav1.Stdin_EOF{}}}); serr != nil {
					if rerr := reattach(serr); rerr != nil {
						return 1, rerr
					}
				}
				continue
			}
			forward := b
			action := EscNone
			if interactive {
				forward, action = esc.Feed(b)
			}
			if len(forward) > 0 {
				inputSeq++
				if serr := send(&genezav1.ClientToHost{Msg: &genezav1.ClientToHost_Input{Input: &genezav1.Input{Seq: inputSeq, Data: forward}}}); serr != nil {
					if rerr := reattach(serr); rerr != nil {
						return 1, rerr
					}
					continue
				}
			}
			switch action {
			case EscDetach:
				if !opts.Detachable {
					notify("[geneza] session is not detachable (start it with --detachable)")
					continue
				}
				send(&genezav1.ClientToHost{Msg: &genezav1.ClientToHost_Detach{Detach: &genezav1.Detach{}}}) //nolint:errcheck // best effort; we are leaving
				drainUntilClose(events, 1*time.Second)
				detachHint()
				return 0, nil
			case EscClose:
				notify("[geneza] connection closed")
				return 0, nil
			}

		case <-winchVal(winchCh):
			cols, rows := termSize()
			if serr := send(&genezav1.ClientToHost{Msg: &genezav1.ClientToHost_Resize{Resize: &genezav1.Resize{Cols: cols, Rows: rows}}}); serr != nil {
				if rerr := reattach(serr); rerr != nil {
					return 1, rerr
				}
			}

		case ev := <-events:
			if ev.err != nil {
				if rerr := reattach(ev.err); rerr != nil {
					if errors.Is(ev.err, io.EOF) {
						return 1, errors.New("connection closed by agent")
					}
					return 1, rerr
				}
				continue
			}
			switch m := ev.msg.Msg.(type) {
			case *genezav1.HostToClient_Snapshot:
				os.Stdout.Write(m.Snapshot.Data) //nolint:errcheck
				lastSeq = m.Snapshot.Seq
			case *genezav1.HostToClient_Output:
				os.Stdout.Write(m.Output.Data) //nolint:errcheck
				lastSeq = m.Output.Seq
			case *genezav1.HostToClient_Stderr:
				os.Stderr.Write(m.Stderr.Data) //nolint:errcheck
			case *genezav1.HostToClient_Exit:
				if m.Exit.Reason != "" && m.Exit.Reason != "exited" {
					notify("[geneza] session ended: %s", m.Exit.Reason)
				}
				return int(m.Exit.Code), nil
			case *genezav1.HostToClient_InputAck:
				// Reserved for client-side input buffering; nothing to do.
			}
		}
	}
}

// winchVal lets select work when the winch channel is nil (non-pty mode).
func winchVal(ch chan os.Signal) <-chan os.Signal {
	if ch == nil {
		return nil
	}
	return ch
}

// drainUntilClose gives the Detach message time to flush by waiting for the
// host to close the channel (or a short timeout).
func drainUntilClose(events <-chan hostEvent, max time.Duration) {
	t := time.NewTimer(max)
	defer t.Stop()
	for {
		select {
		case ev := <-events:
			if ev.err != nil {
				return
			}
		case <-t.C:
			return
		}
	}
}
