package sessionhost

import (
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

var (
	errExitSent = errors.New("exit frame sent")
	errDetached = errors.New("client detached")
)

// Attach binds a bidi stream to a session. The first ClientToHost must be
// open{host_session_id, last_seen_seq}. An already-attached client is
// preempted (tmux attach -d semantics). The reply is either a delta of Output
// frames (when every frame in (last_seen_seq, cur] is still in the ring) or a
// Snapshot repaint, then live output streams until detach, preemption,
// disconnect, or process exit.
func (h *host) Attach(stream grpc.BidiStreamingServer[genezav1.ClientToHost, genezav1.HostToClient]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	open := first.GetOpen()
	if open == nil {
		return status.Error(codes.InvalidArgument, "first message must be open")
	}
	s := h.lookup(open.HostSessionId)
	if s == nil {
		return status.Error(codes.NotFound, "unknown host session "+open.HostSessionId)
	}

	cl := newAttachedClient()
	initial, registered := s.attach(cl, open.LastSeenSeq)
	if !registered {
		// Exited tombstone: report the exit and close.
		for _, m := range initial {
			if err := stream.Send(m); err != nil {
				return err
			}
		}
		return nil
	}
	h.log.Info("client attached",
		"host_session_id", s.hostID, "session_id", s.sessionID,
		"last_seen_seq", open.LastSeenSeq)

	writeDone := make(chan error, 1)
	go func() { writeDone <- writeLoop(stream, s, cl, initial) }()
	recvDone := make(chan error, 1)
	go func() { recvDone <- readLoop(stream, s, cl) }()

	// All session state transitions are owned by whoever closes cl.stop (or
	// by clientGone below); the branches here only translate outcomes into
	// stream results. Goroutines left blocked in Recv/Send unwind when the
	// handler returns and gRPC tears the stream down.
	select {
	case werr := <-writeDone:
		if errors.Is(werr, errExitSent) {
			s.clientGone(cl) // unregister only; session already exited
			return nil
		}
		s.clientGone(cl)
		if werr == nil { // writer stopped: preempted or dropped as too slow
			return status.Error(codes.Aborted, "attach superseded or dropped")
		}
		return werr
	case rerr := <-recvDone:
		if errors.Is(rerr, errDetached) {
			return nil // clean detach; session keeps running
		}
		s.clientGone(cl)
		if _, isStatus := status.FromError(rerr); isStatus && status.Code(rerr) != codes.Unknown {
			return rerr // our own validation errors (dup open, detach rejected)
		}
		return nil // client went away (EOF / transport error)
	case <-cl.stop:
		s.clientGone(cl)
		return status.Error(codes.Aborted, "preempted by another attach")
	}
}

// writeLoop is the only goroutine that sends on the stream: first the initial
// delta/snapshot frames, then everything the pump (and input acks / exit)
// queue on cl.ch. Returns errExitSent after delivering an Exit frame, nil
// when stopped via cl.stop.
func writeLoop(stream grpc.BidiStreamingServer[genezav1.ClientToHost, genezav1.HostToClient], s *session, cl *attachedClient, initial []*genezav1.HostToClient) error {
	for _, m := range initial {
		if err := stream.Send(m); err != nil {
			return err
		}
		if m.GetExit() != nil {
			return errExitSent
		}
	}
	ctx := stream.Context()
	for {
		// If the client fell behind, catch it up with one coalesced repaint
		// (discarding the stale backlog) instead of streaming stale frames —
		// this is what keeps an interactive session smooth under output bursts
		// and brief network jitter rather than dropping the connection.
		if cl.lagged.Load() {
			if snap := s.catchUpSnapshot(cl); snap != nil {
				if err := stream.Send(snap); err != nil {
					return err
				}
			}
			continue
		}
		select {
		case m := <-cl.ch:
			if err := stream.Send(m); err != nil {
				return err
			}
			if m.GetExit() != nil {
				return errExitSent
			}
		case <-cl.stop:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// readLoop dispatches inbound client messages to the session. It returns
// errDetached on an accepted Detach, or the Recv/validation error otherwise.
func readLoop(stream grpc.BidiStreamingServer[genezav1.ClientToHost, genezav1.HostToClient], s *session, cl *attachedClient) error {
	for {
		m, err := stream.Recv()
		if err != nil {
			return err
		}
		switch v := m.Msg.(type) {
		case *genezav1.ClientToHost_Open:
			return status.Error(codes.InvalidArgument, "duplicate open message")
		case *genezav1.ClientToHost_Input:
			s.handleInput(cl, v.Input)
		case *genezav1.ClientToHost_Resize:
			s.handleResize(cl, v.Resize.Cols, v.Resize.Rows)
		case *genezav1.ClientToHost_Signal:
			s.handleSignal(cl, v.Signal.Name)
		case *genezav1.ClientToHost_StdinEof:
			s.handleStdinEOF(cl)
		case *genezav1.ClientToHost_Detach:
			if err := s.detachRequest(cl); err != nil {
				return err
			}
			return errDetached
		}
	}
}
