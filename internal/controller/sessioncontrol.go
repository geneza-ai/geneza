package controller

import (
	genezav1 "geneza.io/internal/pb/geneza/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SessionControl is the client end of realtime enforcement. The
// client opens it for a DIRECT session and streams keepalives; the controller pushes
// the SAME signed revoke / lease / delta it pushes to the agent, so EITHER honest
// end closes the conduit even if the other ignores the cut. The agent stays the
// primary gate; this is belt-and-suspenders for a compromised agent.
//
// Unlike SessionSignal (bounded to the short ICE-setup window), this stream lives
// the WHOLE session: it blocks until the session entry is torn down (e.done, set
// on revoke/end/expiry), the client disconnects, or the stream context ends. The
// reauth sweep touches the entry every tick so the ICE-sized TTL never reaps a
// live session's control channel.
func (u *workspaceAPIService) SessionControl(stream genezav1.WorkspaceAPI_SessionControlServer) error {
	ident, _, ok := identityFrom(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "no verified identity")
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	sid := first.GetSessionId()
	if sid == "" {
		return status.Error(codes.InvalidArgument, "first ClientControl must carry session_id")
	}
	e := u.s.sessionSignals.get(sid)
	if e == nil {
		return status.Error(codes.NotFound, "no such session")
	}
	if !e.authorizes(ident) {
		return status.Error(codes.PermissionDenied, "session belongs to another principal")
	}
	if !e.attachControl() {
		return status.Error(codes.FailedPrecondition, "session control already attached")
	}
	defer e.detachControl()

	// Drain (ignore) client keepalives; their only purpose is to surface a dead
	// client via a recv error so the stream tears down promptly.
	recvErr := make(chan error, 1)
	go func() {
		for {
			if _, rerr := stream.Recv(); rerr != nil {
				recvErr <- rerr
				return
			}
		}
	}()

	for {
		select {
		case ctl := <-e.toControl:
			if serr := stream.Send(ctl); serr != nil {
				return serr
			}
		case rerr := <-recvErr:
			return rerr
		case <-e.done:
			// Session torn down: flush any buffered enforcement so the client acts on
			// the final revoke/lease, then close (the client's receiver unblocks and
			// it tears its own conduit end).
			for {
				select {
				case ctl := <-e.toControl:
					_ = stream.Send(ctl)
				default:
					return status.Error(codes.Aborted, "session closed")
				}
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}
