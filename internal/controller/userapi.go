package controller

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

type userAPIService struct {
	genezav1.UnimplementedUserAPIServer
	s *Server
}

func (u *userAPIService) ListNodes(ctx context.Context, req *genezav1.ListNodesRequest) (*genezav1.ListNodesResponse, error) {
	ident, _, ok := identityFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no verified identity")
	}
	nodes, err := u.s.nodeSummaries(ident.Workspace)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list nodes: %v", err)
	}
	total := len(nodes)
	lo, hi := (Page{Limit: int(req.GetLimit()), Offset: int(req.GetOffset())}).bounds(total)
	return &genezav1.ListNodesResponse{Nodes: nodes[lo:hi], Total: int32(total)}, nil
}

// ListServices returns the services exposed across the fleet (implicit host
// services + agent-advertised), optionally filtered to one node.
func (u *userAPIService) ListServices(ctx context.Context, req *genezav1.ListServicesRequest) (*genezav1.ListServicesResponse, error) {
	ident, _, ok := identityFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no verified identity")
	}
	var nodes []*NodeRecord
	if filter := req.GetNode(); filter != "" {
		n, err := u.s.store.FindNode(ident.Workspace, filter)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "node %q not found", filter)
		}
		nodes = []*NodeRecord{n}
	} else {
		all, err := u.s.store.ListNodes(ident.Workspace)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "list nodes: %v", err)
		}
		nodes = all
	}
	var out []*genezav1.ServiceInfo
	for _, n := range nodes {
		online := u.s.registry.Online(n.ID)
		for _, svc := range u.s.nodeServices(n) {
			out = append(out, &genezav1.ServiceInfo{
				Name: svc.Name, Kind: svc.Kind, Addr: svc.Addr,
				NodeId: n.ID, NodeName: n.Name, Labels: svc.Labels, Online: online,
			})
		}
	}
	return &genezav1.ListServicesResponse{Services: out}, nil
}

func (u *userAPIService) CreateSession(ctx context.Context, req *genezav1.CreateSessionRequest) (*genezav1.CreateSessionResponse, error) {
	ident, _, ok := identityFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no verified identity")
	}
	return u.s.broker.CreateSession(ctx, ident, req)
}

// Heartbeat re-asserts continuous presence for a presence-required session. The
// caller must own the named session (its grant principal). On a verified beat the
// controller stamps last-presence + rotates the challenge; on a failed/denied beat it
// returns ok=false + a reason (NOT a gRPC error) so the client can read it and stop
// — and does NOT stamp, so the session goes stale and the sweep reaps it. The auth
// interceptor already denies a suspended principal before this runs; verifyPresence
// re-checks (belt-and-suspenders).
func (u *userAPIService) Heartbeat(ctx context.Context, req *genezav1.HeartbeatRequest) (*genezav1.HeartbeatResponse, error) {
	ident, _, ok := identityFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no verified identity")
	}
	sid := req.GetSessionId()
	rec, err := u.s.store.GetSession(ident.Workspace, sid)
	if err != nil {
		return &genezav1.HeartbeatResponse{Ok: false, Reason: "no such session"}, nil
	}
	// The beat must come from the session's own principal (subject when keyable,
	// else the display name) — mirror the SessionSignal authorization.
	if rec.Subject != "" {
		if ident.Subject != rec.Subject || normProvider(ident.Provider) != normProvider(rec.Provider) {
			return &genezav1.HeartbeatResponse{Ok: false, Reason: "session belongs to another principal"}, nil
		}
	} else if ident.Name != rec.User {
		return &genezav1.HeartbeatResponse{Ok: false, Reason: "session belongs to another principal"}, nil
	}
	a := req.GetAttestation()
	att := Attestation{
		Kind: a.GetKind(), SessionID: a.GetSessionId(), Signature: a.GetSignature(),
		Counter: a.GetCounter(), ClientData: a.GetClientData(), ChallengeID: a.GetChallengeId(),
	}
	next, ttlSec, verr := u.s.verifyPresenceSession(ident.Workspace, sid, att)
	if verr != nil {
		return &genezav1.HeartbeatResponse{Ok: false, Reason: verr.Error(), PresenceTtlSeconds: ttlSec}, nil
	}
	return &genezav1.HeartbeatResponse{Ok: true, NextChallenge: next, PresenceTtlSeconds: ttlSec}, nil
}

// SessionSignal is the client's session-scoped ICE signaling channel: the
// controller forwards ICE creds/candidates between this stream and the agent's
// NodeControl disco path, keyed by session_id, ONLY between the two principals
// named in the brokered grant. It carries ICE signaling only, never session data.
func (u *userAPIService) SessionSignal(stream genezav1.UserAPI_SessionSignalServer) error {
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
		return status.Error(codes.InvalidArgument, "first ClientSignal must carry session_id")
	}
	e := u.s.sessionSignals.get(sid)
	if e == nil {
		return status.Error(codes.NotFound, "no signaling session")
	}
	if !e.authorizes(ident) {
		return status.Error(codes.PermissionDenied, "session belongs to another principal")
	}
	if !e.attach() {
		return status.Error(codes.FailedPrecondition, "session signaling already attached")
	}
	defer e.detach()

	// Bound the handler independently of a cooperative client: it returns when the
	// entry is torn down (revoke / session end / expiry via e.done), when the ICE
	// window passes, or when either pump errors — so a half-open or revoked stream
	// never lingers forwarding ICE.
	hctx, cancel := context.WithTimeout(stream.Context(), sessionSigWindow)
	defer cancel()

	u.s.forwardClientSignalToAgent(e, sid, first)

	recvErr := make(chan error, 1)
	go func() {
		for {
			msg, rerr := stream.Recv()
			if rerr != nil {
				recvErr <- rerr
				return
			}
			u.s.forwardClientSignalToAgent(e, sid, msg)
		}
	}()
	sendErr := make(chan error, 1)
	go func() {
		for {
			select {
			case sig := <-e.toClient:
				if serr := stream.Send(sig); serr != nil {
					sendErr <- serr
					return
				}
			case <-hctx.Done():
				return
			}
		}
	}()

	// Returning closes the stream, which unblocks the recv goroutine and (via the
	// deferred cancel) the send goroutine.
	select {
	case err := <-recvErr:
		return err
	case err := <-sendErr:
		return err
	case <-e.done:
		return status.Error(codes.Aborted, "session signaling closed")
	case <-hctx.Done():
		return nil
	}
}

// ListSessions: everyone sees their own sessions; only admins may widen the
// view with mine_only=false.
func (u *userAPIService) ListSessions(ctx context.Context, req *genezav1.ListSessionsRequest) (*genezav1.ListSessionsResponse, error) {
	ident, _, ok := identityFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no verified identity")
	}
	seeAll := !req.GetMineOnly() && hasRole(ident, "admin")
	q := SessionQuery{
		Order: "desc", // newest first
		Page:  Page{Limit: int(req.GetLimit()), Offset: int(req.GetOffset())},
	}
	if !seeAll {
		q.User = ident.Name // mine-only / non-admin: the store filters by user
	}
	page, total, err := u.s.store.QuerySessions(ident.Workspace, q)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list sessions: %v", err)
	}
	out := make([]*genezav1.SessionInfo, 0, len(page))
	for _, r := range page {
		out = append(out, &genezav1.SessionInfo{
			SessionId:     r.ID,
			NodeId:        r.NodeID,
			NodeName:      r.NodeName,
			User:          r.User,
			Action:        r.Action,
			State:         r.State,
			StartedUnix:   r.StartedUnix,
			HostSessionId: r.HostSessionID,
			Detachable:    r.Detachable,
			Recorded:      r.Recorded,
		})
	}
	return &genezav1.ListSessionsResponse{Sessions: out, Total: int32(total)}, nil
}

func (u *userAPIService) WhoAmI(ctx context.Context, _ *genezav1.Empty) (*genezav1.WhoAmIResponse, error) {
	ident, leaf, ok := identityFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no verified identity")
	}
	return &genezav1.WhoAmIResponse{
		User:            ident.Name,
		Workspace:       ident.Workspace,
		Roles:           ident.Roles,
		CertExpiresUnix: leaf.NotAfter.Unix(),
	}, nil
}
