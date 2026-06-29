package controller

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// Workspace-scoped principal authorization — the tenant counterpart of the
// cross-tenant ClusterAPI methods. Every operation binds to the caller's OWN
// workspace (actorWorkspace) and ignores any Workspace field in the request, so a
// ws-admin can only act within their tenant; the cross-tenant operator forms stay
// on ClusterAPI for genezactl.

func (a *workspaceAPIService) SuspendPrincipal(ctx context.Context, req *genezav1.SuspendPrincipalRequest) (*genezav1.Empty, error) {
	if err := requireWSAdmin(ctx); err != nil {
		return nil, err
	}
	ws := actorWorkspace(ctx)
	targets := a.s.resolveSuspendTargets(ws, req.GetProvider(), req.GetSubject(), req.GetUsername())
	if len(targets) == 0 {
		return nil, status.Error(codes.NotFound, "could not resolve a principal to suspend; pass --subject")
	}
	reason := req.GetReason()
	if reason == "" {
		reason = "authorization suspended by admin"
	}
	by := adminActor(ctx)
	for _, t := range targets {
		if err := a.s.suspendPrincipal(ws, t.provider, t.subject, t.username, by, reason); err != nil {
			return nil, status.Errorf(codes.Internal, "suspend: %v", err)
		}
	}
	return &genezav1.Empty{}, nil
}

func (a *workspaceAPIService) LiftSuspension(ctx context.Context, req *genezav1.SuspendPrincipalRequest) (*genezav1.Empty, error) {
	if err := requireWSAdmin(ctx); err != nil {
		return nil, err
	}
	ws := actorWorkspace(ctx)
	by := adminActor(ctx)
	if req.GetSubject() != "" {
		p := req.GetProvider()
		if p == "" {
			p = providerLocal
		}
		return &genezav1.Empty{}, a.s.liftSuspension(ws, p, req.GetSubject(), by)
	}
	rows, err := a.s.store.ListSuspensions(ws)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list suspensions: %v", err)
	}
	lifted := 0
	for _, r := range rows {
		if r.Username == req.GetUsername() || (req.GetProvider() == providerLocal && r.Subject == req.GetUsername()) {
			if err := a.s.liftSuspension(r.Workspace, r.Provider, r.Subject, by); err != nil {
				return nil, status.Errorf(codes.Internal, "lift: %v", err)
			}
			lifted++
		}
	}
	if lifted == 0 {
		return nil, status.Error(codes.NotFound, "no matching suspension; pass --subject")
	}
	return &genezav1.Empty{}, nil
}

func (a *workspaceAPIService) ListSuspensions(ctx context.Context, _ *genezav1.Empty) (*genezav1.ListSuspensionsResponse, error) {
	if err := requireWSAdmin(ctx); err != nil {
		return nil, err
	}
	rows, err := a.s.store.ListSuspensions(actorWorkspace(ctx))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list suspensions: %v", err)
	}
	out := make([]*genezav1.Suspension, 0, len(rows))
	for _, r := range rows {
		out = append(out, &genezav1.Suspension{
			Workspace: r.Workspace, Provider: r.Provider, Subject: r.Subject, Username: r.Username,
			Reason: r.Reason, SuspendedBy: r.SuspendedBy, SuspendedUnix: r.SuspendedUnix,
		})
	}
	return &genezav1.ListSuspensionsResponse{Suspensions: out}, nil
}

func (a *workspaceAPIService) RevokeUser(ctx context.Context, req *genezav1.RevokeUserRequest) (*genezav1.RevokeCountResponse, error) {
	if err := requireWSAdmin(ctx); err != nil {
		return nil, err
	}
	if req.GetUser() == "" {
		return nil, status.Error(codes.InvalidArgument, "user required")
	}
	reason := req.GetReason()
	if reason == "" {
		reason = "user access revoked by admin"
	}
	n, err := a.s.revokeUserInWorkspace(actorWorkspace(ctx), req.GetUser(), "admin "+adminActor(ctx)+": "+reason)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "revoke user: %v", err)
	}
	return &genezav1.RevokeCountResponse{Revoked: int32(n)}, nil
}
