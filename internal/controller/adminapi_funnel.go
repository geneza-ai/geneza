package controller

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// Funnel exposures over the AdminAPI (ws-admin scoped to the caller's workspace),
// mirroring the console REST surface; both call the same Server methods.

func funnelInfo(f *FunnelBinding) *genezav1.FunnelInfo {
	return &genezav1.FunnelInfo{
		Hostname: f.Hostname, Node: f.NodeID, Target: f.Target, Mode: f.Mode,
		CreatedUnix: f.CreatedUnix, CreatedBy: f.CreatedBy,
	}
}

func funnelErr(err error) error {
	switch {
	case errors.Is(err, errFunnelTaken):
		return status.Error(codes.AlreadyExists, "that funnel hostname is already in use")
	case errors.Is(err, errFunnelLimit):
		return status.Error(codes.ResourceExhausted, "workspace funnel limit reached")
	case errors.Is(err, errFunnelHost):
		return status.Error(codes.FailedPrecondition, "hostname is not under one of your reservations")
	case errors.Is(err, errManagedDomainDisabled):
		return status.Error(codes.FailedPrecondition, "managed domain is not enabled")
	default:
		return status.Error(codes.InvalidArgument, err.Error())
	}
}

func (a *adminAPIService) CreateFunnel(ctx context.Context, req *genezav1.CreateFunnelRequest) (*genezav1.FunnelInfo, error) {
	rec, err := a.s.createFunnel(actorWorkspace(ctx), req.GetHostname(), req.GetNode(), req.GetTarget(), req.GetMode(), adminActor(ctx))
	if err != nil {
		return nil, funnelErr(err)
	}
	return funnelInfo(rec), nil
}

func (a *adminAPIService) ListFunnels(ctx context.Context, _ *genezav1.Empty) (*genezav1.ListFunnelsResponse, error) {
	fs, err := a.s.store.ListWorkspaceFunnels(actorWorkspace(ctx))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list funnels: %v", err)
	}
	out := make([]*genezav1.FunnelInfo, 0, len(fs))
	for _, f := range fs {
		out = append(out, funnelInfo(f))
	}
	return &genezav1.ListFunnelsResponse{Funnels: out}, nil
}

func (a *adminAPIService) DeleteFunnel(ctx context.Context, req *genezav1.DeleteFunnelRequest) (*genezav1.Empty, error) {
	if err := a.s.deleteFunnel(actorWorkspace(ctx), req.GetHostname(), adminActor(ctx)); err != nil {
		if errors.Is(err, errFunnelTaken) {
			return nil, status.Error(codes.PermissionDenied, "that funnel belongs to another workspace")
		}
		return nil, status.Errorf(codes.Internal, "delete funnel: %v", err)
	}
	return &genezav1.Empty{}, nil
}
