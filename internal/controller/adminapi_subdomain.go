package controller

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// Managed-domain subdomain reservations over the AdminAPI (ws-admin gated like
// the rest of the service, scoped to the caller's workspace). These mirror the
// console REST surface; both call the same Server reserve/release methods.

func subdomainInfo(r *SubdomainReservation) *genezav1.SubdomainReservationInfo {
	return &genezav1.SubdomainReservationInfo{
		Domain:      r.Domain,
		Label:       r.Label,
		Zone:        r.Zone(),
		CreatedUnix: r.CreatedUnix,
		CreatedBy:   r.CreatedBy,
	}
}

func (a *adminAPIService) ReserveSubdomain(ctx context.Context, req *genezav1.ReserveSubdomainRequest) (*genezav1.SubdomainReservationInfo, error) {
	rec, err := a.s.reserveWorkspaceSubdomain(actorWorkspace(ctx), req.GetDomain(), req.GetLabel(), adminActor(ctx))
	if err != nil {
		switch {
		case errors.Is(err, errSubdomainTaken):
			return nil, status.Error(codes.AlreadyExists, "that subdomain is already reserved")
		case errors.Is(err, errSubdomainLimit):
			return nil, status.Error(codes.ResourceExhausted, "workspace subdomain limit reached")
		case errors.Is(err, errManagedDomainDisabled):
			return nil, status.Error(codes.FailedPrecondition, "managed domain is not enabled")
		default:
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}
	return subdomainInfo(rec), nil
}

func (a *adminAPIService) ListSubdomains(ctx context.Context, _ *genezav1.Empty) (*genezav1.ListSubdomainsResponse, error) {
	ws := actorWorkspace(ctx)
	subs, err := a.s.store.ListWorkspaceSubdomains(ws)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list reservations: %v", err)
	}
	out := make([]*genezav1.SubdomainReservationInfo, 0, len(subs))
	for _, s := range subs {
		out = append(out, subdomainInfo(s))
	}
	domains := make([]string, 0, len(a.s.cfg.ManagedDomain.Domains))
	for _, d := range a.s.cfg.ManagedDomain.Domains {
		domains = append(domains, d.Base)
	}
	return &genezav1.ListSubdomainsResponse{
		Enabled:      a.s.cfg.ManagedDomain.enabled(),
		Domains:      domains,
		Max:          int32(maxWorkspaceSubdomains),
		Reservations: out,
	}, nil
}

func (a *adminAPIService) ReleaseSubdomain(ctx context.Context, req *genezav1.ReleaseSubdomainRequest) (*genezav1.Empty, error) {
	if err := a.s.releaseWorkspaceSubdomain(actorWorkspace(ctx), req.GetDomain(), req.GetLabel(), adminActor(ctx)); err != nil {
		if errors.Is(err, errSubdomainTaken) {
			return nil, status.Error(codes.PermissionDenied, "that subdomain belongs to another workspace")
		}
		return nil, status.Errorf(codes.Internal, "release: %v", err)
	}
	return &genezav1.Empty{}, nil
}
