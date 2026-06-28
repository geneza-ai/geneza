package controller

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

func TestAdminSubdomainRPCs(t *testing.T) {
	srv := newReplayServer(t)
	srv.cfg.ManagedDomain = ManagedDomainConfig{
		Domains: []ManagedDomainEntry{{Base: "geneza.app", DNSProvider: "cf"}},
	}
	a := &adminAPIService{s: srv}
	ctx := userCtx(defaultWorkspace, "adm", roleWSAdmin)

	info, err := a.ReserveSubdomain(ctx, &genezav1.ReserveSubdomainRequest{Domain: "geneza.app", Label: "acme"})
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if info.GetZone() != "acme.geneza.app" {
		t.Fatalf("zone %q", info.GetZone())
	}

	// Unknown domain → InvalidArgument.
	if _, err := a.ReserveSubdomain(ctx, &genezav1.ReserveSubdomainRequest{Domain: "evil.com", Label: "x"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unknown domain: want InvalidArgument, got %v", err)
	}

	// Cap at 3 → ResourceExhausted on the fourth.
	for _, l := range []string{"b", "c"} {
		if _, err := a.ReserveSubdomain(ctx, &genezav1.ReserveSubdomainRequest{Domain: "geneza.app", Label: l}); err != nil {
			t.Fatalf("reserve %s: %v", l, err)
		}
	}
	if _, err := a.ReserveSubdomain(ctx, &genezav1.ReserveSubdomainRequest{Domain: "geneza.app", Label: "d"}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("over cap: want ResourceExhausted, got %v", err)
	}

	// Another workspace cannot claim an owned label → AlreadyExists.
	other := userCtx("wsOther", "mallory", roleWSAdmin)
	if _, err := a.ReserveSubdomain(other, &genezav1.ReserveSubdomainRequest{Domain: "geneza.app", Label: "acme"}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("cross-workspace: want AlreadyExists, got %v", err)
	}

	// List reflects the three, with metadata.
	lst, err := a.ListSubdomains(ctx, &genezav1.Empty{})
	if err != nil || !lst.GetEnabled() || lst.GetMax() != 3 || len(lst.GetReservations()) != 3 {
		t.Fatalf("list: err=%v resp=%+v", err, lst)
	}

	// Release then reclaim by the other workspace.
	if _, err := a.ReleaseSubdomain(ctx, &genezav1.ReleaseSubdomainRequest{Domain: "geneza.app", Label: "acme"}); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := a.ReserveSubdomain(other, &genezav1.ReserveSubdomainRequest{Domain: "geneza.app", Label: "acme"}); err != nil {
		t.Fatalf("reclaim after release: %v", err)
	}

	// Disabled controller → FailedPrecondition.
	srv.cfg.ManagedDomain = ManagedDomainConfig{}
	if _, err := a.ReserveSubdomain(ctx, &genezav1.ReserveSubdomainRequest{Domain: "geneza.app", Label: "z"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("disabled: want FailedPrecondition, got %v", err)
	}
}
