package gateway

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

type userAPIService struct {
	genezav1.UnimplementedUserAPIServer
	s *Server
}

func (u *userAPIService) Login(ctx context.Context, req *genezav1.LoginRequest) (*genezav1.LoginResponse, error) {
	return u.s.handleLogin(ctx, req)
}

func (u *userAPIService) ListNodes(ctx context.Context, _ *genezav1.ListNodesRequest) (*genezav1.ListNodesResponse, error) {
	nodes, err := u.s.nodeSummaries()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list nodes: %v", err)
	}
	return &genezav1.ListNodesResponse{Nodes: nodes}, nil
}

// ListServices returns the services exposed across the fleet (implicit host
// services + agent-advertised), optionally filtered to one node.
func (u *userAPIService) ListServices(ctx context.Context, req *genezav1.ListServicesRequest) (*genezav1.ListServicesResponse, error) {
	var nodes []*NodeRecord
	if filter := req.GetNode(); filter != "" {
		n, err := u.s.store.FindNode(filter)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "node %q not found", filter)
		}
		nodes = []*NodeRecord{n}
	} else {
		all, err := u.s.store.ListNodes()
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

// ResolveDNS answers a wire-format DNS query for the caller's tenant zone,
// policy-gated (machine name -> overlay IP; unknown/denied -> NXDOMAIN). The
// resolver runs here in the gateway; the `geneza vpn` client relays its local
// stub's queries over this authenticated channel.
func (u *userAPIService) ResolveDNS(ctx context.Context, req *genezav1.DNSQuery) (*genezav1.DNSResponse, error) {
	ident, _, ok := identityFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no verified identity")
	}
	resp, err := u.s.resolver.Answer(req.GetQuery(), u.s.dnsLookupA(ident))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "dns: %v", err)
	}
	return &genezav1.DNSResponse{Response: resp}, nil
}

func (u *userAPIService) CreateSession(ctx context.Context, req *genezav1.CreateSessionRequest) (*genezav1.CreateSessionResponse, error) {
	ident, _, ok := identityFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no verified identity")
	}
	return u.s.broker.CreateSession(ctx, ident, req)
}

// ListSessions: everyone sees their own sessions; only admins may widen the
// view with mine_only=false.
func (u *userAPIService) ListSessions(ctx context.Context, req *genezav1.ListSessionsRequest) (*genezav1.ListSessionsResponse, error) {
	ident, _, ok := identityFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no verified identity")
	}
	all, err := u.s.store.ListSessions()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list sessions: %v", err)
	}
	seeAll := !req.GetMineOnly() && hasRole(ident, "admin")
	out := make([]*genezav1.SessionInfo, 0, len(all))
	for _, r := range all {
		if !seeAll && r.User != ident.Name {
			continue
		}
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
		})
	}
	return &genezav1.ListSessionsResponse{Sessions: out}, nil
}

func (u *userAPIService) WhoAmI(ctx context.Context, _ *genezav1.Empty) (*genezav1.WhoAmIResponse, error) {
	ident, leaf, ok := identityFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no verified identity")
	}
	return &genezav1.WhoAmIResponse{
		User:            ident.Name,
		Roles:           ident.Roles,
		CertExpiresUnix: leaf.NotAfter.Unix(),
	}, nil
}
