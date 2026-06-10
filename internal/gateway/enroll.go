package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"osie.cloud/geneza/internal/ca"
	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

// EnrollProvider verifies machine-enrollment evidence and yields the labels
// to stamp on the node. This is the seam where cloud instance-identity
// providers (e.g. OpenStack metadata) plug in alongside join tokens.
type EnrollProvider interface {
	Name() string
	Verify(ctx context.Context, req *genezav1.EnrollRequest) (labels map[string]string, suggestedName string, err error)
}

// tokenProvider: single-use-counted, expiring join tokens from the store.
type tokenProvider struct {
	store *Store
}

func (p *tokenProvider) Name() string { return "token" }

func (p *tokenProvider) Verify(_ context.Context, req *genezav1.EnrollRequest) (map[string]string, string, error) {
	if req.GetToken() == "" {
		return nil, "", status.Error(codes.InvalidArgument, "missing join token")
	}
	rec, err := p.store.UseToken(req.GetToken(), time.Now())
	if err != nil {
		// Log the specific failure; never tell the caller which check failed.
		slog.Warn("join token rejected", "err", err)
		return nil, "", status.Error(codes.PermissionDenied, "invalid join token")
	}
	return rec.Labels, "", nil
}

// openstackMetadataProvider is the reserved seam for the OpenStack PoC:
// enrollment via the (vendordata-signed) instance identity document instead
// of a pre-shared token. Registered so the provider name is wired end to end.
type openstackMetadataProvider struct{}

func (p *openstackMetadataProvider) Name() string { return "openstack-metadata" }

func (p *openstackMetadataProvider) Verify(context.Context, *genezav1.EnrollRequest) (map[string]string, string, error) {
	return nil, "", status.Error(codes.Unimplemented,
		"openstack-metadata enrollment: reserved for the OpenStack PoC — see docs/openstack-integration.md")
}

type enrollmentService struct {
	genezav1.UnimplementedEnrollmentServer
	s *Server
}

func randHexID(prefix string) (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b[:]), nil
}

func (e *enrollmentService) Enroll(ctx context.Context, req *genezav1.EnrollRequest) (*genezav1.EnrollResponse, error) {
	s := e.s
	provider, ok := s.enrollProviders[req.GetProvider()]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unknown enrollment provider %q", req.GetProvider())
	}
	deny := func(reason string, err error) (*genezav1.EnrollResponse, error) {
		if aerr := s.audit.Append("enroll", req.GetProvider(), "", "", map[string]string{
			"decision": "deny", "reason": reason, "requested_name": req.GetRequestedName(),
		}); aerr != nil {
			return nil, status.Errorf(codes.Internal, "audit append: %v", aerr)
		}
		return nil, err
	}

	provLabels, suggestedName, err := provider.Verify(ctx, req)
	if err != nil {
		return deny(fmt.Sprintf("provider %s: %v", provider.Name(), err), err)
	}
	if len(req.GetNoiseStaticPub()) != 32 {
		return deny("bad noise static key length",
			status.Error(codes.InvalidArgument, "noise_static_pub must be 32 bytes"))
	}
	if len(req.GetCsrPem()) == 0 {
		return deny("missing CSR", status.Error(codes.InvalidArgument, "csr_pem is required"))
	}

	nodeID, err := randHexID("n-")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "node id: %v", err)
	}
	name := req.GetRequestedName()
	if name == "" {
		name = suggestedName
	}
	if name == "" {
		name = req.GetPlatform().GetHostname()
	}
	if name == "" {
		name = nodeID
	}
	// Provider labels override the agent's self-asserted labels: enrollment
	// evidence (token/instance doc) is the more trusted source.
	labels := make(map[string]string, len(req.GetLabels())+len(provLabels))
	for k, v := range req.GetLabels() {
		labels[k] = v
	}
	for k, v := range provLabels {
		labels[k] = v
	}

	certPEM, err := s.ca.IssueFromCSR(req.GetCsrPem(), ca.Profile{
		Kind: ca.KindNode,
		Name: nodeID,
		TTL:  s.cfg.CertTTL.Node.D(),
	})
	if err != nil {
		return deny("bad CSR", status.Errorf(codes.InvalidArgument, "issue node cert: %v", err))
	}

	rec := &NodeRecord{
		ID:       nodeID,
		Name:     name,
		Labels:   labels,
		NoisePub: req.GetNoiseStaticPub(),
		Platform: PlatformRecord{
			OS:           req.GetPlatform().GetOs(),
			Arch:         req.GetPlatform().GetArch(),
			Hostname:     req.GetPlatform().GetHostname(),
			AgentVersion: req.GetPlatform().GetAgentVersion(),
		},
		CreatedUnix: time.Now().Unix(),
	}
	if err := s.store.PutNode(rec); err != nil {
		return nil, status.Errorf(codes.Internal, "store node: %v", err)
	}
	if err := s.audit.Append("enroll", provider.Name(), nodeID, "", map[string]string{
		"decision": "allow", "name": name,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit append: %v", err)
	}
	slog.Info("node enrolled", "node", nodeID, "name", name, "provider", provider.Name())

	return &genezav1.EnrollResponse{
		NodeId:              nodeID,
		NodeCertPem:         certPEM,
		CaRootsPem:          s.ca.RootsPEM,
		SignedClusterConfig: s.signedClusterConfig(),
	}, nil
}
