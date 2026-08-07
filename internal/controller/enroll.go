package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"geneza.io/internal/ca"
	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// EnrollProvider verifies machine-enrollment evidence and yields the labels to
// stamp on the node plus whether the node may be auto-approved. This is the seam
// where cloud instance-identity providers (e.g. OpenStack metadata) plug in
// alongside join tokens. autoApprove is true only when the evidence is strong
// enough to skip the human admission gate (a token minted --auto-approve, or a
// cryptographic instance-identity document) — a bearer token defaults to false.
type enrollResult struct {
	Labels        map[string]string
	SuggestedName string
	Workspace     string // tenant the node enrolls into (token-bound, or instance->ws)
	AutoApprove   bool
}

type EnrollProvider interface {
	Name() string
	Verify(ctx context.Context, req *genezav1.EnrollRequest) (enrollResult, error)
}

// tokenProvider: single-use-counted, expiring join tokens from the store.
type tokenProvider struct {
	store Store
}

func (p *tokenProvider) Name() string { return "token" }

func (p *tokenProvider) Verify(_ context.Context, req *genezav1.EnrollRequest) (enrollResult, error) {
	if req.GetToken() == "" {
		return enrollResult{}, status.Error(codes.InvalidArgument, "missing join token")
	}
	rec, err := p.store.UseToken(req.GetToken(), time.Now())
	if err != nil {
		// Log the specific failure; never tell the caller which check failed.
		slog.Warn("join token rejected", "err", err)
		return enrollResult{}, status.Error(codes.PermissionDenied, "invalid join token")
	}
	ws := rec.WorkspaceID
	if ws == "" {
		ws = defaultWorkspace
	}
	return enrollResult{Labels: rec.Labels, Workspace: ws, AutoApprove: rec.AutoApprove}, nil
}

// openstackMetadataProvider is the reserved seam for the OpenStack PoC:
// enrollment via the (vendordata-signed) instance identity document instead
// of a pre-shared token. Registered so the provider name is wired end to end.
type openstackMetadataProvider struct{}

func (p *openstackMetadataProvider) Name() string { return "openstack-metadata" }

func (p *openstackMetadataProvider) Verify(context.Context, *genezav1.EnrollRequest) (enrollResult, error) {
	// When implemented this returns AutoApprove=true and maps the instance's
	// project to a Workspace: a vendordata-signed instance identity document is
	// cryptographic evidence of "I am instance X in project Y" — no shared secret
	// to leak — so an admission rule can trust it directly.
	return enrollResult{}, status.Error(codes.Unimplemented,
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

	res, err := provider.Verify(ctx, req)
	if err != nil {
		return deny(fmt.Sprintf("provider %s: %v", provider.Name(), err), err)
	}
	provLabels, suggestedName, autoApprove := res.Labels, res.SuggestedName, res.AutoApprove
	ws := res.Workspace
	if ws == "" {
		ws = defaultWorkspace
	}
	if len(req.GetNoiseStaticPub()) != 32 {
		return deny("bad noise static key length",
			status.Error(codes.InvalidArgument, "noise_static_pub must be 32 bytes"))
	}
	if len(req.GetCsrPem()) == 0 {
		return deny("missing CSR", status.Error(codes.InvalidArgument, "csr_pem is required"))
	}
	// The WireGuard data-plane static key is optional (additive): agents that
	// predate the data plane omit it and simply get no overlay interfaces until
	// they re-enroll. When present it must be a 32-byte Curve25519 key.
	if wg := req.GetWgStaticPub(); len(wg) != 0 && len(wg) != 32 {
		return deny("bad wg static key length",
			status.Error(codes.InvalidArgument, "wg_static_pub must be 32 bytes when present"))
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
	// Cross-check the agent's own view of which instance it is against the one the
	// enrollment evidence pinned. See crossCheckInstanceClaim: this only ever
	// narrows, never grants.
	if err := crossCheckInstanceClaim(req.GetLabels(), provLabels); err != nil {
		return deny("instance claim mismatch: "+err.Error(),
			status.Error(codes.PermissionDenied, "enrollment evidence does not match this machine"))
	}
	labels := mergeEnrollLabels(req.GetLabels(), provLabels)
	// One live node per OpenStack instance: these labels are what routes a launch,
	// so two nodes wearing the same one is an ambiguity resolved by store order.
	if err := s.enforceInstanceUniqueness(ws, labels); err != nil {
		return deny("duplicate instance: "+err.Error(),
			status.Error(codes.AlreadyExists, err.Error()))
	}

	certPEM, err := s.ca.IssueFromCSR(req.GetCsrPem(), ca.Profile{
		Kind:      ca.KindNode,
		Workspace: ws,
		Name:      nodeID,
		TTL:       s.cfg.CertTTL.Node.D(),
	})
	if err != nil {
		return deny("bad CSR", status.Errorf(codes.InvalidArgument, "issue node cert: %v", err))
	}

	// Re-enroll anti-laundering gate: if this host's stable hardware id matches an
	// active quarantine, it does not matter that it presents a fresh node id and a
	// valid --auto-approve token — force it PENDING so an admin reviews it, instead
	// of letting a quarantined host wipe its state and re-enroll its way back to
	// trusted. Empty host_uuid (unprivileged/non-Linux) degrades to node-id scope.
	if hu := req.GetPlatform().GetHostUuid(); hu != "" && autoApprove {
		_, qerr := s.store.FindQuarantineByHostUUID(ws, hu)
		switch {
		case qerr == nil:
			autoApprove = false
			_ = s.audit.Append("enroll_quarantined_identity", provider.Name(), nodeID, "", map[string]string{
				"host_uuid": hu, "name": name,
			})
			slog.Warn("re-enroll of quarantined host forced to pending", "node", nodeID, "host_uuid", hu)
		case !errors.Is(qerr, ErrNotFound):
			// Fail closed: a quarantine lookup we cannot complete (store unreachable)
			// must not auto-approve a host that might be quarantined — land it PENDING.
			autoApprove = false
			slog.Warn("quarantine lookup failed; forcing enrolling node to pending", "node", nodeID, "err", qerr)
		}
	}

	now := time.Now()
	rec := &NodeRecord{
		ID:       nodeID,
		Name:     name,
		Labels:   labels,
		NoisePub: req.GetNoiseStaticPub(),
		WGPub:    req.GetWgStaticPub(),
		Platform: PlatformRecord{
			OS:            req.GetPlatform().GetOs(),
			Arch:          req.GetPlatform().GetArch(),
			Hostname:      req.GetPlatform().GetHostname(),
			AgentVersion:  req.GetPlatform().GetAgentVersion(),
			Distro:        req.GetPlatform().GetDistro(),
			DistroVersion: req.GetPlatform().GetDistroVersion(),
			OSPretty:      req.GetPlatform().GetOsPretty(),
			HostUUID:      req.GetPlatform().GetHostUuid(),
		},
		CreatedUnix: now.Unix(),
		// Zero-trust admission: a node is PENDING until an admin approves it,
		// unless the enrollment evidence was strong enough to auto-approve (a
		// token minted --auto-approve, or a cryptographic instance identity).
		Approved: autoApprove,
	}
	if autoApprove {
		rec.ApprovedBy = "auto:" + provider.Name()
		rec.ApprovedAtUnix = now.Unix()
	}
	if err := s.store.PutNode(ws, rec); err != nil {
		return nil, status.Errorf(codes.Internal, "store node: %v", err)
	}
	if err := s.audit.Append("enroll", provider.Name(), nodeID, "", map[string]string{
		"decision": "allow", "name": name,
		"approved": strconv.FormatBool(autoApprove),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit append: %v", err)
	}
	slog.Info("node enrolled", "node", nodeID, "name", name, "provider", provider.Name(), "approved", autoApprove)

	// Zero-touch reachability: an auto-approved node (cloud instance-identity or a
	// --auto-approve token) is reachable the moment it enrolls, so fan its overlay
	// IP + DNS record + WG peer out to existing co-members now. Without this, a
	// co-member cannot resolve/reach the new node until the next unrelated repush
	// (the manual-approval path already repushes; this closes the auto path). A
	// PENDING node is intentionally NOT pushed — it has no authority until approved.
	if autoApprove {
		s.repushAllNetworks(ws)
	}

	// In split mode the enrollee receives the trust-anchor + routine-map pair so it can
	// pin the anchors' TrustKeys (TOFU over this mTLS channel) and verify the split docs
	// thereafter; in legacy mode only the signed config travels, byte-for-byte as before.
	_, legacy, anchors, routineMap := s.fleetWire()
	return &genezav1.EnrollResponse{
		NodeId:              nodeID,
		NodeCertPem:         certPEM,
		CaRootsPem:          s.ca.RootsPEM,
		SignedClusterConfig: legacy,
		TrustAnchors:        anchors,
		RoutineMap:          routineMap,
	}, nil
}

// reservedLabelPrefix marks the label namespace that only ENROLLMENT EVIDENCE may
// write: os:project and os:instance are what resolveLaunchNode matches a hosted-UI
// launch on, and os:cloud names the trust root. vendordata.go fills them from Nova's
// authoritative callback; a tenant hint belongs under os.claim: instead.
const reservedLabelPrefix = "os:"

// mergeEnrollLabels combines the agent's self-asserted labels with the provider's.
//
// Provider labels are enrollment EVIDENCE (a join token's pinned labels, or a
// verified instance document) and are authoritative. The agent's are a convenience
// and are not trusted, so a reserved-namespace key from the agent is DROPPED rather
// than merely shadowed: letting the provider overwrite is not enough, because a
// provider only sets the keys it knows. A plain join token pins no os: labels at
// all, so an agent key like os:instance would otherwise survive untouched — and a
// node wearing another VM's os:instance receives that VM's shell sessions.
func mergeEnrollLabels(agent, provider map[string]string) map[string]string {
	labels := make(map[string]string, len(agent)+len(provider))
	for k, v := range agent {
		if strings.HasPrefix(k, reservedLabelPrefix) {
			slog.Warn("enroll: dropping agent-supplied reserved label",
				"key", k, "reason", "only enrollment evidence may set the "+reservedLabelPrefix+" namespace")
			continue
		}
		labels[k] = v
	}
	for k, v := range provider {
		labels[k] = v
	}
	return labels
}

// claimedInstanceLabel is where an agent reports what the OpenStack metadata
// service told it about itself. It sits in the UNTRUSTED os.claim: namespace
// because vanilla Nova metadata is unsigned plaintext (docs/openstack-integration.md
// §3): reading it proves nothing to anyone but the reader, and a machine that is
// not an OpenStack VM at all asserts it identically.
const claimedInstanceLabel = "os.claim:instance"

// crossCheckInstanceClaim refuses an enrollment whose evidence was minted for a
// different instance than the machine believes itself to be.
//
// It is a NARROWING check, never a grant. The trusted os:instance still comes only
// from enrollment evidence; this cannot create or change it. What it adds is a way
// to catch a token being redeemed somewhere it was not issued for: the vendordata
// path mints a single-use token keyed to one instance and hands it to Nova, which
// delivers it into that one VM's metadata — so possession of that token is evidence
// of BEING that VM. If the redeeming machine's own metadata says otherwise, the
// token has moved, and the honest cases (it really is that VM) all agree.
//
// Silent when either side is absent: a plain operator-minted token pins no
// instance, and a non-OpenStack machine claims none. Neither is suspicious, and
// demanding a claim would break every bare-metal and non-OpenStack enrollment.
func crossCheckInstanceClaim(agent, provider map[string]string) error {
	pinned, claimed := provider[launchInstanceLabel], agent[claimedInstanceLabel]
	if pinned == "" || claimed == "" {
		return nil
	}
	if pinned != claimed {
		return fmt.Errorf("evidence pins instance %s but the machine reports %s", pinned, claimed)
	}
	return nil
}

// osCloudLabel qualifies the instance id by which cloud it came from. Instance
// UUIDs are unique only within one Nova, so an unqualified match would let a
// second cloud's identical UUID collide with this one (residual risk #22).
const osCloudLabel = "os:cloud"

// enforceInstanceUniqueness refuses a second live node for the same OpenStack
// instance, which docs/openstack-integration.md §10 step 5 requires and residual
// risk #15 restates as "single-node-per-UUID as a unique-active-cert constraint".
//
// Without it the labels are not an identity at all: resolveLaunchNode returns the
// FIRST node whose os:instance matches, in store order, so a second node wearing
// the same instance silently competes for that VM's shell sessions and which one
// wins is not something the operator chose.
//
// Refusing is deliberate over silently dropping the label. A duplicate means either
// a stale record the operator has not retired — in which case the message says so
// and retiring fixes it — or an attempt to take over an enrolled VM's identity,
// which should be loud. The legitimate re-enrollment flow retires first, so it
// never reaches here.
func (s *Server) enforceInstanceUniqueness(ws string, labels map[string]string) error {
	instance := labels[launchInstanceLabel]
	if instance == "" {
		return nil // not an OpenStack-identified node; nothing to keep unique
	}
	nodes, err := s.store.ListNodes(ws)
	if err != nil {
		// Cannot prove uniqueness, so do not grant the identity — but let the node
		// enroll. Dropping the label costs a launch target; refusing would make a
		// store hiccup block enrollment entirely.
		slog.Warn("cannot verify instance uniqueness; enrolling without the OpenStack identity",
			"workspace", ws, "instance", instance, "err", err)
		delete(labels, launchInstanceLabel)
		return nil
	}
	for _, n := range nodes {
		if n.Labels[launchInstanceLabel] != instance {
			continue
		}
		if n.Labels[osCloudLabel] != labels[osCloudLabel] {
			continue // same UUID on a different cloud is a different instance
		}
		return fmt.Errorf("instance %s is already enrolled as node %q (%s); retire it before re-enrolling",
			instance, n.Name, n.ID)
	}
	return nil
}

// reservedLabelIn returns the first reserved-namespace key in labels, or "".
// Used to refuse a claim on inputs the controller cannot verify.
func reservedLabelIn(labels map[string]string) string {
	// Sorted so the message names the same key every time for a given input,
	// rather than whichever the map iteration happened to yield first.
	keys := make([]string, 0, len(labels))
	for k := range labels {
		if strings.HasPrefix(k, reservedLabelPrefix) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	return keys[0]
}
