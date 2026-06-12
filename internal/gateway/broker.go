package gateway

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"osie.cloud/geneza/internal/ca"
	"osie.cloud/geneza/internal/defaults"
	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
	"osie.cloud/geneza/internal/policy"
	"osie.cloud/geneza/internal/types"
)

// AgentDirectory is the registry surface the broker needs (tests inject a
// fake; *Registry implements it).
type AgentDirectory interface {
	Online(nodeID string) bool
	SendOffer(ctx context.Context, nodeID, sessionID string, signedGrant []byte, timeout time.Duration) (accepted bool, reason string, err error)
	Services(nodeID string) ([]types.Service, bool)
}

// implicitServices are the host services every node exposes (the node itself).
func implicitServices(nodeID string) []types.Service {
	return []types.Service{
		{Name: "shell", Kind: types.KindShell, NodeID: nodeID},
		{Name: "exec", Kind: types.KindExec, NodeID: nodeID},
		{Name: "sftp", Kind: types.KindSFTP, NodeID: nodeID},
	}
}

// resolveService finds a named service on a node: implicit host services plus
// whatever the agent advertised in its hello.
func (b *Broker) resolveService(nodeID, name string) (types.Service, bool) {
	for _, svc := range implicitServices(nodeID) {
		if svc.Name == name {
			return svc, true
		}
	}
	adv, _ := b.agents.Services(nodeID)
	for _, svc := range adv {
		if svc.Name == name {
			return svc, true
		}
	}
	return types.Service{}, false
}

const offerTimeout = 5 * time.Second

// Broker turns an authenticated CreateSession request into a signed,
// single-session grant — the gateway's core authorization step.
type Broker struct {
	store         *Store
	audit         *Audit
	agents        AgentDirectory
	engine        func() policy.Engine
	overlay       *overlayAllocator
	grantKey      ed25519.PrivateKey
	grantKeyID    string
	relayAddrs    []string
	grantTTL      time.Duration
	defaultMaxTTL time.Duration
	now           func() time.Time
}

func NewBroker(store *Store, audit *Audit, agents AgentDirectory, engine func() policy.Engine, overlay *overlayAllocator,
	grantKey ed25519.PrivateKey, grantKeyID string, relayAddrs []string,
	grantTTL, defaultMaxTTL time.Duration) *Broker {
	return &Broker{
		store: store, audit: audit, agents: agents, engine: engine, overlay: overlay,
		grantKey: grantKey, grantKeyID: grantKeyID, relayAddrs: relayAddrs,
		grantTTL: grantTTL, defaultMaxTTL: defaultMaxTTL, now: time.Now,
	}
}

func validForwardTarget(t string) error {
	host, port, err := net.SplitHostPort(t)
	if err != nil {
		return fmt.Errorf("forward_target must be host:port: %w", err)
	}
	if host == "" {
		return fmt.Errorf("forward_target has empty host")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("forward_target has invalid port %q", port)
	}
	return nil
}

// CreateSession evaluates policy and brokers a session offer to the agent.
// ident is the verified user identity from the caller's mTLS cert. All sessions
// brokered over the direct user-cert API are native/true-E2E.
func (b *Broker) CreateSession(ctx context.Context, ident *ca.Identity, req *genezav1.CreateSessionRequest) (*genezav1.CreateSessionResponse, error) {
	return b.createSession(ctx, ident, req, types.PathNative)
}

// CreateSessionWeb brokers a session for the in-process web-shell proxy: the
// gateway is the initiator on behalf of an authenticated console user, so the
// path is "web" and `require_native` policy rules correctly deny it.
func (b *Broker) CreateSessionWeb(ctx context.Context, ident *ca.Identity, req *genezav1.CreateSessionRequest) (*genezav1.CreateSessionResponse, error) {
	return b.createSession(ctx, ident, req, types.PathWeb)
}

func (b *Broker) createSession(ctx context.Context, ident *ca.Identity, req *genezav1.CreateSessionRequest, clientPath string) (*genezav1.CreateSessionResponse, error) {
	now := b.now()
	action := req.GetAction()
	forwardTarget := req.GetForwardTarget()

	var (
		node        *NodeRecord
		attachRec   *SessionRecord
		err         error
		svcName     string
		svcKind     string
		svcLabels   map[string]string
		routes      []string
		preResolved bool
	)

	// Service connect/vpn: resolve the named service on the node and DERIVE the
	// real action + target/routes server-side (the client never picks an
	// arbitrary forward target — it names an authorized service). Policy then
	// gates by service name/kind/labels.
	if req.GetService() != "" || action == "connect" || action == types.ActionVPN {
		node, err = b.store.FindNode(req.GetNode())
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil, status.Errorf(codes.NotFound, "node %q not found", req.GetNode())
			}
			return nil, status.Errorf(codes.Internal, "resolve node: %v", err)
		}
		svc, ok := b.resolveService(node.ID, req.GetService())
		if !ok {
			return nil, status.Errorf(codes.NotFound, "service %q not found on node %s", req.GetService(), node.Name)
		}
		preResolved = true
		action = svc.Action()
		svcName, svcKind, svcLabels = svc.Name, svc.Kind, svc.Labels
		switch svc.Kind {
		case types.KindSubnet:
			routes = []string{svc.Addr}
		case types.KindExitNode:
			routes = []string{"0.0.0.0/0"}
		case types.KindShell, types.KindExec, types.KindSFTP:
			// host service: no forward target
		default: // forwarded service
			forwardTarget = svc.Addr
		}
	}

	// Request-shape validation (mirrors types.SessionGrant.Validate so a grant
	// we sign is always one an agent will accept).
	switch action {
	case types.ActionShell, types.ActionExec, types.ActionSFTP, types.ActionForward, types.ActionAttach, types.ActionVPN:
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown action %q", action)
	}
	if action == types.ActionExec && req.GetCommand() == "" {
		return nil, status.Error(codes.InvalidArgument, "exec requires command")
	}
	if action == types.ActionForward {
		if err := validForwardTarget(forwardTarget); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}
	if action == types.ActionVPN && len(routes) == 0 {
		return nil, status.Error(codes.InvalidArgument, "vpn requires a subnet-route or exit-node service")
	}
	if action == types.ActionAttach && req.GetAttachSessionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "attach requires attach_session_id")
	}
	if len(req.GetClientNoisePub()) != 32 {
		return nil, status.Error(codes.InvalidArgument, "client_noise_pub must be 32 bytes")
	}

	// Resolve the target node; for attach the prior session record is
	// authoritative (and all its failure modes collapse to one opaque denial
	// so session ids cannot be probed).
	if action == types.ActionAttach {
		attachRec, node, err = b.resolveAttach(ident.Name, req)
		if err != nil {
			return nil, b.deny(ident.Name, req, "", err.Error(),
				status.Error(codes.PermissionDenied, "attach denied"))
		}
	} else if !preResolved {
		node, err = b.store.FindNode(req.GetNode())
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil, status.Errorf(codes.NotFound, "node %q not found", req.GetNode())
			}
			return nil, status.Errorf(codes.Internal, "resolve node: %v", err)
		}
	}
	// Zero-trust admission gate: an enrolled-but-unapproved node has an identity
	// (it can connect its control channel) but NO session may be brokered to it.
	// This is what makes a leaked/replayed join token insufficient on its own — a
	// rogue machine enrolls, shows up pending, and an admin never approves it.
	if !node.Approved {
		return nil, b.deny(ident.Name, req, node.ID, "node pending approval",
			status.Errorf(codes.FailedPrecondition, "node %s (%s) is pending admin approval", node.ID, node.Name))
	}
	if !b.agents.Online(node.ID) {
		return nil, status.Errorf(codes.Unavailable, "node %s (%s) is offline", node.ID, node.Name)
	}

	// The client path is decided HERE by the trusted caller (CreateSession ->
	// native for the direct user-cert API; CreateSessionWeb -> web for the
	// in-process proxy), NEVER from the client-supplied req.client_path — a
	// client could otherwise assert "native" to defeat a require_native policy.
	decision := b.engine().Evaluate(policy.Input{
		User:          ident.Name,
		Roles:         ident.Roles,
		NodeID:        node.ID,
		NodeName:      node.Name,
		NodeLabels:    node.Labels,
		Action:        action,
		ClientPath:    clientPath,
		Service:       svcName,
		ServiceKind:   svcKind,
		ServiceLabels: svcLabels,
		Now:           now,
	})
	if !decision.Allow {
		return nil, b.deny(ident.Name, req, node.ID, decision.Reason,
			status.Error(codes.PermissionDenied, decision.Reason))
	}
	// Strict: a client that asked for detachability must not silently get a
	// non-detachable session on a target where policy forbids it.
	if req.GetWantDetachable() && !decision.AllowDetach {
		reason := fmt.Sprintf("detachable sessions not permitted on node %s by role %q", node.Name, decision.MatchedRole)
		return nil, b.deny(ident.Name, req, node.ID, reason, status.Error(codes.PermissionDenied, reason))
	}

	sessionID, err := randHexID("s-")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "session id: %v", err)
	}
	maxTTL := b.defaultMaxTTL
	if decision.MaxSessionTTL > 0 && decision.MaxSessionTTL < maxTTL {
		maxTTL = decision.MaxSessionTTL
	}
	relayToken, err := types.NewToken()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "relay token: %v", err)
	}

	// VPN sessions get an overlay IP and validated routes.
	var overlayIP string
	if action == types.ActionVPN {
		for _, c := range routes {
			if !validCIDR(c) {
				return nil, status.Errorf(codes.InvalidArgument, "service route %q is not a valid CIDR", c)
			}
		}
		if b.overlay != nil {
			overlayIP, err = b.overlay.alloc()
			if err != nil {
				return nil, status.Errorf(codes.ResourceExhausted, "overlay address: %v", err)
			}
		}
	}

	grant := &types.SessionGrant{
		V:              1,
		ID:             sessionID,
		User:           ident.Name,
		Roles:          ident.Roles,
		NodeID:         node.ID,
		Action:         action,
		Command:        req.GetCommand(),
		AllowPTY:       req.GetWantPty(),
		AllowDetach:    req.GetWantDetachable() && decision.AllowDetach,
		ForwardTarget:  forwardTarget,
		ClientNoisePub: req.GetClientNoisePub(),
		AgentNoisePub:  node.NoisePub,
		RelayAddr:      b.relayAddrs[0],
		RelayToken:     relayToken,
		ClientPath:     clientPath,
		IssuedAt:       now,
		ExpiresAt:      now.Add(b.grantTTL),
		MaxSessionTTL:  maxTTL,
		Record:         decision.Record && action != types.ActionVPN, // no PTY to record for VPN
		Service:        svcName,
		ServiceKind:    svcKind,
		Routes:         routes,
		OverlayIP:      overlayIP,
	}
	if attachRec != nil {
		grant.AttachID = attachRec.HostSessionID
	}
	signed, err := types.Sign(b.grantKey, b.grantKeyID, defaults.ContextGrant, grant)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sign grant: %v", err)
	}
	signedBytes, err := signed.Encode()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode grant: %v", err)
	}

	// Persist before offering so agent session events that race the offer
	// ack always find the record; a rejected offer marks it ended below.
	sessRec := &SessionRecord{
		ID:            sessionID,
		User:          ident.Name,
		NodeID:        node.ID,
		NodeName:      node.Name,
		Action:        action,
		State:         SessionPending,
		StartedUnix:   now.Unix(),
		Detachable:    grant.AllowDetach,
		HostSessionID: grant.AttachID,
		Roles:         ident.Roles,
		ClientPath:    clientPath,
		Service:       grant.Service,
		ServiceKind:   grant.ServiceKind,
		ServiceLabels: svcLabels,
		OverlayIP:     overlayIP,
	}
	if err := b.store.PutSession(sessRec); err != nil {
		return nil, status.Errorf(codes.Internal, "store session: %v", err)
	}

	accepted, reason, offerErr := b.agents.SendOffer(ctx, node.ID, sessionID, signedBytes, offerTimeout)
	if offerErr != nil || !accepted {
		if reason == "" && offerErr != nil {
			reason = offerErr.Error()
		}
		_ = b.store.UpdateSession(sessionID, func(r *SessionRecord) {
			r.State = SessionEnded
			r.EndedUnix = b.now().Unix()
		})
		return nil, b.deny(ident.Name, req, node.ID, "agent rejected offer: "+reason,
			status.Errorf(codes.Unavailable, "agent rejected session: %s", reason))
	}

	if err := b.audit.Append("session_request", ident.Name, node.ID, sessionID, map[string]string{
		"decision": "allow", "action": action, "role": decision.MatchedRole,
		"reason": decision.Reason, "client_path": req.GetClientPath(),
		"detachable": strconv.FormatBool(grant.AllowDetach),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit append: %v", err)
	}

	return &genezav1.CreateSessionResponse{
		SignedGrant:   signedBytes,
		RelayAddr:     grant.RelayAddr,
		RelayToken:    grant.RelayToken,
		AgentNoisePub: node.NoisePub,
		SessionId:     sessionID,
	}, nil
}

// resolveAttach validates reattachment against the original session record:
// same user, a known host session, and a live-or-detached state. Reattach is
// re-authorized from scratch by the policy evaluation in CreateSession.
func (b *Broker) resolveAttach(user string, req *genezav1.CreateSessionRequest) (*SessionRecord, *NodeRecord, error) {
	rec, err := b.store.GetSession(req.GetAttachSessionId())
	if err != nil {
		return nil, nil, fmt.Errorf("attach: session %q: %w", req.GetAttachSessionId(), err)
	}
	if rec.User != user {
		return nil, nil, fmt.Errorf("attach: session %s belongs to %q, not %q", rec.ID, rec.User, user)
	}
	if rec.HostSessionID == "" {
		return nil, nil, fmt.Errorf("attach: session %s has no host session id", rec.ID)
	}
	if rec.State != SessionActive && rec.State != SessionDetached {
		return nil, nil, fmt.Errorf("attach: session %s is %s", rec.ID, rec.State)
	}
	node, err := b.store.GetNode(rec.NodeID)
	if err != nil {
		return nil, nil, fmt.Errorf("attach: node %s: %w", rec.NodeID, err)
	}
	// If the client also named a node it must be the session's node.
	if req.GetNode() != "" {
		named, err := b.store.FindNode(req.GetNode())
		if err != nil || named.ID != node.ID {
			return nil, nil, fmt.Errorf("attach: requested node %q does not match session node %s", req.GetNode(), node.ID)
		}
	}
	return rec, node, nil
}

// deny audits a denial and returns the gRPC error; an audit failure outranks
// it (no audit record, no answer).
func (b *Broker) deny(user string, req *genezav1.CreateSessionRequest, nodeID, reason string, denyErr error) error {
	if err := b.audit.Append("session_request", user, nodeID, "", map[string]string{
		"decision": "deny", "action": req.GetAction(), "reason": reason,
		"node_arg": req.GetNode(), "client_path": req.GetClientPath(),
	}); err != nil {
		return status.Errorf(codes.Internal, "audit append: %v", err)
	}
	return denyErr
}
