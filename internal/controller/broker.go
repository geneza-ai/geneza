package controller

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"geneza.io/internal/ca"
	"geneza.io/internal/defaults"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/policy"
	"geneza.io/internal/types"
)

// AgentDirectory is the registry surface the broker needs (tests inject a
// fake; *Registry implements it).
type AgentDirectory interface {
	Online(nodeID string) bool
	SendOffer(ctx context.Context, nodeID, sessionID string, signedGrant []byte, turn *genezav1.TurnCreds, timeout time.Duration) (accepted bool, reason string, err error)
	Services(nodeID string) ([]types.Service, bool)
}

// sessionP2PHook lets the broker set up the session-scoped ICE signaling path
// for a brokered session: mint the client+agent TURN creds and register the
// SessionSignal entry. nil = relay-only (the default). Implemented by *Server,
// gated by the session_p2p config flag.
type sessionP2PHook interface {
	setupSession(sessionID, ws, nodeID, user, subject, provider string) (clientTurn, agentTurn *genezav1.TurnCreds)
	teardownSession(sessionID string)
	// armInitialLease mints + pushes the first signed lease (epoch 1) for an
	// accepted session so the agent's fail-closed timer is gated by controller
	// liveness from the start.
	armInitialLease(rec *SessionRecord)
	// selectRelayCandidates returns the signed per-session relay candidate list for
	// the client and agent home regions (each with region-tagged TURN creds).
	selectRelayCandidates(sessionID, clientRegion, agentRegion string) []types.RelayCandidate
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
	adv, ok := b.agents.Services(nodeID)
	if !ok {
		// The agent is held by another controller: resolve against the durable
		// advertised-service directory instead of this controller's live registry.
		if ws, werr := b.store.WorkspaceForNode(nodeID); werr == nil {
			adv, _ = b.store.AdvertisedServices(ws, nodeID)
		}
	}
	for _, svc := range adv {
		if svc.Name == name {
			return svc, true
		}
	}
	return types.Service{}, false
}

const offerTimeout = 5 * time.Second

// Broker turns an authenticated CreateSession request into a signed,
// single-session grant — the controller's core authorization step.
type Broker struct {
	store      Store
	audit      *Audit
	agents     AgentDirectory
	policyFor  func(ws string) policy.Engine
	overlayFor func(ws string) *overlayAllocator
	grantKey   crypto.Signer
	grantKeyID string
	relayAddrs []string
	// relayFloor returns the ordered healthy relay-TCP rendezvous addresses a NEW
	// session's floor should dial, draining/stale relays already excluded. nil (or an
	// empty return) falls back to the static relayAddrs config, so a single-node deploy
	// with no live fleet keeps its configured floor. Wired to the Server's live fleet.
	relayFloor    func() []string
	grantTTL      time.Duration
	defaultMaxTTL time.Duration
	now           func() time.Time
	// sessionP2P sets up session-scoped ICE signaling when enabled (nil = off).
	sessionP2P sessionP2PHook
	// presenceHeartbeat is the advisory client beat interval, surfaced in the
	// CreateSessionResponse for presence-required sessions (0 = presence off).
	presenceHeartbeat time.Duration

	// controllerID + clusterControllers drive the cross-controller client redirect: when the
	// target agent's control stream is held by another controller, the broker returns
	// that controller's signed endpoint so the client re-brokers where the offer can be
	// pushed. clusterControllers is nil / empty on a single-node deployment, making the
	// redirect inert.
	controllerID       string
	clusterControllers func() []types.ControllerEndpoint
}

// SetSessionP2P wires the session-scoped ICE signaling hook (the *Server).
func (b *Broker) SetSessionP2P(h sessionP2PHook) { b.sessionP2P = h }

// SetRelayFloor wires the live-fleet healthy relay-TCP rendezvous resolver used to
// pick a new session's floor. Without it (or when it returns nothing) the broker
// falls back to the static relayAddrs config.
func (b *Broker) SetRelayFloor(fn func() []string) { b.relayFloor = fn }

// floorAddrs is the ordered relay-TCP rendezvous set a new session's floor dials:
// the live healthy fleet when available, else the static relayAddrs config. The
// first entry becomes the scalar grant.RelayAddr (compat); the whole list rides
// grant.RelayFloor so an endpoint tries the next relay if the first refuses.
func (b *Broker) floorAddrs() []string {
	if b.relayFloor != nil {
		if live := b.relayFloor(); len(live) > 0 {
			return live
		}
	}
	return b.relayAddrs
}

// SetPresenceHeartbeat wires the advisory client heartbeat interval.
func (b *Broker) SetPresenceHeartbeat(d time.Duration) { b.presenceHeartbeat = d }

// ReissuedGrant is a freshly-minted grant for an EXISTING session, returned by
// ReissueGrant so the controller can fan the new rendezvous coordinates to both ends
// of a session whose relay drained or died. The session id, lease chain, and
// continuous-authz state are unchanged; only the rendezvous-scoped fields are new.
type ReissuedGrant struct {
	Epoch       int64
	SignedGrant []byte
	Grant       *types.SessionGrant
	RelayAddr   string
	RelayFloor  []string
	RelayToken  string
}

// ReissueGrant re-mints a fresh signed grant for a LIVE session so it can re-home
// onto a surviving relay after the one it was using drained or died, WITHOUT a new
// controller session. It decodes the session's ORIGINALLY-signed grant for its exact
// verified scope and swaps ONLY the rendezvous-scoped fields: a fresh single-use
// RelayToken (the old one is consumed by the first rendezvous), a healthy RelayFloor
// with deadRelayAddr excluded, fresh RelayCandidates, and a new validity window. It
// bumps the record's RehomeEpoch so two ends requesting at once converge on ONE
// re-issue (a request naming an already-applied epoch mints nothing) and a stale
// push is dropped. It refuses a terminal/revoked session — re-home never resurrects
// or extends an ended one; a lapsed lease still tears down independently. For a
// detachable shell it rewrites the action to attach + AttachID = HostSessionID so
// the agent re-attaches the persisted PTY instead of minting a fresh host session.
func (b *Broker) ReissueGrant(ws, sessionID, deadRelayID, deadRelayAddr string, appliedEpoch int64) (*ReissuedGrant, error) {
	rec, err := b.store.GetSession(ws, sessionID)
	if err != nil || rec == nil {
		return nil, fmt.Errorf("no such session")
	}
	if rec.State != SessionActive && rec.State != SessionDetached {
		return nil, fmt.Errorf("session not re-homeable in state %q", rec.State)
	}
	if len(rec.GrantScope) == 0 {
		return nil, fmt.Errorf("session has no recorded grant scope")
	}
	env, err := types.DecodeSigned(rec.GrantScope)
	if err != nil {
		return nil, fmt.Errorf("decode original grant: %w", err)
	}
	orig := &types.SessionGrant{}
	if err := json.Unmarshal(env.Payload, orig); err != nil {
		return nil, fmt.Errorf("unmarshal original grant: %w", err)
	}
	node, err := b.store.GetNode(ws, rec.NodeID)
	if err != nil || node == nil || len(node.NoisePub) != 32 {
		return nil, fmt.Errorf("session node unavailable")
	}

	// Single-minter idempotency: bump exactly once per generation. A request naming
	// an epoch already at/past the record's mints nothing and returns the current
	// generation's epoch so a late requester still learns it has the latest.
	var epoch int64
	if uerr := b.store.UpdateSession(ws, sessionID, func(r *SessionRecord) {
		if appliedEpoch < r.RehomeEpoch {
			epoch = r.RehomeEpoch
			return
		}
		r.RehomeEpoch++
		epoch = r.RehomeEpoch
	}); uerr != nil {
		return nil, uerr
	}

	relayToken, err := types.NewToken()
	if err != nil {
		return nil, fmt.Errorf("relay token: %w", err)
	}
	floor := excludeRelayAddr(b.floorAddrs(), deadRelayAddr)
	if len(floor) == 0 {
		return nil, fmt.Errorf("no surviving relay")
	}
	now := b.now()

	// Start from the original verified scope; swap only what re-home re-mints.
	grant := *orig
	grant.AgentNoisePub = node.NoisePub // unchanged, but re-bind from the live record
	grant.RelayAddr = floor[0]
	grant.RelayFloor = floor
	grant.RelayToken = relayToken
	grant.IssuedAt = now
	grant.ExpiresAt = now.Add(b.grantTTL)
	grant.RelayCandidates = nil
	// A detachable shell re-homes by RE-ATTACHING its persisted host PTY, so the
	// re-issued grant names the host session — the agent takes the attach branch
	// (ownership + liveness re-checked) instead of minting a duplicate shell.
	if rec.Detachable && rec.HostSessionID != "" && grant.Action == types.ActionShell {
		grant.Action = types.ActionAttach
		grant.AttachID = rec.HostSessionID
	}
	// Re-sign the per-session relay candidate list (session p2p only), the dead
	// relay excluded so ICE re-gathers only from survivors.
	if b.sessionP2P != nil && types.PathSupportsICE(rec.ClientPath) {
		grant.RelayCandidates = excludeRelayCandidate(
			b.sessionP2P.selectRelayCandidates(rec.ID, "", node.Region), deadRelayID)
	}
	signed, err := types.Sign(b.grantKey, b.grantKeyID, defaults.ContextGrant, &grant)
	if err != nil {
		return nil, fmt.Errorf("sign grant: %w", err)
	}
	signedBytes, err := signed.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode grant: %w", err)
	}
	return &ReissuedGrant{
		Epoch: epoch, SignedGrant: signedBytes, Grant: &grant,
		RelayAddr: grant.RelayAddr, RelayFloor: grant.RelayFloor, RelayToken: relayToken,
	}, nil
}

// excludeRelayAddr drops a single relay TCP rendezvous address from a floor list,
// preserving order. If dropping it would empty the list (the dead relay is the only
// one the controller knows), the original is returned so the endpoint can still retry —
// a degraded floor onto a recovering relay beats no floor at all.
func excludeRelayAddr(floor []string, dead string) []string {
	if dead == "" {
		return floor
	}
	out := make([]string, 0, len(floor))
	for _, a := range floor {
		if a != dead {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return floor
	}
	return out
}

// excludeRelayCandidate drops the dead relay's region-tagged candidate so ICE
// re-gathers only from survivors.
func excludeRelayCandidate(cands []types.RelayCandidate, deadID string) []types.RelayCandidate {
	if deadID == "" {
		return cands
	}
	out := make([]types.RelayCandidate, 0, len(cands))
	for _, c := range cands {
		if c.RelayID != deadID {
			out = append(out, c)
		}
	}
	return out
}

// SetClusterRedirect wires this controller's id and the signed controller-endpoint
// resolver used to redirect a client to the controller owning a remote agent. Inert
// until the resolver returns a non-empty signed set (single-node never does).
func (b *Broker) SetClusterRedirect(controllerID string, resolve func() []types.ControllerEndpoint) {
	b.controllerID = controllerID
	b.clusterControllers = resolve
}

// redirectFor returns a redirect to the controller that owns nodeID's control stream,
// but ONLY if that controller is present in the signed cluster set — so a redirect can
// never be steered to an unattested endpoint by a tampered affinity row. Returns
// nil when there is no signed fleet (single-node), the node is unowned, this controller
// is the named owner (a stale self-affinity, not a live local stream), or the owner
// is absent from the signed set (the caller then fails closed with Unavailable).
func (b *Broker) redirectFor(nodeID string) *genezav1.ControllerRedirect {
	if b.clusterControllers == nil {
		return nil
	}
	gws := b.clusterControllers()
	if len(gws) == 0 {
		return nil
	}
	owner, _, ok := b.store.AgentAffinity(nodeID)
	if !ok || owner == "" || owner == b.controllerID {
		return nil
	}
	for _, gw := range gws {
		if gw.ControllerID == owner && len(gw.Addrs) > 0 {
			return &genezav1.ControllerRedirect{ControllerId: owner, Addrs: gw.Addrs}
		}
	}
	return nil
}

func NewBroker(store Store, audit *Audit, agents AgentDirectory, policyFor func(ws string) policy.Engine, overlayFor func(ws string) *overlayAllocator,
	grantKey crypto.Signer, grantKeyID string, relayAddrs []string,
	grantTTL, defaultMaxTTL time.Duration) *Broker {
	return &Broker{
		store: store, audit: audit, agents: agents, policyFor: policyFor, overlayFor: overlayFor,
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
// controller is the initiator on behalf of an authenticated console user, so the
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
		node, err = b.store.FindNode(ident.Workspace, req.GetNode())
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
		attachRec, node, err = b.resolveAttach(ident.Workspace, ident.Name, req)
		if err != nil {
			return nil, b.deny(ident.Name, req, "", err.Error(),
				status.Error(codes.PermissionDenied, "attach denied"))
		}
	} else if !preResolved {
		node, err = b.store.FindNode(ident.Workspace, req.GetNode())
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
	// rogue node enrolls, shows up pending, and an admin never approves it.
	if !node.Approved {
		return nil, b.deny(ident.Name, req, node.ID, "node pending approval",
			status.Errorf(codes.FailedPrecondition, "node %s (%s) is pending admin approval", node.ID, node.Name))
	}
	// Authorization gate: a suspended principal gets NO new grant, even
	// with a still-valid 8h cert — this is where a valid credential stops buying
	// access once authorization is revoked (authentication != authorization).
	if b.store.IsSuspended(ident.Workspace, ident.Provider, ident.Subject) {
		return nil, b.deny(ident.Name, req, node.ID, "principal suspended",
			status.Error(codes.PermissionDenied, "your authorization has been suspended"))
	}
	if !b.agents.Online(node.ID) {
		// Not held here. If another controller owns the agent's control stream, redirect
		// the client there so the session is brokered where the offer can be pushed;
		// otherwise the node is genuinely offline. Single-node never redirects.
		if red := b.redirectFor(node.ID); red != nil {
			return &genezav1.CreateSessionResponse{ControllerRedirect: red}, nil
		}
		return nil, status.Errorf(codes.Unavailable, "node %s (%s) is offline", node.ID, node.Name)
	}

	// The client path is decided HERE by the trusted caller (CreateSession ->
	// native for the direct user-cert API; CreateSessionWeb -> web for the
	// in-process proxy), NEVER from the client-supplied req.client_path — a
	// client could otherwise assert "native" to defeat a require_native policy.
	decision := b.policyFor(ident.Workspace).Evaluate(policy.Input{
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
	// Fail closed: a presence-required target is not reachable over the WEB path
	// yet — the browser presence beacon + WebAuthn factor are not implemented for
	// it. A presence-required web session could not beat, so rather than create it
	// and silently drop it (or leave it unenforced), deny it. The native CLI beats.
	if clientPath == types.PathWeb && decision.RequirePresence {
		reason := fmt.Sprintf("presence-required target %s is only reachable via the native client (not the web path)", node.Name)
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
		if a := b.overlayFor(ident.Workspace); a != nil {
			overlayIP, err = a.alloc()
			if err != nil {
				return nil, status.Errorf(codes.ResourceExhausted, "overlay address: %v", err)
			}
		}
	}
	// Hand the overlay IP back on any abort before the agent accepts the session.
	// Once accepted, the agent's lifecycle owns its release (node-control
	// ended/rejected, or the sweep on revoke); a rejected or store-failed VPN
	// session that kept the address would leak it until controller restart, and the
	// 127-address per-workspace pool would exhaust into a permanent VPN denial.
	overlayCommitted := false
	defer func() {
		if !overlayCommitted && overlayIP != "" {
			if a := b.overlayFor(ident.Workspace); a != nil {
				a.release(overlayIP)
			}
		}
	}()

	// The relay-TCP floor is a HEALTHY FLEET pick (draining/stale relays already
	// excluded), not a static config relay: the scalar RelayAddr keeps the first pick
	// for the single-dial path, and RelayFloor carries the ordered set so an endpoint
	// can try the next relay if the first refuses.
	floor := b.floorAddrs()
	grant := &types.SessionGrant{
		V:              1,
		ID:             sessionID,
		User:           ident.Name,
		Roles:          ident.Roles,
		WorkspaceID:    ident.Workspace,
		NetworkVNI:     vniForWorkspace(ident.Workspace),
		NodeID:         node.ID,
		Action:         action,
		Command:        req.GetCommand(),
		AllowPTY:       req.GetWantPty(),
		AllowDetach:    req.GetWantDetachable() && decision.AllowDetach,
		ForwardTarget:  forwardTarget,
		ClientNoisePub: req.GetClientNoisePub(),
		AgentNoisePub:  node.NoisePub,
		RelayAddr:      floor[0],
		RelayFloor:     floor,
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
	// Session p2p (ICE) is for native clients that can hole-punch. The in-process
	// web-shell proxy only ever uses the relay-TCP floor, so do NOT offer ICE to a
	// web session: otherwise the agent waits out its full ICE gather window for
	// candidates the web proxy never sends before falling back to the floor — a
	// ~15s stall before the first shell prompt. The scalar RelayAddr/RelayToken
	// relay-TCP floor is always present for both paths.
	p2p := b.sessionP2P != nil && types.PathSupportsICE(clientPath)
	// Sign the per-session relay candidate list into the grant (session p2p only),
	// so a tampered candidate fails verification.
	if p2p {
		grant.RelayCandidates = b.sessionP2P.selectRelayCandidates(sessionID, req.GetHomeRegion(), node.Region)
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
		ID:              sessionID,
		User:            ident.Name,
		Provider:        ident.Provider,
		Subject:         ident.Subject,
		NodeID:          node.ID,
		NodeName:        node.Name,
		Action:          action,
		State:           SessionPending,
		StartedUnix:     now.Unix(),
		Detachable:      grant.AllowDetach,
		HostSessionID:   grant.AttachID,
		Roles:           ident.Roles,
		ClientPath:      clientPath,
		Service:         grant.Service,
		ServiceKind:     grant.ServiceKind,
		ServiceLabels:   svcLabels,
		OverlayIP:       overlayIP,
		ClientNoisePub:  grant.ClientNoisePub, // bound into every signed lease/revoke
		GrantAllowPTY:   grant.AllowPTY,       // grant ceiling, for tighten detection
		RequirePresence: decision.RequirePresence,
		GrantScope:      signedBytes, // verified scope for an in-session relay re-home re-issue
	}
	if grant.ForwardTarget != "" {
		sessRec.GrantForwardTargets = []string{grant.ForwardTarget}
	}
	// Seed continuous-presence state so the session is not falsely stale before the
	// client beats once (first-beat grace), and the first challenge is ready.
	if decision.RequirePresence {
		sessRec.LastPresenceUnix = now.Unix()
		sessRec.PresenceChallenge = newPresenceChallenge()
	}
	if err := b.store.PutSession(ident.Workspace, sessRec); err != nil {
		return nil, status.Errorf(codes.Internal, "store session: %v", err)
	}

	// Session p2p (opt-in): mint client+agent TURN creds and register the
	// SessionSignal entry BEFORE the offer, so the agent's offer carries its ICE
	// coordinates and the client can immediately signal. Availability only — the
	// Noise gate + signed grant stay the security boundary.
	var clientTurn, agentTurn *genezav1.TurnCreds
	if p2p {
		clientTurn, agentTurn = b.sessionP2P.setupSession(sessionID, ident.Workspace, node.ID, ident.Name, ident.Subject, ident.Provider)
	}

	accepted, reason, offerErr := b.agents.SendOffer(ctx, node.ID, sessionID, signedBytes, agentTurn, offerTimeout)
	if offerErr != nil || !accepted {
		if reason == "" && offerErr != nil {
			reason = offerErr.Error()
		}
		if b.sessionP2P != nil {
			b.sessionP2P.teardownSession(sessionID)
		}
		_ = b.store.UpdateSession(ident.Workspace, sessionID, func(r *SessionRecord) {
			r.State = SessionEnded
			r.EndedUnix = b.now().Unix()
		})
		return nil, b.deny(ident.Name, req, node.ID, "agent rejected offer: "+reason,
			status.Errorf(codes.Unavailable, "agent rejected session: %s", reason))
	}
	// Accepted: the session is live and the agent's lifecycle now owns the overlay
	// IP's release, so the abort-cleanup defer must not hand it back.
	overlayCommitted = true

	if err := b.audit.AppendWS(ident.Workspace, "session_request", ident.Name, node.ID, sessionID, map[string]string{
		"decision": "allow", "action": action, "role": decision.MatchedRole,
		"reason": decision.Reason, "client_path": req.GetClientPath(),
		"detachable": strconv.FormatBool(grant.AllowDetach),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit append: %v", err)
	}

	// Arm the fail-closed lease the instant the tunnel is up (epoch 1), so the
	// agent's lease timer is gated by controller liveness immediately — don't wait
	// for the first sweep tick. The sweep re-pushes it every interval thereafter.
	if b.sessionP2P != nil {
		b.sessionP2P.armInitialLease(sessRec)
	}

	resp := &genezav1.CreateSessionResponse{
		SignedGrant:     signedBytes,
		RelayAddr:       grant.RelayAddr,
		RelayFloor:      grant.RelayFloor,
		RelayToken:      grant.RelayToken,
		AgentNoisePub:   node.NoisePub,
		SessionId:       sessionID,
		Turn:            clientTurn, // nil = relay only (session_p2p off); scalar back-compat
		RelayCandidates: relayCandidatesToProto(grant.RelayCandidates),
	}
	if decision.RequirePresence {
		resp.PresentRequired = true
		resp.HeartbeatIntervalMillis = b.presenceHeartbeat.Milliseconds()
		resp.PresenceChallenge = sessRec.PresenceChallenge // first challenge to echo
	}
	return resp, nil
}

// resolveAttach validates reattachment against the original session record:
// same user, a known host session, and a live-or-detached state. Reattach is
// re-authorized from scratch by the policy evaluation in CreateSession.
func (b *Broker) resolveAttach(ws, user string, req *genezav1.CreateSessionRequest) (*SessionRecord, *NodeRecord, error) {
	rec, err := b.store.GetSession(ws, req.GetAttachSessionId())
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
	node, err := b.store.GetNode(ws, rec.NodeID)
	if err != nil {
		return nil, nil, fmt.Errorf("attach: node %s: %w", rec.NodeID, err)
	}
	// If the client also named a node it must be the session's node.
	if req.GetNode() != "" {
		named, err := b.store.FindNode(ws, req.GetNode())
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
