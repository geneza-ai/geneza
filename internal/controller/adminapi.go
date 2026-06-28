package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"geneza.io/internal/defaults"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

type adminAPIService struct {
	genezav1.UnimplementedAdminAPIServer
	s *Server
}

var sha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// canaryHeartbeatFresh is how recent a canary heartbeat must be to count
// toward promoting a version to the stable ring.
const canaryHeartbeatFresh = 60 * time.Second

func adminActor(ctx context.Context) string {
	if ident, _, ok := identityFrom(ctx); ok {
		return ident.Name
	}
	return ""
}

// actorWorkspace is the workspace of the authenticated caller, derived solely
// from its verified cert. Falls back to the default workspace when there is no
// identity (unit tests / break-glass), so single-tenant behavior is unchanged.
func actorWorkspace(ctx context.Context) string {
	if ident, _, ok := identityFrom(ctx); ok && ident.Workspace != "" {
		return ident.Workspace
	}
	return defaultWorkspace
}

func (a *adminAPIService) CreateJoinToken(ctx context.Context, req *genezav1.CreateJoinTokenRequest) (*genezav1.CreateJoinTokenResponse, error) {
	s := a.s
	ttl := time.Duration(req.GetTtlSeconds()) * time.Second
	if ttl <= 0 {
		ttl = defaults.JoinTokenTTL
	}
	maxUses := req.GetMaxUses()
	if maxUses <= 0 {
		maxUses = 1
	}
	token, err := types.NewToken()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "token: %v", err)
	}
	expires := time.Now().Add(ttl).Unix()
	if err := s.store.PutToken(token, &TokenRecord{
		WorkspaceID: actorWorkspace(ctx),
		Labels:      req.GetLabels(),
		ExpiresUnix: expires,
		MaxUses:     maxUses,
		AutoApprove: req.GetAutoApprove(),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "store token: %v", err)
	}
	// The token value itself never reaches the audit log.
	if err := s.audit.Append("token_create", adminActor(ctx), "", "", map[string]string{
		"ttl_seconds":  strconv.FormatInt(int64(ttl/time.Second), 10),
		"max_uses":     strconv.FormatInt(int64(maxUses), 10),
		"labels":       labelString(req.GetLabels()),
		"auto_approve": strconv.FormatBool(req.GetAutoApprove()),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit append: %v", err)
	}
	return &genezav1.CreateJoinTokenResponse{
		Token:           token,
		ExpiresUnix:     expires,
		RootFingerprint: s.rootFingerprint(),
	}, nil
}

// ApproveNode flips the zero-trust admission gate for one node. approve=true
// makes a pending node usable; approve=false re-quarantines it (and the next
// continuous-authz sweep tears down any live sessions, since the gate is also
// re-checked there — see continuousauthz.go).
func (a *adminAPIService) ApproveNode(ctx context.Context, req *genezav1.ApproveNodeRequest) (*genezav1.Empty, error) {
	s := a.s
	ws := actorWorkspace(ctx)
	node, err := s.store.FindNode(ws, req.GetNode())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "node %q not found", req.GetNode())
		}
		return nil, status.Errorf(codes.Internal, "resolve node: %v", err)
	}
	by := adminActor(ctx)
	if err := s.approveNodeWithReason(ws, node, req.GetApprove(), req.GetReason(), by); err != nil {
		if errors.Is(err, errReasonRequired) {
			return nil, status.Errorf(codes.InvalidArgument,
				"node %s is quarantined; a reason is required to re-approve it", node.ID)
		}
		return nil, status.Errorf(codes.Internal, "set node admission: %v", err)
	}
	return &genezav1.Empty{}, nil
}

// requirePlatformAdmin gates hub-graph mutations (bindings, cloud registration)
// on the platform-admin role: cross-tenant authority that must be strictly above
// a per-deployment admin and is issued only out-of-band. An IdP/policy-granted
// admin (tenant fleet admin) is intentionally rejected here.
func requirePlatformAdmin(ctx context.Context) error {
	ident, _, ok := identityFrom(ctx)
	if !ok || ident == nil {
		return status.Error(codes.Unauthenticated, "platform-admin certificate required")
	}
	if !hasRole(ident, rolePlatformAdmin) {
		return status.Error(codes.PermissionDenied, "platform-admin role required for hub-graph mutations")
	}
	return nil
}

// BindSource binds a cloud-qualified external source (e.g. an OpenStack project)
// to a workspace — the operator pre-bind path. Requires platform-admin; the
// target workspace must exist.
func (a *adminAPIService) BindSource(ctx context.Context, req *genezav1.BindSourceRequest) (*genezav1.Empty, error) {
	if err := requirePlatformAdmin(ctx); err != nil {
		return nil, err
	}
	s := a.s
	key := strings.TrimSpace(req.GetKey())
	ws := strings.TrimSpace(req.GetWorkspaceId())
	if key == "" || ws == "" {
		return nil, status.Error(codes.InvalidArgument, "key and workspace_id are required")
	}
	if _, err := s.store.GetWorkspace(ws); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "workspace %q not found", ws)
		}
		return nil, status.Errorf(codes.Internal, "resolve workspace: %v", err)
	}
	by := adminActor(ctx)
	if err := s.store.PutSourceBinding(&SourceBinding{
		Key: key, WorkspaceID: ws, CreatedUnix: time.Now().Unix(), CreatedBy: by,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "store binding: %v", err)
	}
	if err := s.audit.Append("source_bind", by, "", "", map[string]string{
		"key": key, "workspace": ws, "decision": "bind",
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit append: %v", err)
	}
	return &genezav1.Empty{}, nil
}

// UnbindSource removes a source binding (operator unbind path). Requires
// platform-admin.
func (a *adminAPIService) UnbindSource(ctx context.Context, req *genezav1.UnbindSourceRequest) (*genezav1.Empty, error) {
	if err := requirePlatformAdmin(ctx); err != nil {
		return nil, err
	}
	s := a.s
	key := strings.TrimSpace(req.GetKey())
	if key == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}
	if err := s.store.DeleteSourceBinding(key); err != nil {
		return nil, status.Errorf(codes.Internal, "delete binding: %v", err)
	}
	if err := s.audit.Append("source_bind", adminActor(ctx), "", "", map[string]string{
		"key": key, "decision": "unbind",
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit append: %v", err)
	}
	return &genezav1.Empty{}, nil
}

// ListSourceBindings lists all cloud-qualified source bindings.
func (a *adminAPIService) ListSourceBindings(_ context.Context, _ *genezav1.Empty) (*genezav1.ListSourceBindingsResponse, error) {
	bs, err := a.s.store.ListSourceBindings()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list bindings: %v", err)
	}
	out := make([]*genezav1.SourceBindingInfo, 0, len(bs))
	for _, b := range bs {
		out = append(out, &genezav1.SourceBindingInfo{
			Key: b.Key, WorkspaceId: b.WorkspaceID, CreatedUnix: b.CreatedUnix,
			CreatedBy: b.CreatedBy, AutoProvisioned: b.AutoProvisioned,
		})
	}
	return &genezav1.ListSourceBindingsResponse{Bindings: out}, nil
}

// RevokeCert adds a leaf cert's serial to the revocation denylist: the next
// authenticated RPC from that cert is denied, killing it before TTL without a
// fleet CA re-key. Admin-gated (the AdminAPI is already admin-only).
func (a *adminAPIService) RevokeCert(ctx context.Context, req *genezav1.RevokeCertRequest) (*genezav1.Empty, error) {
	serial := strings.ToLower(strings.TrimSpace(req.GetSerial()))
	if serial == "" {
		return nil, status.Error(codes.InvalidArgument, "serial is required")
	}
	by := adminActor(ctx)
	if err := a.s.store.RevokeCert(&RevokedCert{
		Serial: serial, RevokedUnix: time.Now().Unix(), By: by, Reason: req.GetReason(),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "revoke cert: %v", err)
	}
	// Drop any cached allow for this serial so the deny takes effect on the next
	// RPC, not after the cache TTL.
	a.s.deny.invalidateRevoked(serial)
	if err := a.s.audit.Append("cert_revoke", by, "", "", map[string]string{
		"serial": serial, "reason": req.GetReason(),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit append: %v", err)
	}
	// Takes effect on the cert's next authenticated RPC / stream (re)connect.
	// Immediate teardown of an already-open control stream would need a
	// serial->node index we don't keep yet — noted as a refinement.
	return &genezav1.Empty{}, nil
}

// InstallTrustAnchors ingests an offline/threshold-signed TrustAnchors envelope
// (assembled by geneza-trust) and CASes it into the store, activating split mode.
// The controller holds no trust key and cannot author the anchor — it only stores the
// operator-supplied one and re-pins the routine map to it. Cluster-admin gated by the
// AdminAPI interceptor.
func (a *adminAPIService) InstallTrustAnchors(ctx context.Context, req *genezav1.InstallTrustAnchorsRequest) (*genezav1.InstallTrustAnchorsResponse, error) {
	if len(req.GetTrustAnchors()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "trust_anchors is required")
	}
	anchorVersion, configVersion, err := a.s.installTrustAnchors(req.GetTrustAnchors())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "install trust anchors: %v", err)
	}
	by := adminActor(ctx)
	if err := a.s.audit.Append("trust_anchors_install", by, "", "", map[string]string{
		"anchor_version": strconv.FormatInt(anchorVersion, 10),
		"config_version": strconv.FormatInt(configVersion, 10),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit append: %v", err)
	}
	return &genezav1.InstallTrustAnchorsResponse{AnchorVersion: anchorVersion, ConfigVersion: configVersion}, nil
}

func (a *adminAPIService) ListRevokedCerts(_ context.Context, _ *genezav1.Empty) (*genezav1.ListRevokedCertsResponse, error) {
	rs, err := a.s.store.ListRevokedCerts()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list revoked: %v", err)
	}
	out := make([]*genezav1.RevokedCertInfo, 0, len(rs))
	for _, r := range rs {
		out = append(out, &genezav1.RevokedCertInfo{
			Serial: r.Serial, RevokedUnix: r.RevokedUnix, By: r.By, Reason: r.Reason, Subject: r.Subject,
		})
	}
	return &genezav1.ListRevokedCertsResponse{Certs: out}, nil
}

// ListWorkspaces lists the tenants this controller hosts (from the store registry).
func (a *adminAPIService) ListWorkspaces(ctx context.Context, _ *genezav1.Empty) (*genezav1.ListWorkspacesResponse, error) {
	wss, err := a.s.store.ListWorkspaces()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list workspaces: %v", err)
	}
	out := make([]*genezav1.WorkspaceInfo, 0, len(wss))
	for _, w := range wss {
		out = append(out, &genezav1.WorkspaceInfo{Id: w.ID, Name: w.Name, OverlayCidr: w.OverlayCIDR})
	}
	return &genezav1.ListWorkspacesResponse{Workspaces: out}, nil
}

// RemoveNode decommissions a machine: revoke its live sessions, then delete the
// record so it leaves the fleet and must re-enroll (and be re-approved) to come
// back. The node's own cert keeps working until it expires (short TTL), but with
// no record the broker denies every session to it.
func (a *adminAPIService) RemoveNode(ctx context.Context, req *genezav1.RemoveNodeRequest) (*genezav1.Empty, error) {
	s := a.s
	ws := actorWorkspace(ctx)
	node, err := s.store.FindNode(ws, req.GetNode())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "node %q not found", req.GetNode())
		}
		return nil, status.Errorf(codes.Internal, "resolve node: %v", err)
	}
	// Tear down any live sessions first so we don't orphan tunnels.
	if sessions, err := s.store.ListSessions(ws); err == nil {
		for _, rec := range sessions {
			if rec.NodeID == node.ID && (rec.State == SessionActive || rec.State == SessionDetached) {
				_ = s.revokeSession(rec, "node removed")
			}
		}
	}
	if err := s.store.DeleteNode(ws, node.ID); err != nil {
		return nil, status.Errorf(codes.Internal, "delete node: %v", err)
	}
	if err := s.audit.Append("node_remove", adminActor(ctx), node.ID, "", map[string]string{
		"name": node.Name,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit append: %v", err)
	}
	slog.Info("node removed", "node", node.ID, "name", node.Name, "by", adminActor(ctx))
	// Symmetric teardown: drop the removed node from every co-member's peer set.
	s.repushAllNetworks(ws)
	return &genezav1.Empty{}, nil
}

func labelString(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, k+"="+v)
	}
	// json marshal would also do, but keep it grep-friendly.
	b, _ := json.Marshal(parts)
	return string(b)
}

// PublishArtifact accepts a binary stream whose first chunk carries the
// OFFLINE-signed manifest. The controller verifies the blob against the
// manifest hash, and the manifest signature too when artifact_pubkey_file is
// configured — but it can never produce a manifest itself (no signing key).
func (a *adminAPIService) PublishArtifact(stream grpc.ClientStreamingServer[genezav1.ArtifactChunk, genezav1.PublishArtifactResponse]) error {
	s := a.s
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if len(first.GetSignedManifest()) == 0 {
		return status.Error(codes.InvalidArgument, "first chunk must carry signed_manifest")
	}
	signed, err := types.DecodeSigned(first.GetSignedManifest())
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "signed manifest: %v", err)
	}
	var m types.Manifest
	trust := s.publishTrustSet()
	if len(trust) > 0 {
		// Accept any signing key the single pin OR the configured root-keys doc
		// authorizes (rotation-safe). Defense in depth only — the agent re-verifies
		// the full chain against its pinned root before installing anything.
		if _, err := types.Verify(trust, defaults.ContextManifest, signed, &m); err != nil {
			return status.Errorf(codes.PermissionDenied, "manifest signature: %v", err)
		}
	} else if err := json.Unmarshal(signed.Payload, &m); err != nil {
		// Unverified parse for metadata only; agents/bootstraps still verify
		// against their own pinned key before installing anything.
		return status.Errorf(codes.InvalidArgument, "manifest payload: %v", err)
	}
	if m.Product == "" || m.Version == "" || m.OS == "" || m.Arch == "" {
		return status.Error(codes.InvalidArgument, "manifest missing product/version/os/arch")
	}
	if !sha256HexRe.MatchString(m.SHA256) {
		return status.Error(codes.InvalidArgument, "manifest sha256 must be 64 lowercase hex chars")
	}
	if m.Size <= 0 {
		return status.Error(codes.InvalidArgument, "manifest size must be positive")
	}

	if err := os.MkdirAll(s.cfg.ArtifactsDir(), 0o700); err != nil {
		return status.Errorf(codes.Internal, "artifacts dir: %v", err)
	}
	tmp, err := os.CreateTemp(s.cfg.ArtifactsDir(), ".upload-*")
	if err != nil {
		return status.Errorf(codes.Internal, "temp file: %v", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpPath) // no-op after successful rename
	}()

	var total int64
	chunk := first
	for {
		total += int64(len(chunk.GetData()))
		if total > m.Size {
			return status.Errorf(codes.InvalidArgument, "blob exceeds manifest size %d", m.Size)
		}
		if _, err := tmp.Write(chunk.GetData()); err != nil {
			return status.Errorf(codes.Internal, "write blob: %v", err)
		}
		if chunk.GetEof() {
			break
		}
		chunk, err = stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		return status.Errorf(codes.Internal, "sync blob: %v", err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return status.Errorf(codes.Internal, "seek blob: %v", err)
	}
	if err := m.VerifyBlob(tmp); err != nil {
		return status.Errorf(codes.InvalidArgument, "blob does not match manifest: %v", err)
	}
	if err := tmp.Close(); err != nil {
		return status.Errorf(codes.Internal, "close blob: %v", err)
	}
	final := filepath.Join(s.cfg.ArtifactsDir(), m.SHA256)
	if err := os.Rename(tmpPath, final); err != nil {
		return status.Errorf(codes.Internal, "store blob: %v", err)
	}
	if err := s.store.PutManifest(ManifestKey(m.Product, m.OS, m.Arch, m.Version), first.GetSignedManifest()); err != nil {
		return status.Errorf(codes.Internal, "store manifest: %v", err)
	}
	if err := s.audit.Append("artifact_publish", adminActor(stream.Context()), "", "", map[string]string{
		"product": m.Product, "version": m.Version, "os": m.OS, "arch": m.Arch,
		"sha256": m.SHA256, "size": strconv.FormatInt(m.Size, 10),
		"signature_verified": strconv.FormatBool(len(trust) > 0),
	}); err != nil {
		return status.Errorf(codes.Internal, "audit append: %v", err)
	}
	slog.Info("artifact published", "product", m.Product, "version", m.Version, "sha256", m.SHA256)
	// If auto-update is on for this product, a fresh publish kicks off a staggered
	// auto-rollout to the new version (no-op if one is already running).
	s.maybeAutoStartRollout(m.Product, m.Version)
	return stream.SendAndClose(&genezav1.PublishArtifactResponse{Version: m.Version, Sha256: m.SHA256})
}

// rolloutRing abstracts one product's staged-rollout settings (the agent ring or
// the relay ring) behind a uniform get/set surface, so SetDesiredVersion drives
// either with one code path. canaryReady reports whether a ring member is proven
// healthy on a candidate version (the stable-promotion gate); it differs per
// product (agents report on the control stream, relays on their heartbeat).
type rolloutRing struct {
	product          string
	canaryNodes      func() ([]string, error)
	setCanaryNodes   func([]string) error
	setCanaryVersion func(string) error
	setStableVersion func(string) error
	canaryBlockers   func(nodes []string, version string) []string
}

func (s *Server) agentRing() rolloutRing {
	return rolloutRing{
		product:          "geneza-agent",
		canaryNodes:      s.store.CanaryNodes,
		setCanaryNodes:   s.store.SetCanaryNodes,
		setCanaryVersion: s.store.SetCanaryVersion,
		setStableVersion: s.store.SetStableVersion,
		canaryBlockers:   s.canaryBlockers,
	}
}

func (s *Server) relayRing() rolloutRing {
	return rolloutRing{
		product:          "geneza-relay",
		canaryNodes:      s.store.RelayCanaryNodes,
		setCanaryNodes:   s.store.SetRelayCanaryNodes,
		setCanaryVersion: s.store.SetRelayCanaryVersion,
		setStableVersion: s.store.SetRelayStableVersion,
		canaryBlockers:   s.relayCanaryBlockers,
	}
}

// ringForProduct selects the rollout ring. "" defaults to the agent ring so the
// existing agent rollout path is unchanged.
func (s *Server) ringForProduct(product string) (rolloutRing, error) {
	switch product {
	case "", "geneza-agent":
		return s.agentRing(), nil
	case "geneza-relay":
		return s.relayRing(), nil
	default:
		return rolloutRing{}, status.Errorf(codes.InvalidArgument, "unknown product %q", product)
	}
}

// SetDesiredVersion drives the staged rollout for a product (agent by default,
// or the relay ring when product=geneza-relay). Promoting a version to stable
// while a canary ring exists requires every canary member to be live, healthy
// (<60s heartbeat) and already running that version — the health gate that
// keeps a bad build from reaching the whole fleet.
func (a *adminAPIService) SetDesiredVersion(ctx context.Context, req *genezav1.SetDesiredVersionRequest) (*genezav1.Empty, error) {
	s := a.s
	ring := req.GetRing()
	version := req.GetVersion()
	r, err := s.ringForProduct(req.GetProduct())
	if err != nil {
		return nil, err
	}
	// A staggered rollout owns the canary ring while it runs; refuse a manual
	// version write that would fight the controller. The operator aborts the
	// rollout first, then pins by hand.
	if cur, _ := s.loadRollout(req.GetProduct()); cur != nil && !cur.terminal() {
		return nil, status.Errorf(codes.FailedPrecondition,
			"a staged rollout is in progress for %s (state %s); abort it before setting a version manually",
			productLabel(req.GetProduct()), cur.State)
	}
	switch ring {
	case "canary":
		if nodes := req.GetCanaryNodes(); len(nodes) > 0 {
			if err := r.setCanaryNodes(nodes); err != nil {
				return nil, status.Errorf(codes.Internal, "store canary nodes: %v", err)
			}
		}
		if err := r.setCanaryVersion(version); err != nil {
			return nil, status.Errorf(codes.Internal, "store canary version: %v", err)
		}
	case "stable":
		canaryNodes, err := r.canaryNodes()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "canary nodes: %v", err)
		}
		if len(canaryNodes) > 0 && version != "" {
			if blockers := r.canaryBlockers(canaryNodes, version); len(blockers) > 0 {
				return nil, status.Errorf(codes.FailedPrecondition,
					"stable promotion to %s blocked by canary health gate: %s",
					version, strings.Join(blockers, "; "))
			}
		}
		if err := r.setStableVersion(version); err != nil {
			return nil, status.Errorf(codes.Internal, "store stable version: %v", err)
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "ring must be \"stable\" or \"canary\", got %q", ring)
	}
	if err := s.audit.Append("set_desired_version", adminActor(ctx), "", "", map[string]string{
		"product": r.product, "ring": ring, "version": version,
		"canary_nodes": strings.Join(req.GetCanaryNodes(), ","),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit append: %v", err)
	}
	return &genezav1.Empty{}, nil
}

// canaryBlockers returns one human-readable reason per canary node that is
// not yet proven healthy on the candidate version.
// agentLive is the fleet-wide liveness of one agent, drawn from the freshest of
// the local registry (agents homed on THIS controller) or shared presence (agents
// homed on another controller). It is what makes a rollout wave's health correct
// under HA, where no single controller's registry sees the whole fleet.
type agentLive struct {
	online   bool
	version  string
	healthy  bool
	lastSeen time.Time
}

// agentLivenessMap resolves liveness for a set of nodes in one pass: shared
// presence is read once, then the local registry is overlaid (it is strictly
// fresher for agents homed here, since it updates on every heartbeat in-process).
func (s *Server) agentLivenessMap(nodes []string) map[string]agentLive {
	out := make(map[string]agentLive, len(nodes))
	want := make(map[string]bool, len(nodes))
	for _, id := range nodes {
		want[id] = true
	}
	if rows, err := s.store.ListAgentPresence(); err == nil {
		for _, r := range rows {
			if !want[r.NodeID] {
				continue
			}
			out[r.NodeID] = agentLive{
				online:   true, // freshness is judged by the caller against lastSeen
				version:  r.Version,
				healthy:  r.Healthy,
				lastSeen: time.Unix(r.LastSeenUnix, 0),
			}
		}
	}
	// Overlay the local registry: authoritative + freshest for locally-homed agents.
	for _, id := range nodes {
		if info, online := s.registry.Info(id); online {
			out[id] = agentLive{online: true, version: info.Version, healthy: info.Healthy, lastSeen: info.LastSeen}
		}
	}
	return out
}

func (s *Server) canaryBlockers(canaryNodes []string, version string) []string {
	var blockers []string
	now := time.Now()
	live := s.agentLivenessMap(canaryNodes)
	for _, id := range canaryNodes {
		info, present := live[id]
		switch {
		case !present:
			blockers = append(blockers, fmt.Sprintf("%s: offline", id))
		case info.version != version:
			blockers = append(blockers, fmt.Sprintf("%s: running %q, want %q", id, info.version, version))
		case !info.healthy:
			blockers = append(blockers, fmt.Sprintf("%s: reporting unhealthy", id))
		case now.Sub(info.lastSeen) >= canaryHeartbeatFresh:
			blockers = append(blockers, fmt.Sprintf("%s: heartbeat stale (%s)", id, now.Sub(info.lastSeen).Round(time.Second)))
		}
	}
	return blockers
}

// relayCanaryBlockers is the relay-ring counterpart of canaryBlockers: it gates
// a relay-stable promotion on every canary relay being present in the fleet,
// already reporting the candidate version on its heartbeat, and freshly seen. A
// relay still on the old version (or aged out) blocks the promotion, mirroring
// the agent gate — so a bad relay build cannot reach the whole relay fleet.
func (s *Server) relayCanaryBlockers(canaryRelays []string, version string) []string {
	relays, err := s.store.ListRelays("")
	if err != nil {
		return []string{fmt.Sprintf("relay presence unavailable: %v", err)}
	}
	byID := make(map[string]*RelayRecord, len(relays))
	for _, rl := range relays {
		byID[rl.RelayID] = rl
	}
	var blockers []string
	now := time.Now()
	for _, id := range canaryRelays {
		rec, ok := byID[id]
		switch {
		case !ok:
			blockers = append(blockers, fmt.Sprintf("%s: not present in relay fleet", id))
		case rec.Version != version:
			blockers = append(blockers, fmt.Sprintf("%s: running %q, want %q", id, rec.Version, version))
		case now.Sub(time.Unix(rec.LastSeenUnix, 0)) >= relayStaleTTL:
			blockers = append(blockers, fmt.Sprintf("%s: heartbeat stale (%s)", id,
				now.Sub(time.Unix(rec.LastSeenUnix, 0)).Round(time.Second)))
		}
	}
	return blockers
}

func (a *adminAPIService) GetFleetStatus(ctx context.Context, _ *genezav1.Empty) (*genezav1.FleetStatus, error) {
	s := a.s
	nodes, err := s.nodeSummaries(actorWorkspace(ctx))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list nodes: %v", err)
	}
	stable, err := s.store.StableVersion()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "settings: %v", err)
	}
	canary, err := s.store.CanaryVersion()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "settings: %v", err)
	}
	canaryNodes, err := s.store.CanaryNodes()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "settings: %v", err)
	}
	relayStable, err := s.store.RelayStableVersion()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "settings: %v", err)
	}
	relayCanary, err := s.store.RelayCanaryVersion()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "settings: %v", err)
	}
	relayCanaryNodes, err := s.store.RelayCanaryNodes()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "settings: %v", err)
	}
	return &genezav1.FleetStatus{
		Nodes:              nodes,
		StableVersion:      stable,
		CanaryVersion:      canary,
		CanaryNodes:        canaryNodes,
		RelayStableVersion: relayStable,
		RelayCanaryVersion: relayCanary,
		RelayCanaryNodes:   relayCanaryNodes,
	}, nil
}

func (a *adminAPIService) ReloadPolicy(ctx context.Context, _ *genezav1.Empty) (*genezav1.Empty, error) {
	s := a.s
	// Reload every workspace's policy file (fail closed: previous stays on error).
	if err := s.reloadPolicies(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "policy reload failed (previous policy kept): %v", err)
	}
	if err := s.audit.Append("policy_reload", adminActor(ctx), "", "", map[string]string{
		"file": s.cfg.PolicyFile,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit append: %v", err)
	}
	slog.Info("policy reloaded", "file", s.cfg.PolicyFile)
	// Re-evaluate live sessions immediately so a policy tightening takes effect
	// now rather than on the next continuous-authz tick.
	go s.reauthSweep()
	return &genezav1.Empty{}, nil
}

// RevokeSession force-terminates one live session (admin "kick").
func (a *adminAPIService) RevokeSession(ctx context.Context, req *genezav1.RevokeSessionRequest) (*genezav1.Empty, error) {
	if req.GetSessionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id required")
	}
	reason := req.GetReason()
	if reason == "" {
		reason = "revoked by admin"
	}
	if err := a.s.revokeByID(actorWorkspace(ctx), req.GetSessionId(), "admin "+adminActor(ctx)+": "+reason); err != nil {
		return nil, status.Errorf(codes.NotFound, "revoke session: %v", err)
	}
	return &genezav1.Empty{}, nil
}

// RevokeUser force-terminates all of a user's live sessions.
func (a *adminAPIService) RevokeUser(ctx context.Context, req *genezav1.RevokeUserRequest) (*genezav1.RevokeCountResponse, error) {
	if req.GetUser() == "" {
		return nil, status.Error(codes.InvalidArgument, "user required")
	}
	reason := req.GetReason()
	if reason == "" {
		reason = "user access revoked by admin"
	}
	n, err := a.s.revokeUser(req.GetUser(), "admin "+adminActor(ctx)+": "+reason)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "revoke user: %v", err)
	}
	return &genezav1.RevokeCountResponse{Revoked: int32(n)}, nil
}

type principalRef struct{ provider, subject, username string }

// resolveSuspendTargets maps an admin's (workspace, provider?, subject?,
// username?) request to concrete principals. An explicit subject is used as-is;
// otherwise the principal is resolved from live sessions + member rows + (for
// local) the username itself — so an operator can `suspend bob` without knowing
// bob's stable subject id.
func (a *adminAPIService) resolveSuspendTargets(ws, provider, subject, username string) []principalRef {
	seen := map[string]bool{}
	var out []principalRef
	add := func(p, s, u string) {
		p = normProvider(p)
		if s == "" {
			return
		}
		k := p + "|" + s
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, principalRef{p, s, u})
	}
	if subject != "" {
		p := provider
		if p == "" {
			p = providerLocal
		}
		add(p, subject, username)
		return out
	}
	if sessions, err := a.s.store.ListSessions(ws); err == nil {
		for _, rec := range sessions {
			if rec.User == username && rec.Subject != "" {
				add(rec.Provider, rec.Subject, rec.User)
			}
		}
	}
	if members, err := a.s.store.ListMembers(ws); err == nil {
		for _, m := range members {
			if m.Username == username {
				add(m.Provider, m.Subject, m.Username)
			}
		}
	}
	if provider == "" || normProvider(provider) == providerLocal {
		add(providerLocal, username, username) // local subject == username
	}
	return out
}

func (a *adminAPIService) SuspendPrincipal(ctx context.Context, req *genezav1.SuspendPrincipalRequest) (*genezav1.Empty, error) {
	ws := req.GetWorkspace()
	if ws == "" {
		ws = defaultWorkspace
	}
	targets := a.resolveSuspendTargets(ws, req.GetProvider(), req.GetSubject(), req.GetUsername())
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

func (a *adminAPIService) LiftSuspension(ctx context.Context, req *genezav1.SuspendPrincipalRequest) (*genezav1.Empty, error) {
	ws := req.GetWorkspace()
	if ws == "" {
		ws = defaultWorkspace
	}
	by := adminActor(ctx)
	if req.GetSubject() != "" {
		p := req.GetProvider()
		if p == "" {
			p = providerLocal
		}
		return &genezav1.Empty{}, a.s.liftSuspension(ws, p, req.GetSubject(), by)
	}
	// Resolve from the existing suspension rows by username.
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

func (a *adminAPIService) ListSuspensions(ctx context.Context, _ *genezav1.Empty) (*genezav1.ListSuspensionsResponse, error) {
	rows, err := a.s.store.ListSuspensions("")
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

// SetNodeModules replaces a node's desired agent-module set and pushes it in
// realtime (monitoring on/off, future exporters). Persisted so it survives
// agent reconnects and controller restarts.
func (a *adminAPIService) SetNodeModules(ctx context.Context, req *genezav1.SetNodeModulesRequest) (*genezav1.Empty, error) {
	ws := actorWorkspace(ctx)
	node, err := a.s.store.FindNode(ws, req.GetNode())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "node %q not found", req.GetNode())
	}
	modules := make([]NodeModule, 0, len(req.GetModules()))
	for _, m := range req.GetModules() {
		if m.GetName() == "" {
			return nil, status.Error(codes.InvalidArgument, "module name required")
		}
		modules = append(modules, NodeModule{Name: m.GetName(), Enabled: m.GetEnabled(), Settings: m.GetSettings()})
	}
	if _, err := a.s.store.SetNodeModules(ws, node.ID, modules); err != nil {
		return nil, status.Errorf(codes.Internal, "store node modules: %v", err)
	}
	a.s.pushNodeModules(ws, node.ID)
	if err := a.s.audit.Append("agent_modules_set", adminActor(ctx), node.ID, "", map[string]string{
		"modules": strconv.Itoa(len(modules)),
	}); err != nil {
		slog.Error("audit append failed", "type", "agent_modules_set", "err", err)
	}
	return &genezav1.Empty{}, nil
}

func (a *adminAPIService) GetNodeModules(ctx context.Context, req *genezav1.GetNodeModulesRequest) (*genezav1.NodeModulesResponse, error) {
	ws := actorWorkspace(ctx)
	node, err := a.s.store.FindNode(ws, req.GetNode())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "node %q not found", req.GetNode())
	}
	rec, err := a.s.store.GetNodeModules(ws, node.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load node modules: %v", err)
	}
	return &genezav1.NodeModulesResponse{Modules: moduleConfigProto(rec).Modules}, nil
}

func (a *adminAPIService) QueryAudit(ctx context.Context, req *genezav1.QueryAuditRequest) (*genezav1.QueryAuditResponse, error) {
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 100
	}
	// The AdminAPI is the break-glass cluster-admin plane (auth.go gates it on the
	// reserved "admin" role), so it sees the whole chain across tenants.
	lines, chainOK, err := a.s.audit.Query(req.GetSinceUnix(), req.GetTypeFilter(), "", limit)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "audit query: %v", err)
	}
	records := make([]*genezav1.AuditRecord, 0, len(lines))
	for _, l := range lines {
		records = append(records, &genezav1.AuditRecord{Json: l})
	}
	return &genezav1.QueryAuditResponse{Records: records, ChainOk: chainOK}, nil
}
