package gateway

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

	"osie.cloud/geneza/internal/defaults"
	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
	"osie.cloud/geneza/internal/policy"
	"osie.cloud/geneza/internal/types"
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
		Labels:      req.GetLabels(),
		ExpiresUnix: expires,
		MaxUses:     maxUses,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "store token: %v", err)
	}
	// The token value itself never reaches the audit log.
	if err := s.audit.Append("token_create", adminActor(ctx), "", "", map[string]string{
		"ttl_seconds": strconv.FormatInt(int64(ttl/time.Second), 10),
		"max_uses":    strconv.FormatInt(int64(maxUses), 10),
		"labels":      labelString(req.GetLabels()),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit append: %v", err)
	}
	return &genezav1.CreateJoinTokenResponse{Token: token, ExpiresUnix: expires}, nil
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
// OFFLINE-signed manifest. The gateway verifies the blob against the
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
	if s.artifactPub != nil {
		if err := types.VerifyOne(s.artifactPub, "", defaults.ContextManifest, signed, &m); err != nil {
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
		"signature_verified": strconv.FormatBool(s.artifactPub != nil),
	}); err != nil {
		return status.Errorf(codes.Internal, "audit append: %v", err)
	}
	slog.Info("artifact published", "product", m.Product, "version", m.Version, "sha256", m.SHA256)
	return stream.SendAndClose(&genezav1.PublishArtifactResponse{Version: m.Version, Sha256: m.SHA256})
}

// SetDesiredVersion drives the staged rollout. Promoting a version to stable
// while a canary ring exists requires every canary node to be live, healthy
// (<60s heartbeat) and already running that version — the health gate that
// keeps a bad build from reaching the whole fleet.
func (a *adminAPIService) SetDesiredVersion(ctx context.Context, req *genezav1.SetDesiredVersionRequest) (*genezav1.Empty, error) {
	s := a.s
	ring := req.GetRing()
	version := req.GetVersion()
	switch ring {
	case "canary":
		if nodes := req.GetCanaryNodes(); len(nodes) > 0 {
			if err := s.store.SetCanaryNodes(nodes); err != nil {
				return nil, status.Errorf(codes.Internal, "store canary nodes: %v", err)
			}
		}
		if err := s.store.SetCanaryVersion(version); err != nil {
			return nil, status.Errorf(codes.Internal, "store canary version: %v", err)
		}
	case "stable":
		canaryNodes, err := s.store.CanaryNodes()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "canary nodes: %v", err)
		}
		if len(canaryNodes) > 0 && version != "" {
			if blockers := s.canaryBlockers(canaryNodes, version); len(blockers) > 0 {
				return nil, status.Errorf(codes.FailedPrecondition,
					"stable promotion to %s blocked by canary health gate: %s",
					version, strings.Join(blockers, "; "))
			}
		}
		if err := s.store.SetStableVersion(version); err != nil {
			return nil, status.Errorf(codes.Internal, "store stable version: %v", err)
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "ring must be \"stable\" or \"canary\", got %q", ring)
	}
	if err := s.audit.Append("set_desired_version", adminActor(ctx), "", "", map[string]string{
		"ring": ring, "version": version,
		"canary_nodes": strings.Join(req.GetCanaryNodes(), ","),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit append: %v", err)
	}
	return &genezav1.Empty{}, nil
}

// canaryBlockers returns one human-readable reason per canary node that is
// not yet proven healthy on the candidate version.
func (s *Server) canaryBlockers(canaryNodes []string, version string) []string {
	var blockers []string
	now := time.Now()
	for _, id := range canaryNodes {
		info, online := s.registry.Info(id)
		switch {
		case !online:
			blockers = append(blockers, fmt.Sprintf("%s: offline", id))
		case info.Version != version:
			blockers = append(blockers, fmt.Sprintf("%s: running %q, want %q", id, info.Version, version))
		case !info.Healthy:
			blockers = append(blockers, fmt.Sprintf("%s: reporting unhealthy", id))
		case now.Sub(info.LastSeen) >= canaryHeartbeatFresh:
			blockers = append(blockers, fmt.Sprintf("%s: heartbeat stale (%s)", id, now.Sub(info.LastSeen).Round(time.Second)))
		}
	}
	return blockers
}

func (a *adminAPIService) GetFleetStatus(ctx context.Context, _ *genezav1.Empty) (*genezav1.FleetStatus, error) {
	s := a.s
	nodes, err := s.nodeSummaries()
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
	return &genezav1.FleetStatus{
		Nodes:         nodes,
		StableVersion: stable,
		CanaryVersion: canary,
		CanaryNodes:   canaryNodes,
	}, nil
}

func (a *adminAPIService) ReloadPolicy(ctx context.Context, _ *genezav1.Empty) (*genezav1.Empty, error) {
	s := a.s
	engine, err := policy.Load(s.cfg.PolicyFile)
	if err != nil {
		// Fail closed: the previous policy stays in force.
		return nil, status.Errorf(codes.InvalidArgument, "policy reload failed (previous policy kept): %v", err)
	}
	s.setPolicy(engine)
	if err := s.audit.Append("policy_reload", adminActor(ctx), "", "", map[string]string{
		"file": s.cfg.PolicyFile,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit append: %v", err)
	}
	slog.Info("policy reloaded", "file", s.cfg.PolicyFile)
	return &genezav1.Empty{}, nil
}

func (a *adminAPIService) QueryAudit(ctx context.Context, req *genezav1.QueryAuditRequest) (*genezav1.QueryAuditResponse, error) {
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 100
	}
	lines, chainOK, err := a.s.audit.Query(req.GetSinceUnix(), req.GetTypeFilter(), limit)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "audit query: %v", err)
	}
	records := make([]*genezav1.AuditRecord, 0, len(lines))
	for _, l := range lines {
		records = append(records, &genezav1.AuditRecord{Json: l})
	}
	return &genezav1.QueryAuditResponse{Records: records, ChainOk: chainOK}, nil
}
