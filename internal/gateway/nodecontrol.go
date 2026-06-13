package gateway

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"osie.cloud/geneza/internal/ca"
	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

type nodeControlService struct {
	genezav1.UnimplementedNodeControlServer
	s *Server
}

// Session/recording ids are server-generated; anything else is rejected
// before it can reach the filesystem.
var sessionIDRe = regexp.MustCompile(`^s-[0-9a-f]{12}$`)

// maxRecordingBytes caps one uploaded asciicast (disk-exhaustion guard).
const maxRecordingBytes = 512 << 20

// Stream is the persistent agent control channel. The interceptor already
// guarantees a node cert; the hello must additionally name the same node so
// one stolen agent cert cannot impersonate another node's stream.
func (n *nodeControlService) Stream(stream grpc.BidiStreamingServer[genezav1.AgentMsg, genezav1.GatewayMsg]) error {
	s := n.s
	ident, _, ok := identityFrom(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "no verified identity")
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.InvalidArgument, "first message must be hello")
	}
	if hello.GetNodeId() != ident.Name {
		return status.Errorf(codes.PermissionDenied, "hello node_id %q does not match certificate identity %q",
			hello.GetNodeId(), ident.Name)
	}
	if _, err := s.store.GetNode(ident.Workspace, ident.Name); err != nil {
		return status.Errorf(codes.PermissionDenied, "node %s is not enrolled", ident.Name)
	}

	h := s.registry.Register(ident.Name, stream, hello)
	// Record the observed source IP of this control stream: half of the node's
	// direct WG endpoint (the agent reports the port). Dial-out preserved — the
	// gateway only learns where to tell peers to send, it never dials in.
	if p, ok := peer.FromContext(stream.Context()); ok && p.Addr != nil {
		if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
			h.setObservedIP(host)
		}
	}
	defer func() {
		s.registry.Unregister(h)
		if err := s.audit.Append("node_disconnected", "", ident.Name, "", nil); err != nil {
			slog.Error("audit append failed", "type", "node_disconnected", "err", err)
		}
	}()
	if err := s.audit.Append("node_connected", "", ident.Name, "", map[string]string{
		"version": hello.GetVersion(),
		"config":  strconv.FormatInt(hello.GetClusterConfigVersion(), 10),
	}); err != nil {
		return status.Errorf(codes.Internal, "audit append: %v", err)
	}
	slog.Info("agent connected", "node", ident.Name, "version", hello.GetVersion())

	// Desired-state reconcile: agents holding an older cluster config get
	// the current signed one immediately.
	ccVersion, ccBytes := s.clusterConfig()
	if hello.GetClusterConfigVersion() < ccVersion {
		if err := h.send(&genezav1.GatewayMsg{
			Msg: &genezav1.GatewayMsg_ClusterConfig{ClusterConfig: ccBytes},
		}); err != nil {
			return err
		}
	}
	// Push the node's desired agent-module set (monitoring, ...) on connect so a
	// reconnecting agent restarts whatever was enabled before.
	nodeName := ident.Name
	if nr, err := s.store.GetNode(ident.Workspace, ident.Name); err == nil && nr.Name != "" {
		nodeName = nr.Name
	}
	s.pushNodeModules(ident.Workspace, ident.Name)
	// Push the node's desired per-Network WireGuard set so a reconnecting agent
	// re-derives the same overlay interfaces it had before.
	s.pushNodeNetworks(ident.Workspace, ident.Name)

	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			slog.Info("agent stream closed", "node", ident.Name, "err", err)
			return nil
		}
		switch m := msg.GetMsg().(type) {
		case *genezav1.AgentMsg_Heartbeat:
			hb := m.Heartbeat
			h.updateInfo(func(i *AgentInfo) {
				i.LastSeen = time.Now()
				i.Version = hb.GetVersion()
				i.Healthy = hb.GetHealthy()
				i.Active = hb.GetActiveSessions()
				i.Detached = hb.GetDetachedSessions()
			})
		case *genezav1.AgentMsg_SessionEvent:
			n.handleSessionEvent(ident.Workspace, ident.Name, m.SessionEvent)
		case *genezav1.AgentMsg_OfferAck:
			if !h.deliverAck(m.OfferAck) {
				slog.Warn("offer ack with no waiter", "node", ident.Name, "session", m.OfferAck.GetSessionId())
			}
		case *genezav1.AgentMsg_Metrics:
			n.s.ingestNodeMetrics(ident.Name, nodeName, m.Metrics)
		case *genezav1.AgentMsg_NetworkEndpoints:
			changed := false
			for _, e := range m.NetworkEndpoints.GetEndpoints() {
				if h.setWGPort(e.GetVni(), int(e.GetListenPort())) {
					changed = true
				}
			}
			// Only when an endpoint actually changed do we re-derive co-members'
			// configs (so they learn the direct path). The agent re-reports after
			// every reconcile; gating on change avoids a report→repush→reconcile
			// feedback loop that would flood the control stream.
			if changed {
				s.repushAllNetworks(ident.Workspace)
			}
		case *genezav1.AgentMsg_Disco:
			s.handleAgentDisco(ident.Workspace, ident.Name, m.Disco)
		case *genezav1.AgentMsg_Hello:
			// One hello per stream; a second is a protocol violation.
			return status.Error(codes.InvalidArgument, "duplicate hello")
		default:
			slog.Warn("unknown agent message", "node", ident.Name)
		}
	}
}

// handleSessionEvent advances the session state machine and audits. Events
// for unknown sessions are audited but cannot corrupt state.
func (n *nodeControlService) handleSessionEvent(ws, nodeID string, ev *genezav1.SessionEvent) {
	s := n.s
	update := func(fn func(*SessionRecord)) {
		err := s.store.UpdateSession(ws, ev.GetSessionId(), func(r *SessionRecord) {
			if r.NodeID != nodeID {
				return // a node may only move its own sessions
			}
			// The agent emits "established" at tunnel setup (before it has a
			// host session id) and fills it in on "attached"; persist it from
			// whichever event first carries it so reattach can find it.
			if hsid := ev.GetHostSessionId(); hsid != "" {
				r.HostSessionID = hsid
			}
			fn(r)
		})
		if err != nil {
			slog.Warn("session event for unknown session", "node", nodeID,
				"session", ev.GetSessionId(), "event", ev.GetEvent(), "err", err)
		}
	}
	// Terminal is terminal: once a session is Ended or Revoked it must never move
	// back to Active/Detached, so a node cannot resurrect a finished session
	// record — and a revoked session's tunnel-close "ended" must not erase the
	// "revoked" cause (it stays revoked for audit/UI, only timestamps update).
	terminal := func(s string) bool { return s == SessionEnded || s == SessionRevoked }
	switch ev.GetEvent() {
	case "established":
		update(func(r *SessionRecord) {
			if !terminal(r.State) {
				r.State = SessionActive
			}
		})
	case "attached":
		update(func(r *SessionRecord) {
			if !terminal(r.State) {
				r.State = SessionActive
			}
		})
	case "detached":
		update(func(r *SessionRecord) {
			if !terminal(r.State) {
				r.State = SessionDetached
			}
		})
	case "ended":
		update(func(r *SessionRecord) {
			if r.State != SessionRevoked {
				r.State = SessionEnded
			}
			r.EndedUnix = time.Now().Unix()
			r.ExitCode = ev.GetExitCode()
			s.overlayFor(r.WorkspaceID).release(r.OverlayIP)
		})
	case "rejected":
		update(func(r *SessionRecord) {
			if r.State != SessionRevoked {
				r.State = SessionEnded
			}
			r.EndedUnix = time.Now().Unix()
			s.overlayFor(r.WorkspaceID).release(r.OverlayIP)
		})
	case "offered":
		// audit-only
	default:
		slog.Warn("unknown session event", "node", nodeID, "event", ev.GetEvent())
	}
	if err := s.audit.Append("session_event", "", nodeID, ev.GetSessionId(), map[string]string{
		"event":           ev.GetEvent(),
		"detail":          ev.GetDetail(),
		"host_session_id": ev.GetHostSessionId(),
		"exit_code":       strconv.FormatInt(int64(ev.GetExitCode()), 10),
	}); err != nil {
		slog.Error("audit append failed", "type", "session_event", "err", err)
	}
}

func (n *nodeControlService) RenewCert(ctx context.Context, req *genezav1.RenewCertRequest) (*genezav1.RenewCertResponse, error) {
	s := n.s
	ident, _, ok := identityFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no verified identity")
	}
	// Re-validate enrollment: a node whose record was removed (deprovisioned)
	// must not be able to keep minting fresh certs off an old-but-unexpired one.
	if _, err := s.store.GetNode(ident.Workspace, ident.Name); err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "node %s is not enrolled", ident.Name)
	}
	certPEM, err := s.ca.IssueFromCSR(req.GetCsrPem(), ca.Profile{
		Kind:      ca.KindNode,
		Workspace: ident.Workspace,
		Name:      ident.Name,
		TTL:       s.cfg.CertTTL.Node.D(),
	})
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "issue node cert: %v", err)
	}
	if err := s.audit.Append("cert_renew", "", ident.Name, "", nil); err != nil {
		return nil, status.Errorf(codes.Internal, "audit append: %v", err)
	}
	return &genezav1.RenewCertResponse{
		NodeCertPem: certPEM,
		CaRootsPem:  s.ca.RootsPEM,
	}, nil
}

// UploadRecording streams an asciicast into data_dir/recordings/<id>.cast.
// The session must exist and belong to the calling node; the id format check
// is belt-and-braces against path tricks even though ids are server-made.
func (n *nodeControlService) UploadRecording(stream grpc.ClientStreamingServer[genezav1.RecordingChunk, genezav1.UploadAck]) error {
	s := n.s
	ident, _, ok := identityFrom(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "no verified identity")
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	sessionID := first.GetSessionId()
	if !sessionIDRe.MatchString(sessionID) {
		return status.Errorf(codes.InvalidArgument, "invalid session id %q", sessionID)
	}
	rec, err := s.store.GetSession(ident.Workspace, sessionID)
	if err != nil {
		return status.Errorf(codes.NotFound, "unknown session %s", sessionID)
	}
	if rec.NodeID != ident.Name {
		return status.Errorf(codes.PermissionDenied, "session %s does not belong to node %s", sessionID, ident.Name)
	}

	if err := os.MkdirAll(s.cfg.RecordingsDir(), 0o700); err != nil {
		return status.Errorf(codes.Internal, "recordings dir: %v", err)
	}
	path := filepath.Join(s.cfg.RecordingsDir(), sessionID+".cast")
	// A recording is write-once: refuse to overwrite an existing one so a node
	// cannot silently replace the evidence of an earlier session with the same
	// id. Write to a temp file and atomically rename only on a complete upload;
	// a failed/partial upload leaves no final file, so the worker's retry still
	// succeeds exactly once.
	if _, err := os.Stat(path); err == nil {
		return status.Errorf(codes.AlreadyExists, "recording for session %s already stored", sessionID)
	}
	tmp := path + ".uploading"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return status.Errorf(codes.Internal, "open recording: %v", err)
	}
	committed := false
	defer func() {
		f.Close()
		if !committed {
			os.Remove(tmp)
		}
	}()

	var total int64
	chunk := first
	for {
		if id := chunk.GetSessionId(); id != "" && id != sessionID {
			return status.Error(codes.InvalidArgument, "session id changed mid-stream")
		}
		total += int64(len(chunk.GetData()))
		if total > maxRecordingBytes {
			return status.Errorf(codes.ResourceExhausted, "recording exceeds %d bytes", int64(maxRecordingBytes))
		}
		if _, err := f.Write(chunk.GetData()); err != nil {
			return status.Errorf(codes.Internal, "write recording: %v", err)
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
	if err := f.Sync(); err != nil {
		return status.Errorf(codes.Internal, "sync recording: %v", err)
	}
	if err := f.Close(); err != nil {
		return status.Errorf(codes.Internal, "close recording: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return status.Errorf(codes.Internal, "commit recording: %v", err)
	}
	committed = true
	slog.Info("recording stored", "session", sessionID, "node", ident.Name, "bytes", total)
	return stream.SendAndClose(&genezav1.UploadAck{Ok: true})
}
