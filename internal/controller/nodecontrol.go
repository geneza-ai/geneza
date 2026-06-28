package controller

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"geneza.io/internal/ca"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
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

// cloneConflictWindow is how recently a displaced control stream must have been
// heartbeating for a new stream from a different source IP to count as a concurrent
// identity clone rather than an ordinary reconnect. Kept to a few heartbeat periods
// so a stale/dead prior stream (a normal reconnect) does not false-trigger.
const cloneConflictWindow = 30 * time.Second

// Stream is the persistent agent control channel. The interceptor already
// guarantees a node cert; the hello must additionally name the same node so
// one stolen agent cert cannot impersonate another node's stream.
func (n *nodeControlService) Stream(stream grpc.BidiStreamingServer[genezav1.AgentMsg, genezav1.ControllerMsg]) error {
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

	h, displaced := s.registry.Register(ident.Name, stream, hello)
	// Claim this node's affinity: record that this controller now owns its control
	// stream and bump the fence epoch so any push aimed at a prior (now superseded)
	// stream is detectable. The durable advertised-service set lets another controller
	// resolve a named service on this agent. Subscribe the node's bus subjects so a
	// push raised elsewhere reaches us.
	epoch, aerr := s.store.ClaimAgentAffinity(ident.Name, s.controllerID, time.Now())
	if aerr != nil {
		s.registry.Unregister(h)
		return status.Errorf(codes.Unavailable, "claim affinity: %v", aerr)
	}
	h.setAffinityEpoch(epoch)
	_ = s.store.PutAdvertisedServices(ident.Workspace, ident.Name, epoch, servicesFromHello(ident.Name, hello.GetServices()))
	// Persist the agent's reported home region so the broker can pick its sessions'
	// relay candidates; refresh it on reconnect when it changed.
	if hr := canonicalRegion(hello.GetHomeRegion()); hr != "" {
		if nr, err := s.store.GetNode(ident.Workspace, ident.Name); err == nil && nr.Region != hr {
			nr.Region = hr
			_ = s.store.PutNode(ident.Workspace, nr)
		}
	}
	s.router.OnAgentClaimed(ident.Name, epoch)
	// Record the observed source IP of this control stream: half of the node's
	// direct WG endpoint (the agent reports the port). Dial-out preserved — the
	// controller only learns where to tell peers to send, it never dials in. When the
	// agent homes its control stream through a relay this observed IP is the relay's,
	// not the agent's; that only mis-hints the non-default kernel-WG direct path
	// (the default userspace ICE plane gathers its own srflx via STUN and ignores
	// it), and relay homing implies a multi-region fleet where kernel-WG's same-L2
	// assumption does not hold — so it is a documented tension, not a regression.
	if p, ok := peer.FromContext(stream.Context()); ok && p.Addr != nil {
		if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
			h.setObservedIP(host)
			// Identity-clone detection: if this stream displaced one that was STILL
			// actively heartbeating from a DIFFERENT source IP, two hosts are presenting
			// the same node identity at once — quarantine the node (both endpoints lose
			// the session + data plane; the control stream stays up for investigation).
			// HONEST LIMITS: a sequential clone (attacker connects only after the original
			// drops) shows no concurrency and is not caught here; on a multi-relay HA
			// fleet a legitimate control-stream re-home through a different relay can
			// change the observed IP — so the window is kept tight (an actively-beating
			// prior) and an admin can re-approve a false positive.
			if displaced != nil && displaced != h {
				pip, lastSeen := displaced.cloneSnapshot()
				if pip != "" && pip != host && time.Since(lastSeen) < cloneConflictWindow {
					if qerr := s.quarantineNode(ident.Workspace, ident.Name, "identity_clone", "system", map[string]string{
						"observed_ip": host, "conflict_ip": pip,
					}); qerr != nil {
						slog.Error("quarantine on identity clone failed", "node", ident.Name, "err", qerr)
					}
				}
			}
		}
	}
	defer func() {
		s.registry.Unregister(h)
		// Release the directory row, advertised services, and bus subscriptions all
		// fenced by THIS connection's epoch, so a stale teardown after a newer
		// reconnect to this controller is a no-op and never strands the live connection.
		ep := h.affinityEpoch()
		s.router.OnAgentReleased(ident.Name, ep)
		if ep != 0 {
			_ = s.store.ReleaseAgentAffinity(ident.Name, s.controllerID, ep)
			_ = s.store.ClearAdvertisedServices(ident.Workspace, ident.Name, ep)
		}
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
	// the current signed one immediately. In split mode the push carries the legacy
	// fallback AND the trust-anchor + routine-map pair (FleetState); in legacy mode it
	// is the bare cluster_config arm, byte-for-byte as before.
	ccVersion, _ := s.clusterConfig()
	if hello.GetClusterConfigVersion() < ccVersion {
		if err := h.send(s.fleetControllerMsg()); err != nil {
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
	// Push the node's managed-domain certificates (sealed to its key) so it can
	// serve TLS for its workspace's reserved names. Inert if the feature is off.
	s.pushNodeCerts(ident.Workspace, ident.Name)
	// Push the node's funnel-serve set so it (re)registers its public funnels with
	// the relay pool. Inert if the feature is off or the node hosts no funnels.
	s.pushNodeFunnels(ident.Workspace, ident.Name)
	// Re-push any session teardown that was decided while this node was offline.
	// The node's session host outlives the agent's control stream, so a returning
	// agent may still be holding a PTY the controller already revoked — deliver the
	// owed revoke now so it actually gets cut.
	s.redeliverPendingRevokes(ident.Name)

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
				if ih := hb.GetInventoryHash(); len(ih) > 0 {
					i.InventoryHash = hex.EncodeToString(ih)
				}
			})
			// Mirror the heartbeat into shared presence so a rollout controller on
			// any controller can evaluate this agent's wave health (the in-memory
			// registry only holds agents homed to THIS controller). Best-effort: a
			// store hiccup must not drop the control stream.
			if err := n.s.store.PutAgentPresence(&AgentPresenceRecord{
				NodeID:       ident.Name,
				Version:      hb.GetVersion(),
				Healthy:      hb.GetHealthy(),
				Active:       hb.GetActiveSessions(),
				Detached:     hb.GetDetachedSessions(),
				LastSeenUnix: time.Now().Unix(),
			}); err != nil {
				slog.Debug("agent presence upsert failed", "node", ident.Name, "err", err)
			}
			// Drift detection: the agent self-measures its own running binary every
			// heartbeat; the controller renders the verdict and quarantines on tamper.
			if bh := hb.GetBinaryHash(); len(bh) > 0 {
				s.evaluateBinaryDrift(ident.Workspace, ident.Name, bh)
			}
		case *genezav1.AgentMsg_SessionEvent:
			n.handleSessionEvent(ident.Workspace, ident.Name, m.SessionEvent)
		case *genezav1.AgentMsg_OfferAck:
			if !h.deliverAck(m.OfferAck) {
				slog.Warn("offer ack with no waiter", "node", ident.Name, "session", m.OfferAck.GetSessionId())
			}
		case *genezav1.AgentMsg_Metrics:
			n.s.ingestNodeMetrics(ident.Workspace, ident.Name, nodeName, m.Metrics)
		case *genezav1.AgentMsg_Inventory:
			// Bind the report to the AUTHENTICATED (workspace, node) of this stream,
			// exactly like the recording upload — never the node-supplied node_id — then
			// store the SBOM, re-index its components, and re-match. Errors are logged,
			// not fatal: a bad report must not drop the control stream.
			if _, err := n.s.ingestInventoryReport(stream.Context(), ident.Workspace, ident.Name, m.Inventory); err != nil {
				// A delta whose base we no longer hold: ask the node for a full SBOM so
				// both ends re-converge. Other errors are corruption/policy rejections.
				if errors.Is(err, errInventoryNeedFull) {
					if cerr := n.s.registry.SendInventoryControl(ident.Name, true); cerr != nil {
						slog.Debug("inventory full-resend request not delivered", "node", ident.Name, "err", cerr)
					}
				} else {
					slog.Warn("inventory report rejected", "node", ident.Name, "err", err)
				}
			}
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
		s.sessionSignals.unregister(ev.GetSessionId()) // free any session p2p entry
	case "rejected":
		update(func(r *SessionRecord) {
			if r.State != SessionRevoked {
				r.State = SessionEnded
			}
			r.EndedUnix = time.Now().Unix()
			s.overlayFor(r.WorkspaceID).release(r.OverlayIP)
		})
		s.sessionSignals.unregister(ev.GetSessionId()) // free any session p2p entry
	case "revoked":
		// The agent acked a teardown (it killed the host session, if there was one).
		// Mark the revoke delivered so the sweep stops re-pushing it, then forget the
		// epoch (no further re-push is possible once confirmed).
		s.confirmRevokeDelivered(ws, ev.GetSessionId(), nodeID)
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
		// First-class audit of the transport class + authz epoch, recorded off the
		// data path so the ledger is authoritative even when the relay saw nothing.
		"path_class": ev.GetPathClass(),
		"epoch":      strconv.FormatInt(ev.GetEpoch(), 10),
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

// FetchClusterConfig serves the current signed cluster map to an enrolled node
// over a cheap unary call, so an agent can refresh its fleet view (controllers,
// relays, trust keys) without standing up the persistent Stream. The map is
// signed public fleet data; the node-cert gate plus the enrollment re-check
// (matching RenewCert) keep a deprovisioned node from continuing to pull it. An
// agent already holding the current version gets an empty reply.
func (n *nodeControlService) FetchClusterConfig(ctx context.Context, req *genezav1.MapRequest) (*genezav1.MapResponse, error) {
	s := n.s
	ident, _, ok := identityFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no verified identity")
	}
	if _, err := s.store.GetNode(ident.Workspace, ident.Name); err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "node %s is not enrolled", ident.Name)
	}
	ver, legacy, anchors, routineMap := s.fleetWire()
	if req.GetHaveVersion() >= ver {
		return &genezav1.MapResponse{}, nil // caller is already current
	}
	// In split mode carry the split pair alongside the legacy fallback; in legacy mode
	// only cluster_config travels, byte-for-byte as before.
	return &genezav1.MapResponse{ClusterConfig: legacy, TrustAnchors: anchors, RoutineMap: routineMap}, nil
}

// UploadRecording stores a node's session recording as opaque ciphertext plus an
// integrity-checked index row. The bytes are age-encrypted at the agent to a
// workspace audit key the controller does not hold, so the controller is a blind durable
// store: it verifies the streamed bytes against the node-signed manifest (sha256
// + size) and the node's signature against the cert authenticating the stream,
// then commits — it never decrypts. The session must exist and belong to the
// calling node; the id format check is belt-and-braces against path tricks even
// though ids are server-made. Write-once and the 512 MiB cap are preserved.
func (n *nodeControlService) UploadRecording(stream grpc.ClientStreamingServer[genezav1.RecordingChunk, genezav1.UploadAck]) error {
	s := n.s
	ident, cert, ok := identityFrom(stream.Context())
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
	man := first.GetManifest()
	if man == nil {
		return status.Error(codes.InvalidArgument, "first chunk must carry the recording manifest")
	}

	// The controller can't tell plaintext from sealed at mint time, so the ref is the
	// neutral ".cast" (the manifest's audit_key_id distinguishes the two).
	ref := s.recordingBlobs.newRef(sessionID + ".cast")
	bw, err := s.recordingBlobs.create(ref)
	if err != nil {
		if errors.Is(err, errBlobExists) {
			return status.Errorf(codes.AlreadyExists, "recording for session %s already stored", sessionID)
		}
		return status.Errorf(codes.Internal, "open recording: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			bw.Abort()
		}
	}()

	hasher := sha256.New()
	var total int64
	chunk := first
	for {
		if id := chunk.GetSessionId(); id != "" && id != sessionID {
			return status.Error(codes.InvalidArgument, "session id changed mid-stream")
		}
		data := chunk.GetData()
		total += int64(len(data))
		if total > maxRecordingBytes {
			return status.Errorf(codes.ResourceExhausted, "recording exceeds %d bytes", int64(maxRecordingBytes))
		}
		if _, err := bw.Write(data); err != nil {
			return status.Errorf(codes.Internal, "write recording: %v", err)
		}
		hasher.Write(data)
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

	// Integrity: the streamed bytes must match the manifest's hash and size, and the
	// manifest must be signed by the key in the cert that authenticated this stream
	// (so a node attests only its own recordings, non-transferably bound to the cast).
	gotSum := hasher.Sum(nil)
	if !bytes.Equal(gotSum, man.GetSha256()) {
		return status.Error(codes.InvalidArgument, "recording hash does not match manifest")
	}
	if man.GetSizeBytes() != total {
		return status.Error(codes.InvalidArgument, "recording size does not match manifest")
	}
	sha256Hex := hex.EncodeToString(gotSum)
	if err := verifyRecordingSig(cert, sessionID, sha256Hex, total, man); err != nil {
		return status.Errorf(codes.PermissionDenied, "verify recording signature: %v", err)
	}
	if err := bw.Commit(); err != nil {
		if errors.Is(err, errBlobExists) {
			return status.Errorf(codes.AlreadyExists, "recording for session %s already stored", sessionID)
		}
		return status.Errorf(codes.Internal, "%v", err)
	}
	committed = true

	// Index row: the durable principal comes from the session record (authoritative),
	// not the agent-supplied manifest. node_id is the authenticated identity.
	principal := man.GetPrincipal()
	if rec.Subject != "" {
		principal = recordingPrincipal(rec.Provider, rec.Subject)
	}
	// The audit key id is set authoritatively from the workspace's configured audit
	// recipient SET (the signed cluster config), NOT from the node-supplied manifest:
	// a compromised node must not be able to mislabel which key decrypts its blob and
	// so point an auditor at the wrong (or an attacker-controlled) key. The agent
	// seals to this same set; the manifest's own audit_key_id is advisory.
	auditKeyID := types.AuditKeyID(s.auditRecipients())
	if perr := s.store.PutRecording(ident.Workspace, &RecordingRecord{
		SessionID:   sessionID,
		NodeID:      ident.Name,
		Principal:   principal,
		Action:      rec.Action,
		StartedUnix: man.GetStartedUnix(),
		EndedUnix:   man.GetEndedUnix(),
		SizeBytes:   total,
		SHA256:      sha256Hex,
		NodeSig:     man.GetNodeSig(),
		AuditKeyID:  auditKeyID,
		BlobRef:     ref,
		Truncated:   man.GetTruncated(),
		StoredUnix:  time.Now().Unix(),
	}); perr != nil {
		// The blob is committed; a failed index write must not be acked, so the
		// worker retries — the write-once guard then makes the retry idempotent.
		return status.Errorf(codes.Internal, "index recording: %v", perr)
	}
	// Flip the badge so the sessions list shows "recorded" without a join.
	if uerr := s.store.UpdateSession(ident.Workspace, sessionID, func(r *SessionRecord) {
		r.Recorded = true
	}); uerr != nil {
		slog.Warn("mark session recorded", "session", sessionID, "err", uerr)
	}
	slog.Info("recording stored", "session", sessionID, "node", ident.Name, "bytes", total)
	return stream.SendAndClose(&genezav1.UploadAck{Ok: true})
}

// verifyRecordingSig checks the node's ECDSA signature over the manifest digest
// against the public key of the cert that authenticated the upload stream, so the
// attestation is bound to the node identity and to this exact cast.
func verifyRecordingSig(cert *x509.Certificate, sessionID, sha256Hex string, size int64, man *genezav1.RecordingManifest) error {
	if cert == nil {
		return errors.New("no node certificate")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("node certificate key is not ecdsa")
	}
	digest := types.RecordingManifestDigest(sessionID, sha256Hex, size, man.GetEndedUnix())
	if !ecdsa.VerifyASN1(pub, digest, man.GetNodeSig()) {
		return errors.New("signature does not verify")
	}
	return nil
}

// auditKeyIDFor derives the stable id for a single workspace audit recipient,
// the one-key case of the recipient-set id. The id labels which key decrypts a
// recording (so an auditor can tell, and a rotation leaves old rows pointing at
// the retired key) without copying the whole recipient into every row.
func auditKeyIDFor(recipient string) string {
	if recipient == "" {
		return types.AuditKeyID(nil)
	}
	return types.AuditKeyID([]string{recipient})
}

// recordingPrincipal joins the durable provider/subject into the index principal
// (the stable suspension-style key); an empty subject is left unkeyable.
func recordingPrincipal(provider, subject string) string {
	if subject == "" {
		return ""
	}
	if provider == "" {
		return subject
	}
	return provider + ":" + subject
}
