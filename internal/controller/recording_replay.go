package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// recordingChunkBytes bounds one streamed RecordingBlobChunk so a large cast is
// delivered in steady frames rather than one giant message.
const recordingChunkBytes = 64 << 10

// ListRecordings returns the workspace's recording index rows. Replaying a shell
// is privileged, so this is gated by the audit/replay capability — an ordinary
// operator cannot enumerate who-recorded-what. The rows are metadata only (no
// ciphertext); the controller never reads the blobs.
func (u *userAPIService) ListRecordings(ctx context.Context, req *genezav1.ListRecordingsRequest) (*genezav1.ListRecordingsResponse, error) {
	ident, _, ok := identityFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no verified identity")
	}
	if !canReplayRecordings(ident) {
		u.auditRecordingAccess("recording_list_denied", ident.Name, "", "", nil)
		return nil, status.Error(codes.PermissionDenied, "audit/replay capability required")
	}
	all, err := u.s.store.ListRecordings(ident.Workspace)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list recordings: %v", err)
	}
	// Newest first, mirroring the sessions list; the store returns ascending by
	// started_unix, so walk it in reverse.
	filter := req.GetPrincipal()
	rows := make([]*RecordingRecord, 0, len(all))
	for i := len(all) - 1; i >= 0; i-- {
		if filter != "" && all[i].Principal != filter {
			continue
		}
		rows = append(rows, all[i])
	}
	total := len(rows)
	lo, hi := (Page{Limit: int(req.GetLimit()), Offset: int(req.GetOffset())}).bounds(total)
	out := make([]*genezav1.RecordingInfo, 0, hi-lo)
	for _, r := range rows[lo:hi] {
		out = append(out, &genezav1.RecordingInfo{
			SessionId:   r.SessionID,
			NodeId:      r.NodeID,
			Principal:   r.Principal,
			Action:      r.Action,
			StartedUnix: r.StartedUnix,
			EndedUnix:   r.EndedUnix,
			SizeBytes:   r.SizeBytes,
			Sha256:      r.SHA256,
			AuditKeyId:  r.AuditKeyID,
			Truncated:   r.Truncated,
		})
	}
	// Listing the index reveals who-recorded-what (principals, nodes, times), so the
	// access is itself audited even though no ciphertext is served.
	u.auditRecordingAccess("recording_listed", ident.Name, "", "", map[string]string{
		"returned": strconv.Itoa(len(out)),
		"total":    strconv.Itoa(total),
	})
	return &genezav1.ListRecordingsResponse{Recordings: out, Total: int32(total)}, nil
}

// GetRecording streams a recording's opaque ciphertext back to an authorized
// auditor, with its node-signed manifest on the first chunk. The controller NEVER
// decrypts — only a holder of the workspace audit private key can read the cast.
// Before streaming, the served bytes are verified against the index row's sha256,
// so at-rest corruption or tamper surfaces as an error rather than a silently bad
// cast. Every fetch is itself audited (the auditor is audited).
func (u *userAPIService) GetRecording(req *genezav1.GetRecordingRequest, stream genezav1.UserAPI_GetRecordingServer) error {
	ident, _, ok := identityFrom(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "no verified identity")
	}
	if !canReplayRecordings(ident) {
		u.auditRecordingAccess("recording_fetch_denied", ident.Name, "", req.GetSessionId(), nil)
		return status.Error(codes.PermissionDenied, "audit/replay capability required")
	}
	sessionID := req.GetSessionId()
	if !sessionIDRe.MatchString(sessionID) {
		return status.Errorf(codes.InvalidArgument, "invalid session id %q", sessionID)
	}
	rec, err := u.s.store.GetRecording(ident.Workspace, sessionID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return status.Errorf(codes.NotFound, "no recording for session %s", sessionID)
		}
		return status.Errorf(codes.Internal, "get recording: %v", err)
	}

	rc, err := u.s.recordingBlobs.open(rec.BlobRef)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return status.Errorf(codes.NotFound, "recording blob missing for session %s", sessionID)
		}
		return status.Errorf(codes.Internal, "open recording blob: %v", err)
	}
	defer rc.Close()

	// Integrity gate: read the whole ciphertext, verify its sha256 against the index
	// row, and only then stream — so at-rest corruption or tamper surfaces as an
	// error and a single bad byte is never served as a cast. Recordings are tiny
	// (asciicast stores only emitted bytes + timing), and the 512 MiB upload cap
	// already bounds the blob, so buffering is cheap and the cap re-guards it.
	want, err := hex.DecodeString(rec.SHA256)
	if err != nil {
		return status.Errorf(codes.Internal, "recording has unreadable digest")
	}
	cipher, err := io.ReadAll(io.LimitReader(rc, maxRecordingBytes+1))
	if err != nil {
		return status.Errorf(codes.Internal, "read recording blob: %v", err)
	}
	if int64(len(cipher)) > maxRecordingBytes {
		return status.Errorf(codes.Internal, "recording blob exceeds the size cap")
	}
	sum := sha256.Sum256(cipher)
	if !bytes.Equal(sum[:], want) {
		// At-rest corruption or tamper: refuse to serve a bad cast.
		slog.Error("recording blob hash mismatch", "session", sessionID, "blob", rec.BlobRef)
		return status.Errorf(codes.DataLoss, "recording %s failed integrity check", sessionID)
	}

	// Audit the auditor at the point access is granted — before streaming — so a
	// fetch that begins delivering ciphertext is recorded even if the stream is
	// cancelled mid-cast.
	u.auditRecordingAccess("recording_fetched", ident.Name, rec.NodeID, sessionID, map[string]string{
		"principal":    rec.Principal,
		"audit_key_id": rec.AuditKeyID,
		"size_bytes":   strconv.FormatInt(rec.SizeBytes, 10),
		"sha256":       rec.SHA256,
	})

	// Stream the verified ciphertext; the manifest rides the first chunk so the
	// auditor can re-verify integrity (and the node signature) client-side.
	manifest := recordingManifestFor(rec)
	first := true
	for off := 0; off < len(cipher) || first; off += recordingChunkBytes {
		end := off + recordingChunkBytes
		if end > len(cipher) {
			end = len(cipher)
		}
		chunk := &genezav1.RecordingBlobChunk{Data: cipher[off:end], Eof: end >= len(cipher)}
		if first {
			chunk.Manifest = manifest
			first = false
		}
		if err := stream.Send(chunk); err != nil {
			return err
		}
		if end >= len(cipher) {
			break
		}
	}
	return nil
}

// auditRecordingAccess records a recording access or a denied attempt on the audit
// ledger. A sink failure is logged, not fatal, matching the other audit call sites.
func (u *userAPIService) auditRecordingAccess(event, actor, node, session string, fields map[string]string) {
	if err := u.s.audit.Append(event, actor, node, session, fields); err != nil {
		slog.Error("audit append failed", "type", event, "err", err)
	}
}

// recordingManifestFor rebuilds the node-signed manifest from the stored index row
// so the auditor can verify integrity (and later the node signature) client-side.
func recordingManifestFor(rec *RecordingRecord) *genezav1.RecordingManifest {
	sum, _ := hex.DecodeString(rec.SHA256)
	return &genezav1.RecordingManifest{
		Sha256:      sum,
		SizeBytes:   rec.SizeBytes,
		NodeSig:     rec.NodeSig,
		AuditKeyId:  rec.AuditKeyID,
		StartedUnix: rec.StartedUnix,
		EndedUnix:   rec.EndedUnix,
		Principal:   rec.Principal,
		NodeId:      rec.NodeID,
		Action:      rec.Action,
		Truncated:   rec.Truncated,
	}
}
