package controller

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
)

// consoleCanReplayRecordings is the console-side mirror of canReplayRecordings: it
// gates the recording surface (list the index, fetch a recording's ciphertext) on
// the dedicated audit/replay standing — ws-auditor, or higher. Replaying someone's
// shell is privileged and deliberately NOT implied by ordinary operator membership
// (a ws-member is too low here, unlike the vulnerability surface). The reserved
// cluster roles are stripped from every console login, so matching them only serves
// the break-glass cert path the cert mount also exposes.
func consoleCanReplayRecordings(u *consoleUser) bool {
	return contains(u.Roles, roleWSAuditor) || contains(u.Roles, roleWSAdmin) ||
		contains(u.Roles, roleAdmin) || contains(u.Roles, rolePlatformAdmin)
}

// recordingJSON flattens a stored index row into the camelCase wire shape the
// console types expect, mirroring the gRPC RecordingInfo field set. It carries
// metadata only — never the ciphertext, which the controller cannot read anyway.
func recordingJSON(r *RecordingRecord) map[string]any {
	return map[string]any{
		"sessionId":   r.SessionID,
		"nodeId":      r.NodeID,
		"principal":   r.Principal,
		"action":      r.Action,
		"startedUnix": r.StartedUnix,
		"endedUnix":   r.EndedUnix,
		"sizeBytes":   r.SizeBytes,
		"sha256":      r.SHA256,
		"auditKeyId":  r.AuditKeyID,
		"truncated":   r.Truncated,
	}
}

// handleRecordings lists the workspace's recording index rows, newest first. The
// rows are metadata only; the controller never reads a blob to build this list. Even
// listing reveals who-recorded-what (principals, nodes, times), so a successful or
// denied list is itself audited.
func (c *consoleAPI) handleRecordings(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	if !consoleCanReplayRecordings(u) {
		c.auditConsoleRecording(u, "recording_list_denied", "", "", nil)
		writeErr(w, http.StatusForbidden, "audit/replay capability required")
		return
	}
	all, err := c.s.store.ListRecordings(u.Workspace)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list recordings")
		return
	}
	// The store returns ascending by started_unix; walk it in reverse so the newest
	// recordings lead, mirroring the sessions list. An optional ?principal= narrows
	// to one durable subject.
	filter := r.URL.Query().Get("principal")
	rows := make([]map[string]any, 0, len(all))
	for i := len(all) - 1; i >= 0; i-- {
		if filter != "" && all[i].Principal != filter {
			continue
		}
		rows = append(rows, recordingJSON(all[i]))
	}
	pg := pageParams(r)
	total := len(rows)
	lo, hi := pg.bounds(total)
	c.auditConsoleRecording(u, "recording_listed", "", "", map[string]string{
		"returned": strconv.Itoa(hi - lo),
		"total":    strconv.Itoa(total),
	})
	writeJSON(w, pageEnvelope("recordings", rows[lo:hi], total, pg))
}

// handleRecordingBlob streams a recording's opaque ciphertext back to an authorized
// auditor for CLIENT-SIDE decryption. The controller NEVER decrypts — only a holder of
// the workspace audit private key can read the cast, and that key never reaches the
// server. The manifest (sha256/size/node signature) rides response headers so the
// browser can re-verify integrity before it decrypts. The served bytes are verified
// against the index row's sha256 first, so at-rest corruption or tamper surfaces as
// an error rather than a silently bad cast. Every fetch is audited (the auditor is
// audited).
func (c *consoleAPI) handleRecordingBlob(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	sessionID := r.PathValue("id")
	if !consoleCanReplayRecordings(u) {
		c.auditConsoleRecording(u, "recording_fetch_denied", "", sessionID, nil)
		writeErr(w, http.StatusForbidden, "audit/replay capability required")
		return
	}
	if !sessionIDRe.MatchString(sessionID) {
		writeErr(w, http.StatusBadRequest, "invalid session id")
		return
	}
	rec, err := c.s.store.GetRecording(u.Workspace, sessionID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeErr(w, http.StatusNotFound, "no recording for this session")
			return
		}
		writeErr(w, http.StatusInternalServerError, "get recording")
		return
	}

	rc, err := c.s.recordingBlobs.open(rec.BlobRef)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeErr(w, http.StatusNotFound, "recording blob missing")
			return
		}
		writeErr(w, http.StatusInternalServerError, "open recording blob")
		return
	}
	defer rc.Close()

	// Integrity gate: buffer the whole ciphertext, verify its sha256 against the
	// index row, and only then serve — so a single bad byte is never delivered as a
	// cast. Recordings are tiny and the upload cap already bounds the blob, so the
	// buffer is cheap and the cap re-guards it here.
	want, err := hex.DecodeString(rec.SHA256)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "recording has unreadable digest")
		return
	}
	cipher, err := io.ReadAll(io.LimitReader(rc, maxRecordingBytes+1))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "read recording blob")
		return
	}
	if int64(len(cipher)) > maxRecordingBytes {
		writeErr(w, http.StatusInternalServerError, "recording blob exceeds the size cap")
		return
	}
	sum := sha256.Sum256(cipher)
	if !bytes.Equal(sum[:], want) {
		slog.Error("recording blob hash mismatch", "session", sessionID, "blob", rec.BlobRef)
		writeErr(w, http.StatusInternalServerError, "recording failed integrity check")
		return
	}

	// Audit the access at grant time — before any bytes leave — so a fetch that is
	// cancelled mid-stream is still recorded.
	c.auditConsoleRecording(u, "recording_fetched", rec.NodeID, sessionID, map[string]string{
		"principal":    rec.Principal,
		"audit_key_id": rec.AuditKeyID,
		"size_bytes":   strconv.FormatInt(rec.SizeBytes, 10),
		"sha256":       rec.SHA256,
	})

	// The manifest rides headers so the auditor can re-verify integrity (and later
	// the node signature) in the browser before decrypting.
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("X-Geneza-Recording-Sha256", rec.SHA256)
	h.Set("X-Geneza-Recording-Size", strconv.FormatInt(rec.SizeBytes, 10))
	h.Set("X-Geneza-Recording-Node-Sig", base64.StdEncoding.EncodeToString(rec.NodeSig))
	h.Set("X-Geneza-Recording-Audit-Key-Id", rec.AuditKeyID)
	h.Set("X-Geneza-Recording-Started-Unix", strconv.FormatInt(rec.StartedUnix, 10))
	h.Set("X-Geneza-Recording-Ended-Unix", strconv.FormatInt(rec.EndedUnix, 10))
	if rec.Truncated {
		h.Set("X-Geneza-Recording-Truncated", "true")
	}
	h.Set("Content-Length", strconv.Itoa(len(cipher)))
	_, _ = w.Write(cipher)
}

// auditConsoleRecording records a recording access or a denied attempt on the audit
// ledger, prefixing the actor with "console:" as the other console call sites do. A
// sink failure is logged, not fatal.
func (c *consoleAPI) auditConsoleRecording(u *consoleUser, event, node, session string, fields map[string]string) {
	if err := c.s.audit.AppendWS(u.Workspace, event, "console:"+u.Name, node, session, fields); err != nil {
		slog.Error("audit append failed", "type", event, "err", err)
	}
}
