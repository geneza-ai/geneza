package controller

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Principal suspension, tenant-console REST.
//
// The console already ENFORCES suspension on every path it owns — console login
// (console_session.go), the web-shell watchdog (console_shell.go) and cert auth
// (console.go) all refuse a suspended principal. It just could not cause a
// suspension, lift one, or even see that one existed: those verbs were
// gRPC/CLI-only. That is the worst possible split, because suspending a principal
// is exactly what an operator reaches for mid-incident, and the console is where
// they already are.

func suspensionJSON(r *SuspensionRecord) map[string]any {
	return map[string]any{
		"provider": r.Provider, "subject": r.Subject, "username": r.Username,
		"reason": r.Reason, "suspendedBy": r.SuspendedBy, "suspendedUnix": r.SuspendedUnix,
	}
}

func (c *consoleAPI) handleListSuspensions(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	rows, err := c.s.store.ListSuspensions(u.Workspace)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list suspensions")
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, rec := range rows {
		out = append(out, suspensionJSON(rec))
	}
	writeJSON(w, map[string]any{"suspensions": out})
}

// handleSuspendPrincipal suspends a principal's authorization in this workspace.
// It mirrors the gRPC verb: resolve the target the same way (so a bare username
// works), default the reason, and record the console user as the actor.
func (c *consoleAPI) handleSuspendPrincipal(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	var req struct {
		Provider string `json:"provider"`
		Subject  string `json:"subject"`
		Username string `json:"username"`
		Reason   string `json:"reason"`
		// RevokeSessions additionally tears down the principal's live sessions.
		// Suspension alone blocks the NEXT authorization; without this an operator
		// who suspends someone mid-incident leaves their current shell running.
		RevokeSessions bool `json:"revokeSessions"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	targets := c.s.resolveSuspendTargets(u.Workspace, req.Provider, req.Subject, strings.TrimSpace(req.Username))
	if len(targets) == 0 {
		writeErr(w, http.StatusNotFound, "could not resolve a principal to suspend; supply a subject")
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "authorization suspended by admin"
	}
	by := "console:" + u.Name
	for _, t := range targets {
		if err := c.s.suspendPrincipal(u.Workspace, t.provider, t.subject, t.username, by, reason); err != nil {
			writeErr(w, http.StatusInternalServerError, "suspend: "+err.Error())
			return
		}
	}
	revoked := 0
	if req.RevokeSessions {
		for _, t := range targets {
			name := t.username
			if name == "" {
				name = t.subject
			}
			n, err := c.s.revokeUserInWorkspace(u.Workspace, name, "suspended by "+by)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "revoke sessions: "+err.Error())
				return
			}
			revoked += n
		}
	}
	_ = c.s.audit.AppendWS(u.Workspace, "principal_suspended", u.Name, "", "", map[string]string{
		"subject": targets[0].subject, "provider": targets[0].provider, "reason": reason,
	})
	writeJSON(w, map[string]any{"ok": true, "suspended": len(targets), "sessionsRevoked": revoked})
}

func (c *consoleAPI) handleLiftSuspension(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	provider := normProvider(r.PathValue("provider"))
	subject := r.PathValue("subject")
	if subject == "" {
		writeErr(w, http.StatusBadRequest, "subject required")
		return
	}
	if err := c.s.liftSuspension(u.Workspace, provider, subject, "console:"+u.Name); err != nil {
		writeErr(w, http.StatusInternalServerError, "lift suspension: "+err.Error())
		return
	}
	_ = c.s.audit.AppendWS(u.Workspace, "principal_unsuspended", u.Name, "", "", map[string]string{
		"subject": subject, "provider": provider,
	})
	writeJSON(w, map[string]any{"ok": true})
}

// handleRevokeUserSessions kills every live session a principal holds in this
// workspace, without touching their authorization — the console counterpart of
// `geneza kick --user`. Use it to end an active session; use suspension to stop
// the next one from being brokered.
func (c *consoleAPI) handleRevokeUserSessions(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	var req struct {
		User   string `json:"user"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	user := strings.TrimSpace(req.User)
	if user == "" {
		writeErr(w, http.StatusBadRequest, "user required")
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "revoked by console:" + u.Name
	}
	n, err := c.s.revokeUserInWorkspace(u.Workspace, user, reason)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "revoke: "+err.Error())
		return
	}
	_ = c.s.audit.AppendWS(u.Workspace, "user_sessions_revoked", u.Name, "", "", map[string]string{
		"user": user, "reason": reason,
	})
	writeJSON(w, map[string]any{"ok": true, "revoked": n})
}
