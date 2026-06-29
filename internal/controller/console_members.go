package controller

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// Per-workspace membership management, tenant-console REST. A workspace-admin
// assigns principals (local/oidc/keystone) to THEIR workspace with per-workspace
// roles and groups; role resolution then uses the row's groups for that tenant.
// Every op is scoped to the session's workspace (never a client-supplied one) and
// refuses reserved cluster roles.

// grantableWSRoles are the roles a workspace-admin may assign. Reserved cluster
// roles (admin/platform-admin) are never here — they are break-glass cert only.
var grantableWSRoles = map[string]bool{
	roleWSAdmin: true, roleWSMember: true, roleWSAuditor: true, "ws-viewer": true,
}

func memberJSON(m *MemberRecord) map[string]any {
	return map[string]any{
		"provider": m.Provider, "username": m.Username, "subject": m.Subject,
		"roles": orEmpty(m.Roles), "groups": orEmpty(m.Groups),
		"addedBy": m.AddedBy, "createdUnix": m.CreatedUnix, "updatedUnix": m.UpdatedUnix,
	}
}

func (c *consoleAPI) handleListMembers(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	ms, err := c.s.store.ListMembers(u.Workspace)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list members")
		return
	}
	out := make([]map[string]any, 0, len(ms))
	for _, m := range ms {
		out = append(out, memberJSON(m))
	}
	writeJSON(w, map[string]any{"members": out})
}

func (c *consoleAPI) handlePutMember(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	var req struct {
		Provider string   `json:"provider"`
		Username string   `json:"username"`
		Subject  string   `json:"subject"`
		Roles    []string `json:"roles"`
		Groups   []string `json:"groups"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	provider := normProvider(req.Provider)
	if provider == "" {
		provider = providerLocal
	}
	username := strings.TrimSpace(req.Username)
	subject := strings.TrimSpace(req.Subject)
	if subject == "" {
		subject = username // default: subject == username, matching local config defaulting
	}
	if username == "" || subject == "" {
		writeErr(w, http.StatusBadRequest, "username and subject are required")
		return
	}
	// A ws-admin may grant workspace roles only — never a reserved cluster role,
	// never an unknown one. (PutMember also strips reserved roles defensively.)
	for _, role := range req.Roles {
		if !grantableWSRoles[role] {
			writeErr(w, http.StatusForbidden, "role "+role+" is not grantable from the console")
			return
		}
	}
	rec := &MemberRecord{
		Provider: provider, Username: username, Subject: subject,
		Roles: req.Roles, Groups: req.Groups, AddedBy: "console:" + u.Name,
	}
	if err := c.s.store.PutMember(u.Workspace, rec); err != nil {
		writeErr(w, http.StatusBadRequest, "store member: "+err.Error())
		return
	}
	if err := c.s.audit.AppendWS(u.Workspace, "member_set", u.Name, "", "",
		map[string]string{"provider": provider, "subject": subject}); err != nil {
		writeErr(w, http.StatusInternalServerError, "audit")
		return
	}
	if m, err := c.s.store.GetMember(u.Workspace, provider, subject); err == nil {
		writeJSON(w, memberJSON(m))
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (c *consoleAPI) handleDeleteMember(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	provider := normProvider(r.PathValue("provider"))
	subject := r.PathValue("subject")
	if err := c.s.store.DeleteMember(u.Workspace, provider, subject); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeErr(w, http.StatusNotFound, "member not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "delete member")
		return
	}
	if err := c.s.audit.AppendWS(u.Workspace, "member_removed", u.Name, "", "",
		map[string]string{"provider": provider, "subject": subject}); err != nil {
		writeErr(w, http.StatusInternalServerError, "audit")
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}
