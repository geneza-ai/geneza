package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// Browser login endpoints. The SPA POSTs credentials to a per-provider
// endpoint; the controller authenticates, resolves the workspace server-side, mints
// an opaque session, and returns it. OIDC keeps browser-PKCE: the SPA obtains an
// id_token from the IdP and POSTs it here ONCE (the controller verifies and
// discards it) — no server-side code exchange, no OAuth client secret. All three
// providers funnel through establishSession so workspace resolution, role
// resolution, the session TTL cap and audit are identical.

// sessionResponse is the uniform body every login endpoint returns. When the
// principal belongs to several workspaces and none was requested, the body
// carries AvailableWorkspaces and NO token (the SPA re-POSTs with a choice).
type sessionResponse struct {
	Token               string   `json:"token,omitempty"`
	ExpiresUnix         int64    `json:"expiresUnix,omitempty"`
	User                string   `json:"user,omitempty"`
	Workspace           string   `json:"workspace,omitempty"`
	Roles               []string `json:"roles,omitempty"`
	Admin               bool     `json:"admin"`
	AvailableWorkspaces []string `json:"availableWorkspaces,omitempty"`
}

// authnResult is the authenticated, pre-workspace-resolution identity.
type authnResult struct {
	provider    string
	source      string
	user        string
	subject     string
	groups      []string
	upstreamExp int64
	ksTokenHash string
}

func (c *consoleAPI) handleSessionLocal(w http.ResponseWriter, r *http.Request) {
	if !c.s.cfg.localLoginEnabled() {
		writeErr(w, http.StatusForbidden, "local login is disabled")
		return
	}
	var req struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		Workspace string `json:"workspace"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	user, groups, err := c.s.identity.authenticateLocal(req.Username, req.Password)
	if err != nil {
		c.auditLoginDenied(req.Username, providerLocal, err.Error())
		writeErr(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	c.establishSession(w, r, authnResult{provider: providerLocal, user: user, subject: user, groups: groups}, req.Workspace)
}

func (c *consoleAPI) handleSessionOIDC(w http.ResponseWriter, r *http.Request) {
	if !c.s.cfg.oidcLoginEnabled() {
		writeErr(w, http.StatusForbidden, "oidc login is disabled")
		return
	}
	var req struct {
		IDToken   string `json:"idToken"`
		Workspace string `json:"workspace"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	id, err := c.verifyConsoleOIDC(r.Context(), req.IDToken)
	if err != nil {
		c.auditLoginDenied("", providerOIDC, err.Error())
		writeErr(w, http.StatusUnauthorized, "invalid token")
		return
	}
	c.establishSession(w, r, authnResult{
		provider: providerOIDC, source: c.s.cfg.OIDC.Issuer,
		user: id.User, subject: id.Subject, groups: id.Groups, upstreamExp: id.Exp,
	}, req.Workspace)
}

func (c *consoleAPI) handleSessionKeystone(w http.ResponseWriter, r *http.Request) {
	if !c.s.cfg.keystoneLoginEnabled() {
		writeErr(w, http.StatusForbidden, "keystone login is disabled")
		return
	}
	var req struct {
		Cloud       string `json:"cloud"`
		Username    string `json:"username"`
		Password    string `json:"password"`
		Domain      string `json:"domain"`
		ProjectID   string `json:"projectId"`
		ProjectName string `json:"projectName"`
		Workspace   string `json:"workspace"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	cl, ok := c.s.cfg.Clouds[req.Cloud]
	if !ok {
		writeErr(w, http.StatusBadRequest, "unknown cloud")
		return
	}
	if !cl.allowPasswordLogin() {
		writeErr(w, http.StatusForbidden, "password login is disabled for this cloud")
		return
	}
	verifier := c.s.clouds[req.Cloud]
	if verifier == nil {
		writeErr(w, http.StatusInternalServerError, "cloud verifier unavailable")
		return
	}
	domain := req.Domain
	if domain == "" {
		domain = cl.defaultDomain()
	}
	caller, projects, err := verifier.PasswordLogin(r.Context(), passwordAuth{
		Username: req.Username, Password: req.Password, DomainName: domain,
		ProjectID: req.ProjectID, ProjectName: req.ProjectName,
	})
	if err != nil {
		c.auditLoginDenied(req.Username, providerKeystone, err.Error())
		writeErr(w, http.StatusUnauthorized, "invalid OpenStack credentials")
		return
	}
	// The user has several projects and chose none: return them for a picker.
	if len(projects) > 0 {
		writeJSON(w, map[string]any{"availableProjects": projects})
		return
	}
	// Access-plane guards: reject service/unscoped/domain tokens.
	if err := validateHumanKeystoneToken(caller, cl); err != nil {
		c.auditLoginDenied(req.Username, providerKeystone, err.Error())
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	join, err := c.s.resolveAccessWorkspace(r.Context(), req.Cloud, cl, caller)
	if err != nil {
		if err == errUnboundProject {
			c.auditLoginDenied(caller.UserName, providerKeystone, "unbound project "+caller.ProjectID)
			writeErr(w, http.StatusForbidden, "your OpenStack project is not bound to a Geneza workspace; ask an operator to bind it")
			return
		}
		writeErr(w, http.StatusInternalServerError, "could not resolve workspace")
		return
	}
	_ = c.s.audit.AppendWS(join.Workspace, "access_join", caller.UserName, "", "", map[string]string{
		"provider": providerKeystone, "cloud": req.Cloud, "project": caller.ProjectID,
		"workspace": join.Workspace, "roles": strings.Join(join.Roles, ","),
		"first_admin": boolStr(join.FirstAdmin), "provisioned": boolStr(join.Provisioned),
	})
	c.establishSession(w, r, authnResult{
		provider: providerKeystone, source: req.Cloud,
		user: caller.UserName, subject: join.Subject, groups: nil,
		upstreamExp: caller.ExpiresAt.Unix(), ksTokenHash: hashToken(caller.TokenID),
	}, join.Workspace)
}

// establishSession is the shared tail of every login: resolve the workspace
// (validated against the principal's candidates — a client-supplied workspace is
// ONLY ever a choice among candidates), resolve roles, mint the session.
func (c *consoleAPI) establishSession(w http.ResponseWriter, r *http.Request, a authnResult, requestedWS string) {
	cands := c.s.workspacesForUserStore(a.provider, a.user, a.subject, a.groups)
	ws, ambiguous, ok := resolveLoginWorkspace(requestedWS, cands)
	if ambiguous {
		writeJSON(w, sessionResponse{User: a.user, AvailableWorkspaces: cands})
		return
	}
	if !ok {
		c.auditLoginDenied(a.user, a.provider, "not a member of any workspace (or requested workspace)")
		writeErr(w, http.StatusForbidden, "you are not a member of an accessible workspace")
		return
	}
	// Authorization gate: a suspended principal is authenticated but not
	// authorized — refuse the session even though their token is valid.
	if c.s.store.IsSuspended(ws, a.provider, a.subject) {
		c.auditLoginDenied(a.user, a.provider, "authorization suspended")
		writeErr(w, http.StatusForbidden, "your authorization has been suspended")
		return
	}
	roles := c.s.rolesForMember(ws, a.provider, a.user, a.subject, a.groups)
	if len(roles) == 0 {
		c.auditLoginDenied(a.user, a.provider, "no roles in workspace "+ws)
		writeErr(w, http.StatusForbidden, "you have no roles in this workspace")
		return
	}
	token, rec, err := c.s.mintAuthSession(sessionInput{
		Provider: a.provider, Source: a.source, User: a.user, Subject: a.subject,
		Workspace: ws, Roles: roles, Groups: a.groups,
		UpstreamExp: a.upstreamExp, KSTokenHash: a.ksTokenHash, UserAgent: r.UserAgent(),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create session")
		return
	}
	_ = c.s.audit.AppendWS(ws, "login_success", a.user, "", "", map[string]string{
		"provider": a.provider, "workspace": ws, "roles": strings.Join(rec.Roles, ","), "path": "console",
	})
	writeJSON(w, sessionResponse{
		Token: token, ExpiresUnix: rec.ExpiresUnix, User: rec.User,
		Workspace: rec.Workspace, Roles: rec.Roles, Admin: rec.Admin,
	})
}

// resolveLoginWorkspace picks the workspace to mint a session for. A requested
// workspace must be one of the candidates (else !ok → 403). With no request:
// exactly one candidate is used; several are ambiguous (the SPA must choose);
// none is a denial.
func resolveLoginWorkspace(requested string, cands []string) (ws string, ambiguous, ok bool) {
	if requested != "" {
		if contains(cands, requested) {
			return requested, false, true
		}
		return "", false, false
	}
	switch len(cands) {
	case 0:
		return "", false, false
	case 1:
		return cands[0], false, true
	default:
		return "", true, false
	}
}

// handleSession returns the current session (SPA bootstrap probe). Replaces /me.
func (c *consoleAPI) handleSession(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	writeJSON(w, map[string]any{
		"user": u.Name, "provider": u.Provider, "workspace": u.Workspace,
		"roles": orEmpty(u.Roles), "groups": orEmpty(u.Groups),
		"admin": u.Admin, "expiresUnix": u.ExpiresUnix,
		// Recording is a per-workspace policy choice; the console hides the
		// Recordings UI when this workspace records nothing.
		"recordingEnabled": c.s.policyFor(u.Workspace).Records(),
	})
}

// handleLogout revokes the caller's own session (server-side delete, so the
// token is dead immediately — not just dropped client-side).
func (c *consoleAPI) handleLogout(w http.ResponseWriter, r *http.Request, _ *consoleUser) {
	if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && tok != "" {
		_ = c.s.store.DeleteAuthSession(hashToken(tok))
	}
	writeJSON(w, map[string]any{"ok": true})
}

// verifyConsoleOIDC verifies a browser-supplied id_token against the CONSOLE
// OIDC client (geneza-console) — a DIFFERENT audience than the CLI's geneza-cli
// client, so it must use the console's own verifier, not identityAuth's.
func (c *consoleAPI) verifyConsoleOIDC(ctx context.Context, idToken string) (oidcIdentity, error) {
	if c.verifier == nil || c.s.cfg.OIDC == nil {
		return oidcIdentity{}, errors.New("oidc login is not configured")
	}
	if idToken == "" {
		return oidcIdentity{}, errors.New("missing oidc id token")
	}
	claims, err := c.verifier.verify(ctx, idToken)
	if err != nil {
		return oidcIdentity{}, err
	}
	return extractOIDCIdentity(c.s.cfg.OIDC, claims)
}

func (c *consoleAPI) auditLoginDenied(user, provider, reason string) {
	_ = c.s.audit.Append("login_denied", user, "", "", map[string]string{
		"provider": provider, "reason": reason, "path": "console",
	})
}
