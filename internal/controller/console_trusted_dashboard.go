package controller

import (
	"encoding/json"
	"net/http"
	"time"
)

// Trusted-dashboard SSO. Horizon's websso form-POSTs a keystone token
// to /openstack/{svc-uid} after the user signs into OpenStack; the controller
// validates it, resolves the workspace, and hands the browser a clean
// single-use code (the keystone token is NEVER reflected into a URL). Register
// https://<controller-web>/openstack/<svc-uid> as a trusted_dashboard in Keystone.

const handoffCookie = "geneza_handoff"

// handleTrustedDashboard accepts a Horizon websso POST and 303s to the SPA with
// a single-use handoff code.
func (c *consoleAPI) handleTrustedDashboard(w http.ResponseWriter, r *http.Request) {
	svcUID := r.PathValue("svc")
	cl, ok := c.s.cfg.Clouds[svcUID]
	if !ok {
		http.Error(w, "unknown cloud", http.StatusNotFound) // routing-only
		return
	}
	if !cl.AllowTrustedDashboard {
		http.Error(w, "trusted dashboard is not enabled for this cloud", http.StatusForbidden)
		return
	}
	//: NEVER read a token from the query string — only the POST form. A GET,
	// or a token in the query, is refused without parsing/logging it.
	if r.Method != http.MethodPost || r.URL.Query().Has("token") {
		http.Error(w, "POST a keystone token as a form field", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	token := r.PostFormValue("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	verifier := c.s.clouds[svcUID]
	if verifier == nil {
		http.Error(w, "cloud verifier unavailable", http.StatusInternalServerError)
		return
	}
	sess, err := verifier.Validate(r.Context(), token)
	if err != nil {
		c.auditLoginDenied("", providerKeystone, "trusted_dashboard: validate token: "+err.Error())
		http.Error(w, "invalid keystone token", http.StatusUnauthorized)
		return
	}
	caller := sess.Caller()
	// Reject service / non-project-scoped tokens. The token validated against
	// THIS cloud's keystone, so a caller cannot use a token minted for one cloud
	// to authenticate against another (routing the request to a cloud does not
	// by itself authenticate it).
	if err := validateHumanKeystoneToken(caller, cl); err != nil {
		c.auditLoginDenied(caller.UserName, providerKeystone, "trusted_dashboard: "+err.Error())
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	join, err := c.s.resolveAccessWorkspace(r.Context(), svcUID, cl, caller)
	if err != nil {
		if err == errUnboundProject {
			http.Error(w, "your OpenStack project is not bound to a Geneza workspace", http.StatusForbidden)
			return
		}
		http.Error(w, "could not resolve workspace", http.StatusInternalServerError)
		return
	}

	// Stage the resolved (not-yet-minted) session behind a single-use code + a
	// companion HttpOnly cookie (double-secret).
	code, err := randToken(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	cookieSecret, err := randToken(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ttl := c.s.cfg.handoffCodeTTL()
	rec := &HandoffRecord{
		CodeHash:   hashToken(code),
		CookieHash: hashToken(cookieSecret),
		Session: sessionInput{
			Provider: providerKeystone, Source: svcUID,
			User: caller.UserName, Subject: join.Subject,
			Workspace: join.Workspace, Roles: join.Roles,
			UpstreamExp: caller.ExpiresAt.Unix(), KSTokenHash: hashToken(caller.TokenID),
			UserAgent: r.UserAgent(),
		},
		ExpiresUnix: time.Now().Add(ttl).Unix(),
	}
	if err := c.s.store.PutHandoff(rec); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = c.s.audit.AppendWS(join.Workspace, "access_join", caller.UserName, "", "", map[string]string{
		"provider": providerKeystone, "cloud": svcUID, "project": caller.ProjectID,
		"workspace": join.Workspace, "path": "trusted_dashboard",
		"first_admin": boolStr(join.FirstAdmin), "provisioned": boolStr(join.Provisioned),
	})

	http.SetCookie(w, &http.Cookie{
		Name: handoffCookie, Value: cookieSecret, Path: "/",
		MaxAge: int(ttl.Seconds()) + 5, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, c.extURL+"/?handoff="+code, http.StatusSeeOther)
}

// handleSessionHandoff swaps a single-use handoff code (+ its companion cookie)
// for the real session. The keystone token never touched the browser.
func (c *consoleAPI) handleSessionHandoff(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" {
		writeErr(w, http.StatusBadRequest, "missing handoff code")
		return
	}
	ck, err := r.Cookie(handoffCookie)
	if err != nil || ck.Value == "" {
		writeErr(w, http.StatusBadRequest, "missing handoff cookie")
		return
	}
	in, err := c.s.store.RedeemHandoff(req.Code, ck.Value, time.Now().Unix())
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid or expired handoff")
		return
	}
	// Clear the one-time cookie.
	http.SetCookie(w, &http.Cookie{Name: handoffCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})

	token, rec, err := c.s.mintAuthSession(in)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create session")
		return
	}
	writeJSON(w, sessionResponse{
		Token: token, ExpiresUnix: rec.ExpiresUnix, User: rec.User,
		Workspace: rec.Workspace, Roles: rec.Roles, Admin: rec.Admin,
	})
}
