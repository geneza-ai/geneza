package controller

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"
)

// Server-to-server console handoff: a cloud's own portal hands a signed-in
// customer into THEIR workspace console, so they can manage their fleet — enroll
// a node, read audit, open a shell — without a separate Geneza login.
//
// This is the trusted-dashboard capability with the browser taken off the token
// path. Horizon's websso form-POSTs the keystone token from the browser, which
// only works for a portal that already holds that token in the page. A portal
// that keeps it server-side (the usual arrangement) would have to publish it to
// its own DOM to use that flow — turning a server-side secret into an XSS
// target. Here the portal's BACKEND presents the token and gets back a URL whose
// only credential is a single-use code, so the keystone token never reaches the
// browser at all.
//
// Two legs, exactly as the hosted-UI launch does it (and for the same reason):
// the mint stages a cookieless ticket, and redeeming it in the browser is what
// delivers the HttpOnly companion cookie. One leg cannot be replayed without the
// other.
//
// Scope is deliberately the whole workspace, unlike a launch session which is
// pinned to one node: the point is fleet management. The customer gets exactly
// the roles their keystone identity maps to — nothing is widened here that a
// keystone login through the console would not already grant.

// portalConsoleTicketTTL bounds the first leg: the window between the portal
// minting the URL and the customer's browser spending it. It only has to absorb
// a redirect, so it is deliberately short.
const portalConsoleTicketTTL = 2 * time.Minute

type portalConsoleRequest struct {
	Token string `json:"token"`
}

type portalConsoleResponse struct {
	ConsoleURL  string `json:"console_url"`
	ExpiresUnix int64  `json:"expires_unix"`
	Workspace   string `json:"workspace"`
}

// handlePortalConsoleMint is the portal's server-to-server call. It authenticates
// the CUSTOMER by their own keystone token — the portal never asserts an identity,
// because a portal able to say "this request is for user X" would be an
// impersonation oracle.
func (c *consoleAPI) handlePortalConsoleMint(w http.ResponseWriter, r *http.Request) {
	svcUID := r.PathValue("svc")
	cl, ok := c.s.cfg.Clouds[svcUID]
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown cloud") // routing-only, never auth
		return
	}
	if !cl.AllowTrustedDashboard {
		writeErr(w, http.StatusForbidden, "portal console handoff is not enabled for this cloud")
		return
	}
	// Never accept the token from the query string: it would land in an access
	// log, a Referer, and every proxy trace in between.
	if r.URL.Query().Has("token") {
		writeErr(w, http.StatusBadRequest, "the keystone token must be POSTed in the body, not the query string")
		return
	}
	var req portalConsoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request body")
		return
	}
	if req.Token == "" {
		writeErr(w, http.StatusBadRequest, "missing keystone token")
		return
	}

	verifier := c.s.clouds[svcUID]
	if verifier == nil {
		writeErr(w, http.StatusInternalServerError, "cloud verifier unavailable")
		return
	}
	sess, err := verifier.Validate(r.Context(), req.Token)
	if err != nil {
		c.auditLoginDenied("", providerKeystone, "portal_console: validate token: "+err.Error())
		writeErr(w, http.StatusUnauthorized, "invalid keystone token")
		return
	}
	caller := sess.Caller()
	// Same guards as every other access-plane entrypoint: a service token and an
	// unscoped token are both refused, so a captured Nova credential cannot be
	// spent here.
	if err := validateHumanKeystoneToken(caller, cl); err != nil {
		c.auditLoginDenied(caller.UserName, providerKeystone, "portal_console: "+err.Error())
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	join, err := c.s.resolveAccessWorkspace(r.Context(), svcUID, cl, caller)
	if err != nil {
		if err == errUnboundProject {
			writeErr(w, http.StatusForbidden, "your OpenStack project is not bound to a Geneza workspace")
			return
		}
		writeErr(w, http.StatusInternalServerError, "could not resolve workspace")
		return
	}

	code, err := randToken(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	expires := time.Now().Add(portalConsoleTicketTTL)
	// CookieHash empty = a cookieless ticket awaiting its bind leg.
	//
	// The Scope here is a STAGE MARKER, not a grant, and handlePortalConsoleBind
	// strips it before the session is minted. The store uses Scope to tell ticket
	// kinds apart — RedeemLaunchBind refuses a scope-less record precisely so a
	// cookie-bound trusted-dashboard handoff can never be spent cookielessly — so
	// an unbound ticket must carry one to be bindable at all. Marking it keeps that
	// separation intact instead of loosening the redeem path to admit scope-less
	// tickets, which would weaken the guarantee for every other caller.
	//
	// If the strip were ever missed, the result fails CLOSED: allowsNode requires a
	// non-empty NodeID, so a session left carrying this marker authorizes no node.
	if err := c.s.store.PutHandoff(&HandoffRecord{
		CodeHash: hashToken(code),
		Session: sessionInput{
			Provider: providerKeystone, Source: svcUID,
			User: caller.UserName, Subject: join.Subject,
			Workspace: join.Workspace, Roles: join.Roles,
			UpstreamExp: caller.ExpiresAt.Unix(), KSTokenHash: hashToken(caller.TokenID),
			Scope: &SessionScope{Cloud: svcUID},
		},
		ExpiresUnix: expires.Unix(),
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	_ = c.s.audit.AppendWS(join.Workspace, "portal_console_mint", caller.UserName, "", "", map[string]string{
		"cloud": svcUID, "project": caller.ProjectID, "workspace": join.Workspace,
		"first_admin": boolStr(join.FirstAdmin), "provisioned": boolStr(join.Provisioned),
		"portal_ip": remoteIP(r),
	})

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, portalConsoleResponse{
		ConsoleURL:  c.extURL + "/console-bind?cloud=" + url.QueryEscape(svcUID) + "&ct=" + code,
		ExpiresUnix: expires.Unix(),
		Workspace:   join.Workspace,
	})
}

// handlePortalConsoleBind is the browser's leg. It burns the portal's code and
// re-stages the session behind a fresh code plus the HttpOnly companion cookie,
// so from the address bar onward it takes two secrets to replay the handoff and
// neither is sufficient alone.
//
// The portal's code does appear in this request's query string, and so in an
// access log — but it is single-use and already spent by the time the log is
// written, and it yields nothing without completing this redirect, which is what
// delivers the cookie. That is the exposure the trusted-dashboard handoff and the
// launch bind both already accept.
func (c *consoleAPI) handlePortalConsoleBind(w http.ResponseWriter, r *http.Request) {
	svcUID := r.URL.Query().Get("cloud")
	cl, ok := c.s.cfg.Clouds[svcUID]
	if !ok || !cl.AllowTrustedDashboard {
		http.Error(w, "unknown cloud", http.StatusNotFound)
		return
	}
	in, err := c.s.store.RedeemLaunchBind(r.URL.Query().Get("ct"), time.Now().Unix())
	if err != nil {
		http.Error(w, "this console link has expired or was already used", http.StatusUnauthorized)
		return
	}
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
	// Drop the stage marker the mint attached: from here on this is an ordinary
	// workspace session, and anything left in Scope would pin it to a node.
	in.Scope = nil
	// The second leg only has to survive this redirect and the SPA's first
	// paint, not the wait for the customer to click.
	ttl := 2 * time.Minute
	if err := c.s.store.PutHandoff(&HandoffRecord{
		CodeHash: hashToken(code), CookieHash: hashToken(cookieSecret),
		Session: in, ExpiresUnix: time.Now().Add(ttl).Unix(),
	}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: handoffCookie, Value: cookieSecret, Path: "/",
		MaxAge: int(ttl.Seconds()) + 5, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, c.extURL+"/?handoff="+code, http.StatusSeeOther)
}
