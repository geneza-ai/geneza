package controller

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"geneza.io/internal/policy"
	"geneza.io/internal/types"
)

// Hosted-UI launch (docs/hosted-ui-launch-spec.md). A cloud provider's own
// tenant portal puts a "Console" button next to each VM: one click, a live
// shell on THAT VM, no Geneza login and no install.
//
// Rule zero: the portal is a presenter, never an authority. The launch call
// carries the signed-in tenant's OWN Keystone token — validated against that
// cloud's Keystone by the same verifier the trusted-dashboard path uses — never
// a provider API key asserting who the user is. So a compromised portal can
// only act for humans whose tokens it already holds, which is authority it
// already had; it never becomes a fleet-wide impersonation oracle.
//
// The second half of the contract is that the scope is pinned SERVER-SIDE at
// mint time (SessionScope, stored on the AuthSession) and is never read back
// from anything the browser sends — so the tenant cannot widen a one-VM launch
// into a workspace console by editing a URL.

// launchCookie is the companion secret for a TOP-LEVEL launch: HttpOnly, so
// script cannot read it, and Strict, so it rides only same-site requests. It is
// never the authenticator on its own — the session token is always a Bearer
// header — it exists solely so the fragment code is not sufficient by itself.
const launchCookie = "geneza_launch"

const (
	// launchInstanceLabel / launchProjectLabel are the TRUSTED enrollment labels:
	// vendordata.go stamps them from Nova's authoritative callback, and the enroll
	// path DROPS any os:-namespaced label an agent asserts (mergeEnrollLabels), so
	// only enrollment evidence can set them. Tenant hints live under os.claim:.
	//
	// That drop is load-bearing, not hygiene: these two keys are the entire match
	// for a hosted-UI launch, so an agent able to set os:instance would receive
	// another VM's shell sessions.
	launchInstanceLabel = "os:instance"
	launchProjectLabel  = "os:project"
)

// launchRequest is the portal's server-to-server mint call. The Keystone token
// rides the BODY over TLS — never a query string, so it cannot reach an access
// log, a Referer header, or a proxy trace.
type launchRequest struct {
	Token      string `json:"token"`
	InstanceID string `json:"instance_id"`
	Action     string `json:"action,omitempty"` // default "shell"
	Embed      bool   `json:"embed,omitempty"`  // launch to be framed by the portal
}

type launchResponse struct {
	LaunchURL   string `json:"launch_url"`
	ExpiresUnix int64  `json:"expires_unix"`
	NodeID      string `json:"node_id"`
	NodeName    string `json:"node_name"`
	Action      string `json:"action"`
	Online      bool   `json:"online"`
}

// handleLaunchMint validates a tenant's Keystone token, resolves the named cloud
// instance to a node they are actually entitled to, and returns a single-use
// launch URL. Every failure mode is fail-closed and says as little as the portal
// needs to render a sensible button state.
func (c *consoleAPI) handleLaunchMint(w http.ResponseWriter, r *http.Request) {
	svcUID := r.PathValue("svc")
	cl, ok := c.s.cfg.Clouds[svcUID]
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown cloud") // routing-only, never auth
		return
	}
	if !cl.Launch.Allow {
		writeErr(w, http.StatusForbidden, "hosted-UI launch is not enabled for this cloud")
		return
	}
	var req launchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request body")
		return
	}
	// Same rule as the trusted dashboard: a credential never rides the URL.
	if r.URL.Query().Has("token") {
		writeErr(w, http.StatusBadRequest, "the keystone token must be POSTed in the body, not the query string")
		return
	}
	if req.Token == "" {
		writeErr(w, http.StatusBadRequest, "missing keystone token")
		return
	}
	if req.InstanceID == "" {
		writeErr(w, http.StatusBadRequest, "missing instance_id")
		return
	}
	action := req.Action
	if action == "" {
		action = types.ActionShell
	}
	if !cl.allowsLaunchAction(action) {
		writeErr(w, http.StatusForbidden, fmt.Sprintf("action %q is not launchable for this cloud", action))
		return
	}
	if req.Embed && !cl.Launch.Embed.Allow {
		writeErr(w, http.StatusForbidden, "embedded launch is not enabled for this cloud")
		return
	}

	verifier := c.s.clouds[svcUID]
	if verifier == nil {
		writeErr(w, http.StatusInternalServerError, "cloud verifier unavailable")
		return
	}
	sess, err := verifier.Validate(r.Context(), req.Token)
	if err != nil {
		c.auditLoginDenied("", providerKeystone, "launch: validate token: "+err.Error())
		writeErr(w, http.StatusUnauthorized, "invalid keystone token")
		return
	}
	caller := sess.Caller()
	// Reject service / non-project-scoped tokens exactly as the other access-plane
	// entrypoints do. The token validated against THIS cloud's keystone, so
	// routing a request to a cloud does not by itself authenticate it.
	if err := validateHumanKeystoneToken(caller, cl); err != nil {
		c.auditLoginDenied(caller.UserName, providerKeystone, "launch: "+err.Error())
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

	node, err := c.s.resolveLaunchNode(join.Workspace, caller.ProjectID, req.InstanceID)
	if err != nil {
		_ = c.s.audit.AppendWS(join.Workspace, "launch_denied", caller.UserName, "", "", map[string]string{
			"cloud": svcUID, "project": caller.ProjectID, "instance": req.InstanceID, "reason": err.Error(),
		})
		writeErr(w, http.StatusNotFound, "no Geneza node for that instance in your project")
		return
	}

	// Mint-time policy dry-run. ADVISORY ONLY: it exists so the portal can grey
	// out a button instead of handing the tenant a URL that dies three seconds
	// later. The authoritative checks stay where they are — the broker at session
	// creation and the AGENT when it honors the session — so a rule, a
	// quarantine, or a suspension landing between mint and redeem still denies.
	decision := c.s.policyFor(join.Workspace).Evaluate(policy.Input{
		User:       caller.UserName,
		Roles:      join.Roles,
		NodeID:     node.ID,
		NodeName:   node.Name,
		NodeLabels: node.Labels,
		Action:     action,
		ClientPath: types.PathWeb,
		Now:        time.Now(),
	})
	if !decision.Allow {
		_ = c.s.audit.AppendWS(join.Workspace, "launch_denied", caller.UserName, node.ID, "", map[string]string{
			"cloud": svcUID, "instance": req.InstanceID, "action": action, "reason": decision.Reason,
		})
		writeErr(w, http.StatusForbidden, decision.Reason)
		return
	}

	code, err := randToken(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	ttl := cl.launchTicketTTL()
	expires := time.Now().Add(ttl)
	// The record holds the RESOLVED identity and scope; the session itself is
	// minted only at redeem. CookieHash is deliberately empty — a launch ticket
	// is cookieless (see HandoffRecord) and is redeemable only through
	// RedeemLaunch, which refuses cookie-bound records.
	rec := &HandoffRecord{
		CodeHash: hashToken(code),
		Session: sessionInput{
			Provider: providerKeystone, Source: svcUID,
			User: caller.UserName, Subject: join.Subject,
			Workspace: join.Workspace, Roles: join.Roles,
			UpstreamExp: caller.ExpiresAt.Unix(), KSTokenHash: hashToken(caller.TokenID),
			MaxTTL: cl.launchSessionTTL(), AbsoluteTTL: cl.launchAbsoluteTTL(),
			Scope: &SessionScope{
				NodeID: node.ID, NodeName: node.Name,
				Actions: []string{action}, Cloud: svcUID,
				Instance: req.InstanceID, Embed: req.Embed,
			},
		},
		ExpiresUnix: expires.Unix(),
	}
	if err := c.s.store.PutHandoff(rec); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	_ = c.s.audit.AppendWS(join.Workspace, "launch_mint", caller.UserName, node.ID, "", map[string]string{
		"cloud": svcUID, "project": caller.ProjectID, "instance": req.InstanceID,
		"action": action, "embed": boolStr(req.Embed), "portal_ip": remoteIP(r),
		"expires_unix": fmt.Sprint(expires.Unix()),
	})

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, launchResponse{
		LaunchURL:   c.launchURL(svcUID, code, req.Embed),
		ExpiresUnix: expires.Unix(),
		NodeID:      node.ID,
		NodeName:    node.Name,
		Action:      action,
		Online:      c.s.nodeOnlineAnywhere(node.ID),
	})
}

// nodeOnlineAnywhere reports whether a node is live on ANY controller, not just
// this one. Under HA an agent homes its control stream to a single controller,
// so the local in-memory registry says "offline" for every node owned by a peer
// — which would make the portal grey out a Console button that works perfectly
// well. It reuses agentLivenessMap (shared presence rows, overlaid with the local
// registry, which is freshest for locally-homed agents) so there is exactly one
// notion of liveness in the controller rather than a second one here.
func (s *Server) nodeOnlineAnywhere(nodeID string) bool {
	info, ok := s.agentLivenessMap([]string{nodeID})[nodeID]
	if !ok {
		return false
	}
	// Shared rows carry only a heartbeat timestamp, so judge freshness here (the
	// same rule the canary gate applies); a locally-homed agent's row is stamped
	// on every heartbeat and passes trivially.
	return time.Since(info.lastSeen) < canaryHeartbeatFresh
}

// launchURL builds the one-click URL, in one of two shapes.
//
// TOP-LEVEL (the default): the URL points at the controller's bind endpoint,
// which burns this code and hands the browser a fresh code in the fragment plus
// a companion HttpOnly cookie — the same double-secret the trusted-dashboard
// handoff uses. Two secrets means a later leak of the browser's URL (history, a
// screenshot) is not enough to replay the launch.
//
// EMBED: straight to the fragment, cookieless. A page framed by the provider's
// portal is a third-party context, where a cookie write is blocked outright by
// Safari's ITP and Chrome's phase-out — so requiring one would not harden the
// flow, it would break it. The compensations are in §7 of the spec: the code
// never leaves the fragment, the TTL is short, the redeem is origin-checked,
// and the session it yields reaches exactly one node.
func (c *consoleAPI) launchURL(svcUID, code string, embed bool) string {
	if embed {
		return c.extURL + "/embed/shell?cloud=" + url.QueryEscape(svcUID) + "#lc=" + code
	}
	return c.extURL + "/launch?cloud=" + url.QueryEscape(svcUID) + "&lt=" + url.QueryEscape(code)
}

// handleLaunchBind is stage one of the top-level flow. It burns the portal's
// code, mints the browser-facing pair (a fresh code + its companion cookie)
// together so they are genuinely two secrets, and 303s to a URL whose only
// credential is in the fragment.
//
// The portal's code does appear in this request's query string, and therefore in
// an access log — but it is single-use and spent by the time the log is written,
// and it yields nothing without completing this redirect (which delivers the
// cookie to whoever completes it). That is the same exposure the trusted-dashboard
// handoff already accepts.
func (c *consoleAPI) handleLaunchBind(w http.ResponseWriter, r *http.Request) {
	svcUID := r.URL.Query().Get("cloud")
	cl, ok := c.s.cfg.Clouds[svcUID]
	if !ok || !cl.Launch.Allow {
		http.Error(w, "unknown cloud", http.StatusNotFound)
		return
	}
	in, err := c.s.store.RedeemLaunchBind(r.URL.Query().Get("lt"), time.Now().Unix())
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
	// The second leg is short: it only has to survive this redirect and the
	// SPA's first paint, not the wait for the tenant to click.
	ttl := 2 * time.Minute
	if err := c.s.store.PutHandoff(&HandoffRecord{
		CodeHash: hashToken(code), CookieHash: hashToken(cookieSecret),
		Session: in, ExpiresUnix: time.Now().Add(ttl).Unix(),
	}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: launchCookie, Value: cookieSecret, Path: "/",
		MaxAge: int(ttl.Seconds()) + 5, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, c.extURL+"/embed/shell?cloud="+url.QueryEscape(svcUID)+"#lc="+code, http.StatusSeeOther)
}

// resolveLaunchNode maps a cloud instance id to a node the caller is entitled to
// reach. BOTH checks must hold and neither implies the other:
//
//  1. the node is in the workspace the caller's project resolved to, and
//  2. the node's trusted os:project label equals the caller's authoritative
//     project id.
//
// A workspace may bind MANY projects, so (1) is strictly weaker than (2):
// without (2) one project's tenant could open a shell on a co-bound project's
// VM. Nodes enrolled outside the OpenStack plane carry no os:instance label and
// are therefore not launchable at all.
func (s *Server) resolveLaunchNode(ws, projectID, instanceID string) (*NodeRecord, error) {
	if projectID == "" || instanceID == "" {
		return nil, fmt.Errorf("empty project or instance")
	}
	nodes, err := s.store.ListNodes(ws)
	if err != nil {
		return nil, err
	}
	for _, n := range nodes {
		if n.Labels[launchInstanceLabel] != instanceID {
			continue
		}
		if n.Labels[launchProjectLabel] != projectID {
			return nil, fmt.Errorf("instance belongs to a different project")
		}
		if !n.Approved {
			return nil, fmt.Errorf("node is not approved")
		}
		if q, qerr := s.store.GetQuarantine(ws, n.ID); qerr == nil && q != nil {
			return nil, fmt.Errorf("node is quarantined")
		}
		return n, nil
	}
	return nil, fmt.Errorf("no node for instance")
}

// handleSessionLaunch swaps a single-use launch code for the SCOPED session. The
// code arrives by POST from the embed page (it lived in the fragment, so this is
// the first time it touches a server) and is burned on any redeem attempt.
func (c *consoleAPI) handleSessionLaunch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil || req.Code == "" {
		writeErr(w, http.StatusBadRequest, "missing launch code")
		return
	}
	// The exchange must come from the console's own origin. A browser sends
	// Origin on every cross-origin POST, so this stops a foreign page from
	// spending a code it somehow observed; a non-browser caller (no Origin) is
	// left to the code's own secrecy, exactly as the WS ticket path is.
	if !c.checkShellOrigin(r) {
		writeErr(w, http.StatusForbidden, "bad origin")
		return
	}
	// The companion cookie for a top-level launch. Absent for an embed launch,
	// where the record carries no cookie leg either — the store decides which
	// rule applies from the RECORD, never from what the caller supplies.
	cookie := ""
	if ck, cerr := r.Cookie(launchCookie); cerr == nil {
		cookie = ck.Value
	}
	in, err := c.s.store.RedeemLaunch(req.Code, cookie, time.Now().Unix())
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid or expired launch code")
		return
	}
	// Burn the one-time cookie regardless of outcome.
	http.SetCookie(w, &http.Cookie{Name: launchCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	token, rec, err := c.s.mintAuthSession(in)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create session")
		return
	}
	_ = c.s.audit.AppendWS(rec.Workspace, "launch_redeem", rec.User, rec.Scope.NodeID, "", map[string]string{
		"cloud": rec.Scope.Cloud, "instance": rec.Scope.Instance,
		"actions": strings.Join(rec.Scope.Actions, ","), "embed": boolStr(rec.Scope.Embed),
		"framed_by": r.Header.Get("Origin"), "user_agent": r.UserAgent(),
	})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{
		"token":       token,
		"expiresUnix": rec.ExpiresUnix,
		"user":        rec.User,
		"workspace":   rec.Workspace,
		"scope": map[string]any{
			"nodeId": rec.Scope.NodeID, "nodeName": rec.Scope.NodeName,
			"actions": orEmpty(rec.Scope.Actions),
		},
	})
}

// handleSessionRenew slides a live launch session's expiry forward. The embed
// UI calls it on a timer while the shell is attached, so an ATTENDED session
// keeps going and an abandoned one still dies at its idle window. It cannot
// extend past the absolute ceiling stamped at mint (which already folds in the
// Keystone token's expiry), and it re-checks revocation and suspension first —
// renewal is a re-authorization, not a rubber stamp.
func (c *consoleAPI) handleSessionRenew(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	if u.Scope == nil {
		writeErr(w, http.StatusBadRequest, "only a launch session renews")
		return
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	window := c.s.cfg.Clouds[u.Scope.Cloud].launchSessionTTL()
	rec, err := c.s.renewSession(hashToken(tok), window)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	writeJSON(w, map[string]any{
		"expiresUnix": rec.ExpiresUnix,
		// The client shows a warning as the ceiling approaches, so an operator
		// is never cut off mid-keystroke without having seen it coming.
		"maxExpiresUnix": rec.MaxExpiresUnix,
	})
}

func remoteIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
