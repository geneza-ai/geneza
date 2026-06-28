package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"geneza.io/internal/ca"
	"geneza.io/internal/version"
)

// clusterConsoleAPI is the cluster-operator (super-admin) read plane. It runs on
// its OWN mTLS listener and serves cross-workspace, read-only fleet views under
// /clusterconsole/v1. Unlike the tenant console (workspace-scoped sessions) and the
// desktop cert mount (any user cert, workspace-scoped), this surface authorizes only
// two principals: the break-glass cluster admin cert, or — when no cert is presented —
// an OIDC browser login whose token carries the configured cluster-admin group. A
// tenant ws-admin / ws-member, a tenant session, or any non-admin is rejected on every
// route, and the two session namespaces are kept disjoint (a tenant session can never
// authenticate here, nor a cluster session there).
type clusterConsoleAPI struct {
	s        *Server
	static   string
	verifier *oidcVerifier // nil unless cluster_console.oidc is configured
	clientID string        // cluster console's OIDC audience
	issuer   string        // resolved issuer (own override or inherited)
	extURL   string        // public origin (forms the OIDC redirect_uri the SPA uses)
}

func (s *Server) newClusterConsoleAPI() *clusterConsoleAPI {
	c := &clusterConsoleAPI{
		s:      s,
		static: s.cfg.ClusterConsole.StaticDir,
		extURL: strings.TrimRight(s.cfg.ClusterConsole.ExternalURL, "/"),
	}
	// OIDC is optional (validated at config load): build the verifier only when a
	// cluster_console.oidc block resolves to a usable client_id + issuer. The cluster
	// console uses its OWN client_id/audience, distinct from the tenant console's.
	if s.cfg.clusterConsoleOIDCEnabled() {
		c.clientID = s.cfg.ClusterConsole.OIDC.ClientID
		c.issuer = s.cfg.clusterConsoleOIDCIssuer()
		c.verifier = newOIDCVerifier(c.issuer, c.clientID)
		// Warm discovery + JWKS so the first login after (re)start doesn't pay the
		// cold-fetch latency.
		go c.verifier.Warm(context.Background())
	}
	return c
}

func (c *clusterConsoleAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /clusterconsole/v1/topology/controllers", c.clusterAuth(c.handleControllers))
	mux.Handle("GET /clusterconsole/v1/topology/relays", c.clusterAuth(c.handleRelays))
	mux.Handle("GET /clusterconsole/v1/agents", c.clusterAuth(c.handleAgents))
	mux.Handle("GET /clusterconsole/v1/agents/risk", c.clusterAuth(c.handleAgentsRisk))
	mux.Handle("GET /clusterconsole/v1/workspaces", c.clusterAuth(c.handleWorkspaces))
	// Relay self-update rollout: read the current relay ring and drive it (canary or
	// stable). Gated by the same cluster authority as the rest of /clusterconsole/v1.
	mux.Handle("GET /clusterconsole/v1/relays/updates/desired", c.clusterAuth(c.handleRelayUpdateDesired))
	mux.Handle("POST /clusterconsole/v1/relays/updates/rollout", c.clusterAuth(c.handleRelayUpdateRollout))
	// Auth surface, namespaced apart from the API and the SPA routes so they never
	// collide. /clusterconsole/auth/config is the anonymous SPA bootstrap (it
	// advertises the OIDC client so the login screen can render); the others mint and
	// tear down the cluster session.
	mux.HandleFunc("GET /clusterconsole/auth/config", c.handleAuthConfig)
	mux.HandleFunc("POST /clusterconsole/auth/oidc", c.handleSessionOIDC)
	mux.HandleFunc("GET /clusterconsole/v1/session", c.handleSession)
	mux.HandleFunc("DELETE /clusterconsole/v1/session", c.handleLogout)
	// The built operator SPA is served at / when a static dir is configured. Unlike
	// the API, the shell is reachable WITHOUT a cert (a browser presents none) so the
	// SPA itself can drive the OIDC login; it then calls the API with the bearer. A
	// break-glass cert, when presented, still authenticates the API directly.
	if c.static != "" {
		mux.HandleFunc("/", c.serveSPA)
	}
	return secHeaders(mux)
}

// serveSPA serves the built operator SPA, falling back to index.html for client
// routes (any non-API/non-auth path that does not map to a file on disk).
func (c *clusterConsoleAPI) serveSPA(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/clusterconsole/") {
		http.NotFound(w, r)
		return
	}
	clean := filepath.Clean(r.URL.Path)
	p := filepath.Join(c.static, clean)
	// Guard against path traversal escaping the static dir.
	if !strings.HasPrefix(p, filepath.Clean(c.static)) {
		http.NotFound(w, r)
		return
	}
	if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
		http.ServeFile(w, r, p)
		return
	}
	http.ServeFile(w, r, filepath.Join(c.static, "index.html"))
}

// clusterAdminFromCert returns the verified break-glass cluster admin identity, or
// nil if the request carries no usable cert or the cert is not a cluster admin. It
// chain-verifies locally (VerifiedChains, not the bare PeerCertificates) exactly
// as the gRPC peer extractor and the desktop cert mount do, then requires the
// break-glass admin role AND that the cert is neither revoked nor suspended.
func (c *clusterConsoleAPI) clusterAdminFromCert(r *http.Request) *ca.Identity {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil
	}
	leaf := r.TLS.VerifiedChains[0][0]
	id, err := ca.PeerIdentity(leaf)
	if err != nil || id.Kind != ca.KindUser {
		return nil
	}
	// The break-glass cluster role is the only thing that authorizes this surface; a
	// ws-admin / ws-member / any non-admin cert never passes (reservedRoles guarantees
	// the role is unreachable from any login path, so this is genuinely cert-only).
	if !hasRole(id, roleAdmin) {
		return nil
	}
	serial := serialHex(leaf)
	if c.s.deny.certRevoked(serial, func() (bool, error) { return c.s.store.IsCertRevokedE(serial) }) {
		return nil
	}
	key := principalKey(id.Workspace, id.Provider, id.Subject)
	if c.s.deny.suspended(key, func() (bool, error) {
		return c.s.store.IsSuspendedE(id.Workspace, id.Provider, id.Subject)
	}) {
		return nil
	}
	return id
}

// clusterAuth gates every /clusterconsole/v1 API route on cluster-admin authority,
// in this precedence: a verified break-glass admin cert wins (the existing path);
// otherwise a valid cluster session (an OIDC login that carried the required group)
// is required. Neither → 403. The session is checked ONLY when no admin cert is
// present, so the cert path stays byte-for-byte and a session can never widen it.
func (c *clusterConsoleAPI) clusterAuth(fn func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.clusterAdminFromCert(r) != nil {
			fn(w, r)
			return
		}
		if _, err := c.clusterSessionFromRequest(r); err == nil {
			fn(w, r)
			return
		}
		writeErr(w, http.StatusForbidden, "cluster admin certificate or session required")
	})
}

// clusterSessionFromRequest resolves a cluster session from the Authorization bearer,
// or an error if none is present/valid. A cluster session only ever exists for a
// principal who passed the required-group gate at login, so its mere existence is the
// authorization — there is no per-request role re-check beyond liveness.
func (c *clusterConsoleAPI) clusterSessionFromRequest(r *http.Request) (*AuthSession, error) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		return nil, errors.New("missing bearer token")
	}
	return c.s.clusterSessionByToken(tok)
}

// ---- auth (OIDC login) ----

// handleAuthConfig is the anonymous SPA bootstrap: it advertises whether OIDC login
// is available and, if so, the client/issuer/redirect the SPA needs to run the
// Authorization Code + PKCE flow. It carries no secrets. The break-glass cert path
// needs nothing from here (the cert authenticates the API directly).
func (c *clusterConsoleAPI) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"clusterName": c.s.cfg.ClusterName,
		"oidc":        nil,
	}
	if c.verifier != nil {
		redirect := c.extURL + "/"
		if c.extURL == "" {
			// No external_url configured: the SPA falls back to its own origin.
			redirect = ""
		}
		out["oidc"] = map[string]string{
			"issuer":      c.issuer,
			"clientId":    c.clientID,
			"redirectUri": redirect,
		}
	}
	writeJSON(w, out)
}

// handleSessionOIDC is the cluster-console login token-exchange: the SPA completes
// Authorization Code + PKCE against the IdP itself, then POSTs the resulting id_token
// here ONCE. The controller verifies it against the CLUSTER console's audience, requires
// the configured cluster-admin group, and on success mints a cluster session. The
// id_token is discarded after verification (no server-side code exchange, no secret).
func (c *clusterConsoleAPI) handleSessionOIDC(w http.ResponseWriter, r *http.Request) {
	if c.verifier == nil {
		writeErr(w, http.StatusForbidden, "oidc login is not configured")
		return
	}
	var req struct {
		IDToken string `json:"idToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	id, err := c.verifyClusterOIDC(r.Context(), req.IDToken)
	if err != nil {
		c.auditLoginDenied("", err.Error())
		writeErr(w, http.StatusUnauthorized, "invalid token")
		return
	}
	// The cluster-admin gate: a valid token WITHOUT the required group is rejected,
	// 403 — this is what separates a cluster operator from any other authenticated user.
	want := c.s.cfg.ClusterConsole.requiredGroup()
	if !contains(id.Groups, want) {
		c.auditLoginDenied(id.User, "missing required group "+want)
		writeErr(w, http.StatusForbidden, "your account is not a member of the cluster-admin group")
		return
	}
	token, rec, err := c.s.mintClusterSession(clusterSessionInput{
		Source: c.issuer, User: id.User, Subject: id.Subject,
		Groups: id.Groups, UpstreamExp: id.Exp, UserAgent: r.UserAgent(),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create session")
		return
	}
	_ = c.s.audit.Append("login_success", id.User, "", "", map[string]string{
		"provider": providerOIDC, "path": "cluster_console",
	})
	writeJSON(w, map[string]any{
		"token": token, "expiresUnix": rec.ExpiresUnix, "user": rec.User,
	})
}

// handleSession is the SPA's session probe / "who am I". It reports the live cluster
// session for a bearer, or — when a break-glass cert authenticates the request and no
// bearer is present — a cert-auth marker so the SPA knows it is already authenticated
// and need not run the OIDC login.
func (c *clusterConsoleAPI) handleSession(w http.ResponseWriter, r *http.Request) {
	if id := c.clusterAdminFromCert(r); id != nil {
		writeJSON(w, map[string]any{"user": id.Name, "auth": "cert", "admin": true})
		return
	}
	rec, err := c.clusterSessionFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, map[string]any{
		"user": rec.User, "auth": "oidc", "admin": true,
		"groups": orEmpty(rec.Groups), "expiresUnix": rec.ExpiresUnix,
	})
}

// handleLogout revokes the caller's own cluster session (server-side delete, so the
// bearer is dead immediately). A cert-authed operator has no session to revoke.
func (c *clusterConsoleAPI) handleLogout(w http.ResponseWriter, r *http.Request) {
	if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && tok != "" {
		_ = c.s.store.DeleteAuthSession(hashToken(tok))
	}
	writeJSON(w, map[string]any{"ok": true})
}

// verifyClusterOIDC verifies a browser-supplied id_token against the CLUSTER console's
// OIDC client (its own audience), then extracts the username/subject/groups/exp using
// the cluster console's configured claim names.
func (c *clusterConsoleAPI) verifyClusterOIDC(ctx context.Context, idToken string) (oidcIdentity, error) {
	if c.verifier == nil {
		return oidcIdentity{}, errors.New("oidc login is not configured")
	}
	if idToken == "" {
		return oidcIdentity{}, errors.New("missing oidc id token")
	}
	claims, err := c.verifier.verify(ctx, idToken)
	if err != nil {
		return oidcIdentity{}, err
	}
	return extractOIDCIdentity(&OIDCConfig{
		UsernameClaim: c.s.cfg.clusterConsoleUsernameClaim(),
		GroupsClaim:   c.s.cfg.clusterConsoleGroupsClaim(),
	}, claims)
}

func (c *clusterConsoleAPI) auditLoginDenied(user, reason string) {
	_ = c.s.audit.Append("login_denied", user, "", "", map[string]string{
		"provider": providerOIDC, "reason": reason, "path": "cluster_console",
	})
}

// ---- topology ----

func (c *clusterConsoleAPI) handleControllers(w http.ResponseWriter, r *http.Request) {
	rows, err := c.s.store.ListControllers()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list controllers")
		return
	}
	now := time.Now().Unix()
	out := make([]map[string]any, 0, len(rows)+1)
	seen := make(map[string]bool, len(rows))
	for _, g := range rows {
		seen[g.ControllerID] = true
		out = append(out, map[string]any{
			"controllerId":    g.ControllerID,
			"region":       g.RegionID,
			"addrs":        orEmpty(g.Addrs),
			"controlAddrs": orEmpty(g.ControlAddrs),
			"version":      g.Version,
			"lastSeenUnix": g.LastSeenUnix,
			"online":       now-g.LastSeenUnix < int64(controllerStaleTTL.Seconds()),
		})
	}
	// A single-node (or static) controller does not heartbeat a presence row, but the
	// operator must still see the controller they are talking to. Add this controller's
	// own endpoint when it is not already present from the discovery set.
	if self := c.s.controllerEndpoint(); !seen[self.ControllerID] {
		out = append(out, map[string]any{
			"controllerId":    self.ControllerID,
			"region":       self.RegionID,
			"addrs":        orEmpty(self.Addrs),
			"controlAddrs": orEmpty(self.ControlAddrs),
			"version":      version.Version,
			"lastSeenUnix": now,
			"online":       true,
		})
	}
	writeJSON(w, map[string]any{"controllers": out})
}

func (c *clusterConsoleAPI) handleRelays(w http.ResponseWriter, r *http.Request) {
	rows, err := c.s.store.ListRelays("")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list relays")
		return
	}
	now := time.Now().Unix()
	out := make([]map[string]any, 0, len(rows)+len(c.s.cfg.RelayAddrs))
	seenAddr := make(map[string]bool)
	for _, rl := range rows {
		for _, a := range rl.Addrs {
			seenAddr[a] = true
		}
		out = append(out, map[string]any{
			"regionId":     rl.RegionID,
			"relayId":      rl.RelayID,
			"addrs":        orEmpty(rl.Addrs),
			"version":      rl.Version,
			"lastSeenUnix": rl.LastSeenUnix,
			"online":       now-rl.LastSeenUnix < int64(relayStaleTTL.Seconds()),
			// draining surfaces a relay shedding for a swap (still visible/online, but
			// excluded from new-session selection); healthy is its complement.
			"draining": rl.Draining,
			"healthy":  !rl.Draining,
			// activeCount is the relay's live splice + control-mux count: a draining
			// relay's per-relay drain progress, which reaches 0 once its sessions have
			// migrated off and the binary is safe to swap.
			"activeCount": rl.ActiveCount,
			"static":      false,
		})
	}
	// Statically configured relays (relay_addrs) that have not dynamically
	// registered still belong in the topology — on a single-node deploy they are
	// the only relays. Their version is unknown until they register; mark them
	// static so the operator can tell a configured relay from a heartbeating one.
	for _, addr := range c.s.cfg.RelayAddrs {
		if seenAddr[addr] {
			continue
		}
		out = append(out, map[string]any{
			"regionId":     "",
			"relayId":      addr,
			"addrs":        []string{addr},
			"version":      "",
			"lastSeenUnix": int64(0),
			"online":       true,
			"draining":     false,
			"healthy":      true,
			"activeCount":  int32(0),
			"static":       true,
		})
	}
	writeJSON(w, map[string]any{"relays": out})
}

// ---- relay self-update rollout ----

// clusterActor names the authenticated cluster operator for the audit log: the
// break-glass cert subject when present, else the OIDC cluster session user.
func (c *clusterConsoleAPI) clusterActor(r *http.Request) string {
	if id := c.clusterAdminFromCert(r); id != nil {
		return id.Name
	}
	if sess, err := c.clusterSessionFromRequest(r); err == nil && sess != nil {
		return sess.User
	}
	return ""
}

// handleRelayUpdateDesired reports the current relay rollout ring (stable and
// canary versions plus the canary relay set) so an operator can see what the
// relay fleet is being driven toward.
func (c *clusterConsoleAPI) handleRelayUpdateDesired(w http.ResponseWriter, r *http.Request) {
	stable, err := c.s.store.RelayStableVersion()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "relay rollout settings")
		return
	}
	canary, err := c.s.store.RelayCanaryVersion()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "relay rollout settings")
		return
	}
	canaryRelays, err := c.s.store.RelayCanaryNodes()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "relay rollout settings")
		return
	}
	// Per-relay drain progress so an operator watching a rollout can see which relays
	// are shedding and how far they have cleared (activeCount -> 0 is fully drained).
	rows, err := c.s.store.ListRelays("")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "relay fleet")
		return
	}
	now := time.Now().Unix()
	relays := make([]map[string]any, 0, len(rows))
	for _, rl := range rows {
		relays = append(relays, map[string]any{
			"relayId":     rl.RelayID,
			"regionId":    rl.RegionID,
			"version":     rl.Version,
			"draining":    rl.Draining,
			"activeCount": rl.ActiveCount,
			"drained":     rl.Draining && rl.ActiveCount == 0,
			"online":      now-rl.LastSeenUnix < int64(relayStaleTTL.Seconds()),
		})
	}
	writeJSON(w, map[string]any{
		"stableVersion": stable,
		"canaryVersion": canary,
		"canaryRelays":  orEmpty(canaryRelays),
		"relays":        relays,
	})
}

type relayRolloutReq struct {
	Ring         string   `json:"ring"`
	Version      string   `json:"version"`
	CanaryRelays []string `json:"canaryRelays"`
}

// handleRelayUpdateRollout drives the relay ring (canary or stable). A stable
// promotion runs the same relay-aware canary health gate as the gRPC path, so a
// console operator cannot promote past a lagging canary relay either.
func (c *clusterConsoleAPI) handleRelayUpdateRollout(w http.ResponseWriter, r *http.Request) {
	var req relayRolloutReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	ring := c.s.relayRing()
	switch req.Ring {
	case "canary":
		if len(req.CanaryRelays) > 0 {
			if err := ring.setCanaryNodes(req.CanaryRelays); err != nil {
				writeErr(w, http.StatusInternalServerError, "store canary relays")
				return
			}
		}
		if err := ring.setCanaryVersion(req.Version); err != nil {
			writeErr(w, http.StatusInternalServerError, "store relay canary version")
			return
		}
	case "stable":
		canaryRelays, err := ring.canaryNodes()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "relay canary set")
			return
		}
		if len(canaryRelays) > 0 && req.Version != "" {
			if blockers := ring.canaryBlockers(canaryRelays, req.Version); len(blockers) > 0 {
				writeErr(w, http.StatusConflict,
					"stable promotion to "+req.Version+" blocked by canary health gate: "+strings.Join(blockers, "; "))
				return
			}
		}
		if err := ring.setStableVersion(req.Version); err != nil {
			writeErr(w, http.StatusInternalServerError, "store relay stable version")
			return
		}
	default:
		writeErr(w, http.StatusBadRequest, "ring must be \"stable\" or \"canary\"")
		return
	}
	if err := c.s.audit.Append("set_desired_version", c.clusterActor(r), "", "", map[string]string{
		"product": "geneza-relay", "ring": req.Ring, "version": req.Version,
		"canary_nodes": strings.Join(req.CanaryRelays, ","),
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "audit append")
		return
	}
	writeJSON(w, map[string]any{"ok": true, "ring": req.Ring, "version": req.Version})
}

// ---- agents ----

// desiredFor returns the version a node should be running: the canary version if
// the node is in the canary ring, otherwise the stable version.
func desiredFor(nodeID string, canarySet map[string]bool, stable, canary string) string {
	if canarySet[nodeID] {
		return canary
	}
	return stable
}

// canaryMembership loads the canary ring as a set plus the stable/canary versions
// once, so a fleet sweep does not re-read settings per node.
func (c *clusterConsoleAPI) canaryMembership() (set map[string]bool, stable, canary string) {
	stable, _ = c.s.store.StableVersion()
	canary, _ = c.s.store.CanaryVersion()
	nodes, _ := c.s.store.CanaryNodes()
	set = make(map[string]bool, len(nodes))
	for _, n := range nodes {
		set[n] = true
	}
	return set, stable, canary
}

func (c *clusterConsoleAPI) handleAgents(w http.ResponseWriter, r *http.Request) {
	nodes, err := c.s.store.ListAllNodes()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list nodes")
		return
	}
	canarySet, stable, canary := c.canaryMembership()
	outdatedOnly := r.URL.Query().Get("outdated") == "true"
	out := make([]map[string]any, 0, len(nodes))
	for _, n := range nodes {
		desired := desiredFor(n.ID, canarySet, stable, canary)
		outdated := n.Platform.AgentVersion != desired
		if outdatedOnly && !outdated {
			continue
		}
		_, online := c.s.registry.Info(n.ID)
		out = append(out, map[string]any{
			"workspace":      n.WorkspaceID,
			"nodeId":         n.ID,
			"name":           n.Name,
			"agentVersion":   n.Platform.AgentVersion,
			"desiredVersion": desired,
			"outdated":       outdated,
			"online":         online,
		})
	}
	writeJSON(w, map[string]any{"agents": out})
}

func (c *clusterConsoleAPI) handleAgentsRisk(w http.ResponseWriter, r *http.Request) {
	nodes, err := c.s.store.ListAllNodes()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list nodes")
		return
	}
	canarySet, stable, canary := c.canaryMembership()
	outdatedOnly := r.URL.Query().Get("outdated_only") == "true"

	type riskRow struct {
		body     map[string]any
		outdated bool
		sevRank  int
		kev      int
		cve      int
	}
	rows := make([]riskRow, 0, len(nodes))
	for _, n := range nodes {
		desired := desiredFor(n.ID, canarySet, stable, canary)
		outdated := n.Platform.AgentVersion != desired
		if outdatedOnly && !outdated {
			continue
		}
		// Use the node's OWN workspace for the CVE fan-out so the lookup is
		// tenant-correct — a node's CVEs come only from its own workspace's verdicts.
		findings, ferr := cvesForNodeFanned(c.s.store, n.WorkspaceID, n.ID)
		if ferr != nil {
			writeErr(w, http.StatusInternalServerError, "node cve lookup")
			return
		}
		worstRank, worstSev, kevCount := 0, "", 0
		seen := make(map[string]bool, len(findings))
		for _, f := range findings {
			seen[f.CVE] = true
			if f.KEV {
				kevCount++
			}
			if rk := severityRank(f.Severity); rk > worstRank {
				worstRank, worstSev = rk, f.Severity
			}
		}
		_, online := c.s.registry.Info(n.ID)
		rows = append(rows, riskRow{
			body: map[string]any{
				"workspace":      n.WorkspaceID,
				"nodeId":         n.ID,
				"name":           n.Name,
				"agentVersion":   n.Platform.AgentVersion,
				"desiredVersion": desired,
				"outdated":       outdated,
				"worstSeverity":  worstSev,
				"kevCount":       kevCount,
				"cveCount":       len(seen),
				"online":         online,
			},
			outdated: outdated,
			sevRank:  worstRank,
			kev:      kevCount,
			cve:      len(seen),
		})
	}
	// Float the genuinely-urgent nodes to the top: an outdated agent that ALSO carries
	// a KEV or a CRITICAL finding first, then by worst severity, then by CVE count.
	urgent := func(x riskRow) bool { return x.outdated && (x.kev > 0 || x.sevRank == 4) }
	sort.SliceStable(rows, func(i, j int) bool {
		ui, uj := urgent(rows[i]), urgent(rows[j])
		if ui != uj {
			return ui
		}
		if rows[i].sevRank != rows[j].sevRank {
			return rows[i].sevRank > rows[j].sevRank
		}
		return rows[i].cve > rows[j].cve
	})
	out := make([]map[string]any, 0, len(rows))
	for _, rr := range rows {
		out = append(out, rr.body)
	}
	writeJSON(w, map[string]any{"agents": out})
}

func (c *clusterConsoleAPI) handleWorkspaces(w http.ResponseWriter, r *http.Request) {
	rows, err := c.s.store.ListWorkspaces()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list workspaces")
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, ws := range rows {
		out = append(out, map[string]any{
			"id":          ws.ID,
			"name":        ws.Name,
			"overlayCidr": ws.OverlayCIDR,
			"createdUnix": ws.CreatedUnix,
		})
	}
	writeJSON(w, map[string]any{"workspaces": out})
}

// clusterConsoleServer builds the cluster-operator console's mTLS server, or nil if
// disabled. The listener accepts an OPTIONAL client cert (VerifyClientCertIfGiven): a
// browser presenting no cert still completes the handshake and authenticates via OIDC,
// while a presented cert is chain-verified so the break-glass path keeps working. A
// cert that is not a break-glass cluster admin (or no cert + no session) is rejected
// per-route by clusterAuth.
func (s *Server) clusterConsoleServer() (*http.Server, error) {
	if !s.cfg.ClusterConsoleEnabled() {
		return nil, nil
	}
	clientCAs, err := ca.PoolFromPEM(s.ca.RootsPEM)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              s.cfg.ClusterConsole.Listen,
		Handler:           s.clusterConsole.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         clusterConsoleTLS(s.tlsCert, clientCAs),
	}, nil
}

// clusterConsoleTLS verifies a client cert ONLY when one is presented
// (VerifyClientCertIfGiven): a browser with no cert still connects and then logs in
// via OIDC, while a presented cert is chain-verified against our CA so VerifiedChains
// is non-empty exactly when the break-glass check should trust the leaf. A cert our CA
// did not sign still fails the handshake; the absence of a cert does not.
func clusterConsoleTLS(serverCert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
		ClientCAs:    clientCAs,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}
}
