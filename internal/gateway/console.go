package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"osie.cloud/geneza/internal/types"
)

// consoleAPI is the web control panel's HTTP/JSON backend. It runs as a
// plain-HTTP listener (TLS is terminated by a front proxy) and authenticates
// browsers with an OIDC bearer ID token (the SPA runs the Authorization Code +
// PKCE flow itself). Authorization reuses the same policy role mapping as the
// rest of the gateway: read endpoints require any role, mutations require admin.
type consoleAPI struct {
	s        *Server
	verifier *oidcVerifier
	clientID string
	extURL   string
	static   string
}

func (s *Server) newConsoleAPI() (*consoleAPI, error) {
	if s.cfg.OIDC == nil {
		return nil, errors.New("console requires oidc to be configured")
	}
	clientID := s.cfg.Console.OIDCClientID
	if clientID == "" {
		clientID = s.cfg.OIDC.ClientID
	}
	c := &consoleAPI{
		s:        s,
		verifier: newOIDCVerifier(s.cfg.OIDC.Issuer, clientID),
		clientID: clientID,
		extURL:   strings.TrimRight(s.cfg.Console.ExternalURL, "/"),
		static:   s.cfg.Console.StaticDir,
	}
	// Warm the OIDC discovery + JWKS in the background so the FIRST console
	// request after a (re)start doesn't pay the cold-fetch latency and 401 —
	// a transient 401 logs the SPA out, which would also kill a live web shell.
	go c.verifier.Warm(context.Background())
	return c, nil
}

type consoleUser struct {
	Name        string
	Workspace   string // tenant scope for all console reads/mutations
	Groups      []string
	Roles       []string
	Admin       bool
	ExpiresUnix int64
}

func (c *consoleAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/config", c.handleConfig)
	mux.Handle("GET /api/v1/me", c.auth(c.handleMe))
	mux.Handle("GET /api/v1/overview", c.auth(c.handleOverview))
	mux.Handle("GET /api/v1/nodes", c.auth(c.handleNodes))
	mux.Handle("GET /api/v1/sessions", c.auth(c.handleSessions))
	mux.Handle("GET /api/v1/fleet", c.auth(c.handleFleet))
	mux.Handle("GET /api/v1/policy", c.auth(c.handlePolicy))
	mux.Handle("GET /api/v1/audit", c.auth(c.handleAudit))
	mux.Handle("POST /api/v1/tokens", c.authAdmin(c.handleMintToken))
	mux.Handle("DELETE /api/v1/sessions/{id}", c.authAdmin(c.handleRevokeSession))
	mux.Handle("POST /api/v1/nodes/{id}/approve", c.authAdmin(c.handleApproveNode))
	mux.Handle("DELETE /api/v1/nodes/{id}", c.authAdmin(c.handleRemoveNode))
	// Monitoring: Prometheus-shaped query API (any role) + per-node module toggle (admin).
	mux.Handle("GET /api/v1/metrics/query", c.auth(c.handleMetricsQuery))
	mux.Handle("GET /api/v1/metrics/query_range", c.auth(c.handleMetricsQueryRange))
	mux.Handle("GET /api/v1/nodes/{id}/modules", c.auth(c.handleGetNodeModules))
	mux.Handle("PUT /api/v1/nodes/{id}/modules", c.authAdmin(c.handleSetNodeModules))
	// Browser remote shell (WebSocket; authenticates from ?token= since a WS
	// handshake can't carry the Authorization header). Policy is enforced
	// server-side as client_path=web.
	mux.HandleFunc("GET /api/v1/nodes/{id}/shell", c.handleShell)
	mux.HandleFunc("/", c.serveSPA)
	return secHeaders(mux)
}

func secHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// ---- auth ----

func (c *consoleAPI) authenticate(r *http.Request) (*consoleUser, error) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		return nil, errors.New("missing bearer token")
	}
	return c.authenticateToken(r.Context(), tok)
}

// authenticateToken verifies a raw bearer token and builds the console user.
// Used by the header-based middleware and by the WebSocket shell (browsers can't
// set the Authorization header on a WS handshake, so it arrives as ?token=).
func (c *consoleAPI) authenticateToken(ctx context.Context, tok string) (*consoleUser, error) {
	claims, err := c.verifier.verify(ctx, tok)
	if err != nil {
		return nil, err
	}
	user, _ := claims[c.s.cfg.OIDC.UsernameClaim].(string)
	if user == "" {
		return nil, errors.New("token has no username claim")
	}
	groups := claimStrings(claims[c.s.cfg.OIDC.GroupsClaim])
	roles := c.s.policy().RolesFor(user, groups)
	exp, _ := claims["exp"].(float64)
	return &consoleUser{Name: user, Workspace: defaultWorkspace, Groups: groups, Roles: roles, Admin: contains(roles, "admin"), ExpiresUnix: int64(exp)}, nil
}

func (c *consoleAPI) auth(fn func(http.ResponseWriter, *http.Request, *consoleUser)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := c.authenticate(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if len(u.Roles) == 0 {
			writeErr(w, http.StatusForbidden, "no roles for this user")
			return
		}
		fn(w, r, u)
	})
}

func (c *consoleAPI) authAdmin(fn func(http.ResponseWriter, *http.Request, *consoleUser)) http.Handler {
	return c.auth(func(w http.ResponseWriter, r *http.Request, u *consoleUser) {
		if !u.Admin {
			writeErr(w, http.StatusForbidden, "admin role required")
			return
		}
		fn(w, r, u)
	})
}

// ---- handlers ----

func (c *consoleAPI) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"oidc": map[string]string{
			"issuer":      c.s.cfg.OIDC.Issuer,
			"clientId":    c.clientID,
			"redirectUri": c.extURL + "/",
		},
		"clusterName": c.s.cfg.ClusterName,
		"externalUrl": c.extURL,
	})
}

func (c *consoleAPI) handleMe(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	writeJSON(w, map[string]any{
		"user": u.Name, "workspace": u.Workspace, "roles": orEmpty(u.Roles), "groups": orEmpty(u.Groups),
		"admin": u.Admin, "expiresUnix": u.ExpiresUnix,
	})
}

func (c *consoleAPI) nodeJSON(ws string) []map[string]any {
	sums, err := c.s.nodeSummaries(ws)
	if err != nil {
		return nil
	}
	out := make([]map[string]any, 0, len(sums))
	for _, n := range sums {
		out = append(out, map[string]any{
			"nodeId": n.GetNodeId(), "name": n.GetName(), "online": n.GetOnline(),
			"version": n.GetVersion(), "os": n.GetOs(), "arch": n.GetArch(),
			"labels": orEmptyMap(n.GetLabels()), "lastSeenUnix": n.GetLastSeenUnix(),
			"activeSessions": n.GetActiveSessions(), "detachedSessions": n.GetDetachedSessions(),
			"approved": n.GetApproved(), "overlayIp": n.GetOverlayIp(),
		})
	}
	return out
}

func (c *consoleAPI) handleNodes(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	writeJSON(w, map[string]any{"nodes": c.nodeJSON(u.Workspace)})
}

func (c *consoleAPI) handleSessions(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	all, err := c.s.store.ListSessions(u.Workspace)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list sessions")
		return
	}
	out := make([]map[string]any, 0, len(all))
	for _, s := range all {
		out = append(out, map[string]any{
			"sessionId": s.ID, "nodeId": s.NodeID, "nodeName": s.NodeName, "user": s.User,
			"action": s.Action, "state": s.State, "startedUnix": s.StartedUnix,
			"detachable": s.Detachable, "hostSessionId": s.HostSessionID,
		})
	}
	writeJSON(w, map[string]any{"sessions": out})
}

func (c *consoleAPI) handleFleet(w http.ResponseWriter, r *http.Request, _ *consoleUser) {
	stable, _ := c.s.store.StableVersion()
	canary, _ := c.s.store.CanaryVersion()
	cn, _ := c.s.store.CanaryNodes()
	writeJSON(w, map[string]any{"stable": stable, "canary": canary, "canaryNodes": orEmpty(cn)})
}

func (c *consoleAPI) handleOverview(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	nodes := c.nodeJSON(u.Workspace)
	online := 0
	var active, detached uint32
	for _, n := range nodes {
		if n["online"].(bool) {
			online++
		}
		active += n["activeSessions"].(uint32)
		detached += n["detachedSessions"].(uint32)
	}
	sessions, _ := c.s.store.ListSessions(u.Workspace)
	stable, _ := c.s.store.StableVersion()
	canary, _ := c.s.store.CanaryVersion()
	count, chainOK := 0, true
	if n, err := c.s.audit.Verify(); err == nil {
		count = n
	} else {
		chainOK = false
	}
	writeJSON(w, map[string]any{
		"nodes":    map[string]any{"total": len(nodes), "online": online},
		"sessions": map[string]any{"active": active, "detached": detached, "total": len(sessions)},
		"versions": map[string]any{"stable": stable, "canary": canary},
		"audit":    map[string]any{"count": count, "chainOk": chainOK},
		"relays":   orEmpty(c.s.cfg.RelayAddrs),
	})
}

func (c *consoleAPI) handlePolicy(w http.ResponseWriter, r *http.Request, _ *consoleUser) {
	b, err := os.ReadFile(c.s.cfg.PolicyFile)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "read policy")
		return
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		writeErr(w, http.StatusInternalServerError, "parse policy")
		return
	}
	writeJSON(w, normalizeYAML(doc))
}

func (c *consoleAPI) handleAudit(w http.ResponseWriter, r *http.Request, _ *consoleUser) {
	q := r.URL.Query()
	since, _ := strconv.ParseInt(q.Get("since"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	lines, chainOK, err := c.s.audit.Query(since, q.Get("type"), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query audit")
		return
	}
	recs := make([]json.RawMessage, 0, len(lines))
	for _, l := range lines {
		recs = append(recs, json.RawMessage(l))
	}
	writeJSON(w, map[string]any{"records": recs, "chainOk": chainOK})
}

func (c *consoleAPI) handleMintToken(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	var req struct {
		TTLSeconds int64             `json:"ttlSeconds"`
		Labels     map[string]string `json:"labels"`
		MaxUses    int32             `json:"maxUses"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	if req.MaxUses <= 0 {
		req.MaxUses = 1
	}
	token, err := types.NewToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token")
		return
	}
	expires := time.Now().Add(ttl).Unix()
	if err := c.s.store.PutToken(token, &TokenRecord{Labels: req.Labels, ExpiresUnix: expires, MaxUses: req.MaxUses}); err != nil {
		writeErr(w, http.StatusInternalServerError, "store token")
		return
	}
	_ = c.s.audit.Append("token_create", "console:"+u.Name, "", "", map[string]string{
		"ttl_seconds": strconv.FormatInt(int64(ttl/time.Second), 10),
		"max_uses":    strconv.FormatInt(int64(req.MaxUses), 10),
	})
	writeJSON(w, map[string]any{"token": token, "expiresUnix": expires})
}

// handleRevokeSession lets an admin kick a live session from the console.
func (c *consoleAPI) handleRevokeSession(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	id := r.PathValue("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "session id required")
		return
	}
	if err := c.s.revokeByID(u.Workspace, id, "console "+u.Name+": revoked by admin"); err != nil {
		writeErr(w, http.StatusNotFound, "revoke: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// handleApproveNode flips a machine's admission gate from the console (admin).
// Body: {"approve": true|false}.
func (c *consoleAPI) handleApproveNode(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	id := r.PathValue("id")
	node, err := c.s.store.FindNode(u.Workspace, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}
	var body struct {
		Approve bool `json:"approve"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	by := "console:" + u.Name
	if _, err := c.s.store.SetNodeApproval(u.Workspace, node.ID, body.Approve, by, time.Now()); err != nil {
		writeErr(w, http.StatusInternalServerError, "set approval")
		return
	}
	decision := "approve"
	if !body.Approve {
		decision = "revoke_approval"
	}
	_ = c.s.audit.Append("node_approval", by, node.ID, "", map[string]string{"decision": decision, "name": node.Name})
	writeJSON(w, map[string]any{"ok": true, "approved": body.Approve})
}

// handleRemoveNode decommissions a machine from the console (admin): revoke its
// live sessions, then delete the record.
func (c *consoleAPI) handleRemoveNode(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	id := r.PathValue("id")
	node, err := c.s.store.FindNode(u.Workspace, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}
	if sessions, err := c.s.store.ListSessions(u.Workspace); err == nil {
		for _, rec := range sessions {
			if rec.NodeID == node.ID && (rec.State == SessionActive || rec.State == SessionDetached) {
				_ = c.s.revokeSession(rec, "node removed")
			}
		}
	}
	if err := c.s.store.DeleteNode(u.Workspace, node.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete node")
		return
	}
	_ = c.s.audit.Append("node_remove", "console:"+u.Name, node.ID, "", map[string]string{"name": node.Name})
	writeJSON(w, map[string]any{"ok": true})
}

// serveSPA serves the built static SPA, falling back to index.html for client
// routes (any non-/api path that does not map to a file).
func (c *consoleAPI) serveSPA(w http.ResponseWriter, r *http.Request) {
	if c.static == "" {
		http.Error(w, "console static dir not configured", http.StatusNotFound)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
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

// ---- helpers ----

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func claimStrings(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return x
	}
	return nil
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func orEmptyMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// normalizeYAML converts yaml.v3's map[string]interface{} (already string-keyed
// for mappings) recursively so json.Marshal handles any nested any-typed maps.
func normalizeYAML(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, val := range x {
			m[k] = normalizeYAML(val)
		}
		return m
	case map[any]any:
		m := make(map[string]any, len(x))
		for k, val := range x {
			m[toStr(k)] = normalizeYAML(val)
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalizeYAML(e)
		}
		return out
	default:
		return v
	}
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// consoleServer builds the plain-HTTP console server, or nil if disabled.
func (s *Server) consoleServer() (*http.Server, error) {
	if !s.cfg.ConsoleEnabled() {
		return nil, nil
	}
	api, err := s.newConsoleAPI()
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              s.cfg.Console.Listen,
		Handler:           api.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}, nil
}
