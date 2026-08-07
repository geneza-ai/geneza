package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"geneza.io/internal/ca"
	"geneza.io/internal/enrollcode"
	"geneza.io/internal/policy"
	"geneza.io/internal/types"
)

// consoleAPI is the web control panel's HTTP/JSON backend. It runs as a
// plain-HTTP listener (TLS is terminated by a front proxy) and authenticates
// browsers with a CONTROLLER-MINTED opaque session token (Bearer), NOT an upstream
// IdP token: the SPA POSTs credentials to a /session/{local,oidc,keystone}
// endpoint and carries the returned session. Authorization reuses the policy
// role mapping: read endpoints require any role, mutations require ws-admin.
type consoleAPI struct {
	s        *Server
	verifier *oidcVerifier // nil unless OIDC is configured (oidc login + bootstrap discovery)
	clientID string
	extURL   string
	static   string
}

func (s *Server) newConsoleAPI() (*consoleAPI, error) {
	c := &consoleAPI{
		s:      s,
		extURL: strings.TrimRight(s.cfg.Console.ExternalURL, "/"),
		static: s.cfg.Console.StaticDir,
	}
	// OIDC is now OPTIONAL: the console runs on any enabled mechanism (validated
	// at config load). Build the verifier only when OIDC is configured.
	if s.cfg.OIDC != nil {
		clientID := s.cfg.Console.OIDCClientID
		if clientID == "" {
			clientID = s.cfg.OIDC.ClientID
		}
		c.clientID = clientID
		c.verifier = newOIDCVerifier(s.cfg.OIDC.Issuer, clientID)
		// Warm OIDC discovery + JWKS so the first oidc login after (re)start
		// doesn't pay the cold-fetch latency.
		go c.verifier.Warm(context.Background())
	}
	return c, nil
}

type consoleUser struct {
	Name        string
	Provider    string
	Subject     string
	Workspace   string // tenant scope for all console reads/mutations (from the session record)
	Groups      []string
	Roles       []string
	Admin       bool
	ExpiresUnix int64
	// Scope is non-nil for a hosted-UI launch session: the caller is pinned to
	// one node and one action set. Nil for every ordinary console session.
	Scope *SessionScope
}

func (c *consoleAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/config", c.handleConfig)
	// Login: anonymous credential exchange -> opaque session.
	mux.HandleFunc("POST /api/v1/session/local", c.handleSessionLocal)
	mux.HandleFunc("POST /api/v1/session/oidc", c.handleSessionOIDC)
	mux.HandleFunc("POST /api/v1/session/keystone", c.handleSessionKeystone)
	// Session lifecycle (the SPA bootstrap probe + logout). Scoped: an embedded
	// launch session must be able to read its own identity and end itself.
	mux.Handle("GET /api/v1/session", c.authScoped(c.handleSession))
	mux.Handle("DELETE /api/v1/session", c.authScoped(c.handleLogout))
	mux.Handle("POST /api/v1/session/renew", c.authScoped(c.handleSessionRenew))
	// Presence hardware-factor enroll: begin/finish store an EnrolledCredential
	// so the software-stub gate refuses software thereafter.
	mux.Handle("POST /api/v1/presence/enroll/begin", c.auth(c.handleEnrollBegin))
	mux.Handle("POST /api/v1/presence/enroll/finish", c.auth(c.handleEnrollFinish))
	mux.Handle("GET /api/v1/presence/credentials", c.auth(c.handleEnrollList))
	// RFC 8628 device grant: the CLI hits authorize/token on :7402; the human
	// approves here (session-authed). authorize/token are also served here so a
	// console-only deployment still works.
	mux.HandleFunc("POST /api/v1/device/authorize", c.s.handleDeviceAuthorize)
	mux.HandleFunc("POST /api/v1/device/token", c.s.handleDeviceToken)
	mux.Handle("GET /api/v1/device/{code}", c.auth(c.handleDeviceLookup))
	mux.Handle("POST /api/v1/device/approve", c.auth(c.handleDeviceApprove))
	mux.Handle("POST /api/v1/device/deny", c.auth(c.handleDeviceDeny))
	// Trusted-dashboard SSO: Horizon websso form-POSTs a keystone token here; the
	// SPA swaps the returned single-use code for a session.
	mux.HandleFunc("POST /openstack/{svc}", c.handleTrustedDashboard)
	mux.HandleFunc("POST /api/v1/session/handoff", c.handleSessionHandoff)
	// Portal console handoff: the same capability as trusted_dashboard, but minted
	// server-to-server so a portal holding the keystone token server-side never has
	// to publish it to its own DOM.
	mux.HandleFunc("POST /openstack/{svc}/console", c.handlePortalConsoleMint)
	mux.HandleFunc("GET /console-bind", c.handlePortalConsoleBind)
	// Hosted-UI launch: the cloud's tenant portal mints a single-use, node-scoped
	// URL (server-to-server, carrying the tenant's OWN keystone token); the embed
	// page swaps the code for a scoped session.
	mux.HandleFunc("POST /openstack/{svc}/launch", c.handleLaunchMint)
	mux.HandleFunc("GET /launch", c.handleLaunchBind)
	mux.HandleFunc("POST /api/v1/session/launch", c.handleSessionLaunch)
	mux.Handle("GET /api/v1/overview", c.auth(c.handleOverview))
	mux.Handle("GET /api/v1/nodes", c.auth(c.handleNodes))
	mux.Handle("GET /api/v1/nodes/{id}", c.auth(c.handleNode))
	mux.Handle("GET /api/v1/sessions", c.auth(c.handleSessions))
	mux.Handle("GET /api/v1/fleet", c.auth(c.handleFleet))
	mux.Handle("GET /api/v1/policy", c.auth(c.handlePolicy))
	mux.Handle("PUT /api/v1/policy", c.authAdmin(c.handleSetPolicy))
	mux.Handle("POST /api/v1/policy/validate", c.auth(c.handleValidatePolicy))
	mux.Handle("GET /api/v1/policy/history", c.authAdmin(c.handlePolicyHistory))
	mux.Handle("POST /api/v1/policy/render", c.auth(c.handleRenderPolicy))
	mux.Handle("GET /api/v1/audit", c.auth(c.handleAudit))
	mux.Handle("POST /api/v1/tokens", c.authAdmin(c.handleMintToken))
	// Per-workspace membership (ws-admin), scoped to the session's tenant.
	mux.Handle("GET /api/v1/suspensions", c.authAdmin(c.handleListSuspensions))
	mux.Handle("POST /api/v1/suspensions", c.authAdmin(c.handleSuspendPrincipal))
	mux.Handle("DELETE /api/v1/suspensions/{provider}/{subject}", c.authAdmin(c.handleLiftSuspension))
	mux.Handle("POST /api/v1/sessions/revoke-user", c.authAdmin(c.handleRevokeUserSessions))
	mux.Handle("GET /api/v1/members", c.authAdmin(c.handleListMembers))
	mux.Handle("POST /api/v1/members", c.authAdmin(c.handlePutMember))
	mux.Handle("DELETE /api/v1/members/{provider}/{subject}", c.authAdmin(c.handleDeleteMember))
	// Managed-domain subdomain reservations: list (any member) + reserve/release
	// (ws-admin). The cert manager issues a wildcard per reservation.
	mux.Handle("GET /api/v1/subdomains", c.auth(c.handleListSubdomains))
	mux.Handle("POST /api/v1/subdomains", c.authAdmin(c.handleReserveSubdomain))
	mux.Handle("DELETE /api/v1/subdomains/{domain}/{label}", c.authAdmin(c.handleReleaseSubdomain))
	// Funnel exposures: list (any member), create/delete (ws-admin).
	mux.Handle("GET /api/v1/funnels", c.auth(c.handleListFunnels))
	mux.Handle("POST /api/v1/funnels", c.authAdmin(c.handleCreateFunnel))
	mux.Handle("DELETE /api/v1/funnels/{hostname}", c.authAdmin(c.handleDeleteFunnel))
	mux.Handle("DELETE /api/v1/sessions/{id}", c.authAdmin(c.handleRevokeSession))
	mux.Handle("POST /api/v1/nodes/{id}/approve", c.authAdmin(c.handleApproveNode))
	mux.Handle("POST /api/v1/nodes/{id}/rebaseline", c.authAdmin(c.handleRebaselineNode))
	mux.Handle("DELETE /api/v1/nodes/{id}", c.authAdmin(c.handleRemoveNode))
	// Monitoring: Prometheus-shaped query API (any role) + per-node module toggle (admin).
	mux.Handle("GET /api/v1/metrics/query", c.auth(c.handleMetricsQuery))
	mux.Handle("GET /api/v1/metrics/query_range", c.auth(c.handleMetricsQueryRange))
	mux.Handle("GET /api/v1/nodes/{id}/modules", c.auth(c.handleGetNodeModules))
	mux.Handle("PUT /api/v1/nodes/{id}/modules", c.authAdmin(c.handleSetNodeModules))

	// Vulnerability surface (read, ws-member-gated in the handlers).
	mux.Handle("GET /api/v1/nodes/{id}/cves", c.auth(c.handleNodeCVEs))
	mux.Handle("GET /api/v1/nodes/{id}/components", c.auth(c.handleNodeComponents))
	mux.Handle("GET /api/v1/vuln/feed", c.auth(c.handleVulnFeedStatus))
	mux.Handle("GET /api/v1/cves", c.auth(c.handleWorkspaceCVEs))
	mux.Handle("GET /api/v1/cves/{cve}/nodes", c.auth(c.handleNodesAffectedByCVE))
	// Open SBOM/findings edges: export a node's inventory as CycloneDX and its
	// verdicts as OpenVEX (vuln-view-gated), and ingest a CycloneDX SBOM from an
	// external scanner (operator-gated). The export build and the ingest match path
	// reuse the same component index and matcher the agent's gRPC report uses.
	mux.Handle("GET /api/v1/nodes/{id}/sbom", c.auth(c.handleNodeSBOMExport))
	mux.Handle("GET /api/v1/nodes/{id}/findings.vex", c.auth(c.handleNodeFindingsVEX))
	mux.Handle("POST /api/v1/nodes/{id}/sbom", c.authAdmin(c.handleNodeSBOMIngest))
	// Session recordings (replay-capability-gated in the handlers). The list is
	// metadata; the blob is opaque ciphertext the auditor decrypts client-side.
	mux.Handle("GET /api/v1/recordings", c.auth(c.handleRecordings))
	mux.Handle("GET /api/v1/recordings/{id}", c.auth(c.handleRecordingBlob))
	// Browser remote shell (WebSocket; authenticates from ?token= since a WS
	// handshake can't carry the Authorization header). Policy is enforced
	// server-side as client_path=web.
	mux.Handle("POST /api/v1/nodes/{id}/shell-ticket", c.authScoped(c.handleShellTicket))
	mux.HandleFunc("GET /api/v1/nodes/{id}/shell", c.handleShell)

	// Mirror the installer onto the console listener. The one-liner this
	// controller hands out points at the CONSOLE's public origin (that is the
	// front with publicly-trusted TLS, so curl on a bare host trusts it), and
	// without these the SPA catch-all below answers /install.sh with index.html
	// and HTTP 200 — HTML piped into `sudo sh`, and a status-code check still
	// reads healthy. Everything here is public material whose trust derives from
	// the pinned fingerprint and the signed update chain, not from the channel.
	c.s.registerInstallerRoutes(mux)

	mux.HandleFunc("/", c.serveSPA)
	return secHeaders(mux)
}

// embedPathPrefix is the ONLY part of the console that may ever be framed, and
// only when a cloud opts in with an exact frame-ancestors allow-list. Every
// other path — the whole console — keeps X-Frame-Options: DENY.
const embedPathPrefix = "/embed/"

func secHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !strings.HasPrefix(r.URL.Path, embedPathPrefix) {
			// The embed document sets its own framing policy (CSP frame-ancestors,
			// which XFO would otherwise contradict); serveSPA falls back to DENY
			// there whenever embedding is not explicitly allowed.
			w.Header().Set("X-Frame-Options", "DENY")
		}
		// A launch URL carries its single-use code in the fragment, which is never
		// sent anywhere — but keep referrers off the provider's portal regardless.
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// embedFramingHeaders emits the framing policy for an /embed/ document. The
// ?cloud= query is a ROUTING hint only — it selects which allow-list to serve
// and authenticates nothing (the launch code, and therefore all authority,
// lives in the fragment and is exchanged later). An unknown cloud, a cloud with
// launch or embedding off, or a missing hint all fail closed to 'none'.
func (c *consoleAPI) embedFramingHeaders(w http.ResponseWriter, r *http.Request) {
	ancestors := c.s.cfg.Clouds[r.URL.Query().Get("cloud")].frameAncestors()
	if len(ancestors) == 0 {
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.Header().Set("X-Frame-Options", "DENY")
		return
	}
	w.Header().Set("Content-Security-Policy", "frame-ancestors "+strings.Join(ancestors, " "))
}

// ---- auth ----

func (c *consoleAPI) authenticate(r *http.Request) (*consoleUser, error) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		return nil, errors.New("missing bearer token")
	}
	return c.authenticateToken(r.Context(), tok)
}

// certUser derives a consoleUser from a verified mTLS user cert, or nil if the
// request carries no usable cert (or the cert/principal is revoked/suspended).
// Used ONLY by the cert-only :7402 mount (certAuth); the browser :7406 listener
// stays bearer-only.
func (c *consoleAPI) certUser(r *http.Request) *consoleUser {
	// Require a CHAIN-VERIFIED cert locally (don't trust PeerCertificates on the
	// strength of a distant ClientAuth setting): VerifiedChains is non-empty only
	// when the handshake built and verified the chain against ClientCAs, exactly
	// as the gRPC peer extractor does.
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil
	}
	leaf := r.TLS.VerifiedChains[0][0]
	id, err := ca.PeerIdentity(leaf)
	if err != nil || id.Kind != ca.KindUser || id.Name == "" {
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
	return &consoleUser{
		Name:        id.Name,
		Provider:    id.Provider,
		Subject:     id.Subject,
		Workspace:   id.Workspace,
		Roles:       id.Roles,
		Admin:       isWorkspaceAdmin(id.Roles),
		ExpiresUnix: leaf.NotAfter.Unix(),
	}
}

// authenticateToken resolves a raw bearer/`?token=` value to the logged-in user
// by looking up the controller-minted session (hashed at rest). Workspace, roles
// and admin come ONLY from the stored record — never a hardcoded default and
// never a client-supplied value. Used by the header middleware and the
// WebSocket shell (which can't set Authorization, so the token arrives as
// ?token=). ctx is unused now (no upstream verification) but kept for the shared
// signature.
func (c *consoleAPI) authenticateToken(_ context.Context, tok string) (*consoleUser, error) {
	if tok == "" {
		return nil, errors.New("missing session token")
	}
	return c.authenticateSessionHash(hashToken(tok))
}

// authenticateSessionHash resolves a session by its stored token-hash (the Bearer
// path hashes the raw token; the WS-ticket path already holds the hash). The
// session record is the SOLE authority — workspace/roles/admin come only from it.
func (c *consoleAPI) authenticateSessionHash(tokenHash string) (*consoleUser, error) {
	rec, err := c.s.store.GetAuthSession(tokenHash)
	if err != nil {
		return nil, errors.New("invalid session")
	}
	// A cluster-console session must never authenticate the tenant console: the two
	// namespaces are disjoint, so anything but a tenant (empty/legacy) kind is refused.
	if rec.Kind == sessionKindCluster {
		return nil, errors.New("invalid session")
	}
	if rec.Revoked {
		return nil, errors.New("session revoked")
	}
	if rec.ExpiresUnix > 0 && time.Now().Unix() >= rec.ExpiresUnix {
		_ = c.s.store.DeleteAuthSession(rec.TokenHash)
		return nil, errors.New("session expired")
	}
	return &consoleUser{
		Name:        rec.User,
		Provider:    rec.Provider,
		Subject:     rec.Subject,
		Workspace:   rec.Workspace,
		Groups:      rec.Groups,
		Roles:       rec.Roles,
		Admin:       rec.Admin,
		ExpiresUnix: rec.ExpiresUnix,
		Scope:       rec.Scope,
	}, nil
}

// isWorkspaceAdmin reports whether a role set satisfies the console mutation
// gate. ws-admin is the workspace-scoped admin granted by login/membership;
// admin is the (break-glass-only) cluster role, which also implies console
// admin. The gRPC ClusterAPI gate, by contrast, accepts ONLY the cluster admin.
func isWorkspaceAdmin(roles []string) bool {
	return contains(roles, roleAdmin) || contains(roles, roleWSAdmin)
}

// auth is the ordinary console gate. It refuses a SCOPED (hosted-UI launch)
// session outright: a launch session reaches only the handful of routes that
// deliberately opt in via authScoped. This is an allow-list by construction —
// a route added to the console later is denied to launch sessions until someone
// changes its wrapper, rather than being exposed by forgetting a deny-list
// entry. It holds even for endpoints the caller's own roles would permit.
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
		if u.Scope != nil {
			writeErr(w, http.StatusForbidden, "this session is scoped to a single node and may not use the console API")
			return
		}
		fn(w, r, u)
	})
}

// authScoped admits BOTH ordinary console sessions and hosted-UI launch
// sessions. It is used only on the few routes an embedded shell needs. When the
// caller is scoped and the route is node-addressed, the node in the path must be
// the one the launch pinned — a scoped session can never address a second node.
func (c *consoleAPI) authScoped(fn func(http.ResponseWriter, *http.Request, *consoleUser)) http.Handler {
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
		if id := r.PathValue("id"); id != "" && !u.Scope.allowsNode(id) {
			writeErr(w, http.StatusForbidden, "this session is scoped to a different node")
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

// certAuth is the mTLS-cert-only auth wrapper for the :7402 mount: it never
// consults the Authorization header, so a bearer session can't be replayed
// against the public cert port — only a verified client cert authenticates.
func (c *consoleAPI) certAuth(fn func(http.ResponseWriter, *http.Request, *consoleUser)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := c.certUser(r)
		if u == nil {
			writeErr(w, http.StatusUnauthorized, "client certificate required")
			return
		}
		if len(u.Roles) == 0 {
			writeErr(w, http.StatusForbidden, "no roles for this user")
			return
		}
		fn(w, r, u)
	})
}

func (c *consoleAPI) certAuthAdmin(fn func(http.ResponseWriter, *http.Request, *consoleUser)) http.Handler {
	return c.certAuth(func(w http.ResponseWriter, r *http.Request, u *consoleUser) {
		if !u.Admin {
			writeErr(w, http.StatusForbidden, "admin role required")
			return
		}
		fn(w, r, u)
	})
}

// certHandler is the reduced, cert-only console surface mounted on the
// internet-facing :7402 listener for the desktop app. It serves ONLY the
// authenticated read/mutation routes the embedded console needs — deliberately
// omitting the anonymous bearer-minting login routes, the keystone websso POST,
// the device-grant endpoints, the controller-brokered web-shell, and the SPA
// fallback, none of which the desktop uses. Unmatched paths 404 (no SPA).
func (c *consoleAPI) certHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/config", c.handleConfig) // anonymous bootstrap (no secrets)
	mux.Handle("GET /api/v1/session", c.certAuth(c.handleSession))
	mux.Handle("GET /api/v1/overview", c.certAuth(c.handleOverview))
	mux.Handle("GET /api/v1/nodes", c.certAuth(c.handleNodes))
	mux.Handle("GET /api/v1/nodes/{id}", c.certAuth(c.handleNode))
	mux.Handle("GET /api/v1/sessions", c.certAuth(c.handleSessions))
	mux.Handle("GET /api/v1/fleet", c.certAuth(c.handleFleet))
	mux.Handle("GET /api/v1/policy", c.certAuth(c.handlePolicy))
	mux.Handle("GET /api/v1/audit", c.certAuth(c.handleAudit))
	mux.Handle("GET /api/v1/metrics/query", c.certAuth(c.handleMetricsQuery))
	mux.Handle("GET /api/v1/metrics/query_range", c.certAuth(c.handleMetricsQueryRange))
	mux.Handle("GET /api/v1/nodes/{id}/modules", c.certAuth(c.handleGetNodeModules))
	mux.Handle("GET /api/v1/nodes/{id}/cves", c.certAuth(c.handleNodeCVEs))
	mux.Handle("GET /api/v1/nodes/{id}/components", c.certAuth(c.handleNodeComponents))
	mux.Handle("GET /api/v1/vuln/feed", c.certAuth(c.handleVulnFeedStatus))
	mux.Handle("GET /api/v1/cves", c.certAuth(c.handleWorkspaceCVEs))
	mux.Handle("GET /api/v1/cves/{cve}/nodes", c.certAuth(c.handleNodesAffectedByCVE))
	mux.Handle("GET /api/v1/nodes/{id}/sbom", c.certAuth(c.handleNodeSBOMExport))
	mux.Handle("GET /api/v1/nodes/{id}/findings.vex", c.certAuth(c.handleNodeFindingsVEX))
	mux.Handle("POST /api/v1/nodes/{id}/sbom", c.certAuthAdmin(c.handleNodeSBOMIngest))
	mux.Handle("GET /api/v1/recordings", c.certAuth(c.handleRecordings))
	mux.Handle("GET /api/v1/recordings/{id}", c.certAuth(c.handleRecordingBlob))
	mux.Handle("POST /api/v1/tokens", c.certAuthAdmin(c.handleMintToken))
	mux.Handle("DELETE /api/v1/sessions/{id}", c.certAuthAdmin(c.handleRevokeSession))
	mux.Handle("POST /api/v1/nodes/{id}/approve", c.certAuthAdmin(c.handleApproveNode))
	mux.Handle("POST /api/v1/nodes/{id}/rebaseline", c.certAuthAdmin(c.handleRebaselineNode))
	mux.Handle("DELETE /api/v1/nodes/{id}", c.certAuthAdmin(c.handleRemoveNode))
	mux.Handle("PUT /api/v1/nodes/{id}/modules", c.certAuthAdmin(c.handleSetNodeModules))
	return secHeaders(mux)
}

// ---- handlers ----

// handleConfig is the anonymous SPA bootstrap: it advertises which login
// mechanisms the operator enabled so the login form renders the right cards
// (an SSO button, a local username/password form, and/or a keystone cloud
// dropdown). OIDC is optional now.
func (c *consoleAPI) handleConfig(w http.ResponseWriter, r *http.Request) {
	auth := map[string]any{
		"local":    c.s.cfg.localLoginEnabled(),
		"oidc":     nil,
		"keystone": []map[string]string{},
	}
	if c.s.cfg.oidcLoginEnabled() {
		auth["oidc"] = map[string]string{
			"issuer":      c.s.cfg.OIDC.Issuer,
			"clientId":    c.clientID,
			"redirectUri": c.extURL + "/",
		}
	}
	clouds := make([]map[string]string, 0)
	for _, kc := range c.s.cfg.consoleKeystoneClouds() {
		clouds = append(clouds, map[string]string{"cloud": kc.Cloud, "label": kc.label()})
	}
	auth["keystone"] = clouds
	writeJSON(w, map[string]any{
		"clusterName": c.s.cfg.ClusterName,
		"externalUrl": c.extURL,
		"auth":        auth,
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
			"distro": n.GetDistro(), "distroVersion": n.GetDistroVersion(),
			"osPretty": n.GetOsPretty(),
			"labels":   orEmptyMap(n.GetLabels()), "lastSeenUnix": n.GetLastSeenUnix(),
			"activeSessions": n.GetActiveSessions(), "detachedSessions": n.GetDetachedSessions(),
			"approved": n.GetApproved(), "overlayIp": n.GetOverlayIp(),
			"quarantineReason": n.GetQuarantineReason(),
		})
	}
	return out
}

// handleNodes lists the workspace's nodes. Filtering and sorting happen HERE,
// before paging — not in the browser over whatever page happened to arrive.
//
// The store orders nodes by id, so the first page is the 100 lowest ids, which
// correlates with nothing an operator cares about. With the filter applied client
// side, a fleet above one page could show an empty "Pending" tab while nodes were
// genuinely waiting for approval — and approval is the main thing that page is for.
func (c *consoleAPI) handleNodes(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	q := r.URL.Query()
	pg := pageParams(r)
	all := c.nodeJSON(u.Workspace)
	all = filterNodes(all, q.Get("q"), q.Get("state"))
	sortNodes(all, q.Get("sort"), q.Get("order"))
	total := len(all)
	lo, hi := pg.bounds(total)
	writeJSON(w, pageEnvelope("nodes", all[lo:hi], total, pg))
}

// handleNode returns ONE node by id or name. The console used to resolve a node
// detail page by fetching the node list and searching it, so node 101 rendered
// "Node not found." for a node that plainly exists.
func (c *consoleAPI) handleNode(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	id := r.PathValue("id")
	for _, n := range c.nodeJSON(u.Workspace) {
		if n["nodeId"] == id || n["name"] == id {
			writeJSON(w, n)
			return
		}
	}
	writeErr(w, http.StatusNotFound, "node not found")
}

// filterNodes applies the free-text and state filters the nodes view offers.
// search matches the name, id, and label values; state is one of
// online/offline/pending/quarantined/approved ("" or "all" keeps everything).
func filterNodes(nodes []map[string]any, search, state string) []map[string]any {
	q := strings.ToLower(strings.TrimSpace(search))
	state = strings.ToLower(strings.TrimSpace(state))
	if q == "" && (state == "" || state == "all") {
		return nodes
	}
	out := nodes[:0]
	for _, n := range nodes {
		if q != "" && !nodeMatchesSearch(n, q) {
			continue
		}
		if !nodeMatchesState(n, state) {
			continue
		}
		out = append(out, n)
	}
	return out
}

func nodeMatchesSearch(n map[string]any, q string) bool {
	for _, k := range []string{"name", "nodeId", "os", "osPretty", "distro"} {
		if v, _ := n[k].(string); strings.Contains(strings.ToLower(v), q) {
			return true
		}
	}
	if labels, ok := n["labels"].(map[string]string); ok {
		for k, v := range labels {
			if strings.Contains(strings.ToLower(k), q) || strings.Contains(strings.ToLower(v), q) {
				return true
			}
		}
	}
	return false
}

func nodeMatchesState(n map[string]any, state string) bool {
	online, _ := n["online"].(bool)
	approved, _ := n["approved"].(bool)
	quarantined, _ := n["quarantineReason"].(string)
	switch state {
	case "", "all":
		return true
	case "online":
		return online
	case "offline":
		return !online
	case "approved":
		return approved
	case "quarantined":
		return !approved && quarantined != ""
	case "pending":
		// Pending means "awaiting a first approval", which is NOT the same as
		// quarantined: QuarantineNode clears Approved too, so without excluding a
		// recorded cause a drift-quarantined host would sit in the approval queue
		// looking like a new arrival.
		return !approved && quarantined == ""
	default:
		return true
	}
}

// sortNodes orders the list. The default (name) is what an operator scanning a
// fleet expects; the store's id order is an implementation detail.
func sortNodes(nodes []map[string]any, sortKey, order string) {
	desc := strings.EqualFold(order, "desc")
	str := func(n map[string]any, k string) string {
		v, _ := n[k].(string)
		return strings.ToLower(v)
	}
	num := func(n map[string]any, k string) int64 {
		switch v := n[k].(type) {
		case int64:
			return v
		case int:
			return int64(v)
		case float64:
			return int64(v)
		}
		return 0
	}
	less := func(i, j int) bool { return str(nodes[i], "name") < str(nodes[j], "name") }
	switch strings.ToLower(strings.TrimSpace(sortKey)) {
	case "lastseen":
		less = func(i, j int) bool {
			return num(nodes[i], "lastSeenUnix") < num(nodes[j], "lastSeenUnix")
		}
	case "os":
		less = func(i, j int) bool { return str(nodes[i], "osPretty") < str(nodes[j], "osPretty") }
	case "sessions":
		less = func(i, j int) bool {
			return num(nodes[i], "activeSessions") < num(nodes[j], "activeSessions")
		}
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		if desc {
			return less(j, i)
		}
		return less(i, j)
	})
}

func (c *consoleAPI) handleSessions(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	q := r.URL.Query()
	pg := pageParams(r)
	sq := SessionQuery{
		State:  q.Get("state"),
		Search: q.Get("q"),
		Sort:   q.Get("sort"),
		Order:  q.Get("order"),
		Page:   pg,
	}
	// Match the CLI: a workspace admin sees the whole workspace, everyone else sees
	// only their own sessions. This applied no user filter at all, so a ws-viewer —
	// a role that cannot even read the vulnerability views — could enumerate every
	// session in the workspace, including who was on which host and when.
	if !u.Admin {
		sq.User = u.Name
	}
	all, total, err := c.s.store.QuerySessions(u.Workspace, sq)
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
	writeJSON(w, pageEnvelope("sessions", out, total, pg))
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
	// Cached: this handler is polled every 10s by any open dashboard, and an
	// uncached verify is a full-file HMAC rescan holding the audit append mutex.
	if n, err := c.s.audit.VerifyCached(); err == nil {
		count = n
	} else {
		chainOK = false
	}
	writeJSON(w, map[string]any{
		"nodes":    map[string]any{"total": len(nodes), "online": online},
		"sessions": map[string]any{"active": active, "detached": detached, "total": len(sessions)},
		"versions": map[string]any{"stable": stable, "canary": canary},
		"audit":    map[string]any{"count": count, "chainOk": chainOK},
		// Relays are cluster infrastructure, not workspace-scoped — they live in
		// the cluster-operator console, not the tenant overview.
	})
}

// handlePolicy returns the CALLER'S WORKSPACE policy from the durable store (the
// per-tenant source of truth) as both raw YAML (for the editor) and a parsed
// structure (for a structured view), plus edit provenance and whether this
// caller may edit it (ws-admin).
func (c *consoleAPI) handlePolicy(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	ws := u.Workspace
	if ws == "" {
		ws = defaultWorkspace
	}
	doc, meta, err := c.s.GetWorkspacePolicy(ws)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "read policy")
		return
	}
	var parsed map[string]any
	_ = yaml.Unmarshal(doc, &parsed)
	writeJSON(w, map[string]any{
		"workspace":   ws,
		"yaml":        string(doc),
		"policy":      normalizeYAML(parsed),
		"updatedBy":   meta.UpdatedBy,
		"updatedUnix": meta.UpdatedUnix,
		"editable":    u.Admin,
	})
}

// handleSetPolicy persists a new policy document for the caller's workspace
// (ws-admin only) and hot-swaps the live engine. The body is validated against
// the real policy parser; a parse error returns 400 with the message so the
// editor can surface it, and neither the store nor the live engine changes.
// policyMaxBytes caps a submitted policy document, matching the 64 KiB the other
// console writes use.
const policyMaxBytes = 1 << 16

func (c *consoleAPI) handleSetPolicy(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	ws := u.Workspace
	if ws == "" {
		ws = defaultWorkspace
	}
	var req struct {
		Yaml string `json:"yaml"`
	}
	// Cap the body like every sibling write does (/members, /nodes/{id}/modules).
	// A policy document is a few KiB; an uncapped decode is an unauthenticated-size
	// allocation on an authenticated route, which is a needless asymmetry.
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, policyMaxBytes)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request body")
		return
	}
	if strings.TrimSpace(req.Yaml) == "" {
		writeErr(w, http.StatusBadRequest, "policy document is empty")
		return
	}
	if err := c.s.SetWorkspacePolicy(ws, []byte(req.Yaml), "console:"+u.Name); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "workspace": ws})
}

// handlePolicyHistory returns the retained previous revisions of the workspace's
// policy, newest first, so an admin can diff against what is live and restore a
// known-good document. The store overwrites a single settings key, so without this
// an edit to the document that decides who may reach what was unrecoverable.
func (c *consoleAPI) handlePolicyHistory(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	ws := u.Workspace
	if ws == "" {
		ws = defaultWorkspace
	}
	hist, err := getWorkspacePolicyHistory(c.s.store, ws)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "read policy history")
		return
	}
	out := make([]map[string]any, 0, len(hist))
	for _, h := range hist {
		out = append(out, map[string]any{
			"yaml": h.Doc, "updatedBy": h.UpdatedBy, "updatedUnix": h.UpdatedUnix,
		})
	}
	writeJSON(w, map[string]any{"revisions": out})
}

// handleValidatePolicy parses a candidate policy document without persisting it,
// so the editor can validate live. Always 200; {valid, error} is in the body
// (an invalid policy is a normal editor state, not an HTTP error).
func (c *consoleAPI) handleValidatePolicy(w http.ResponseWriter, r *http.Request, _ *consoleUser) {
	var req struct {
		Yaml string `json:"yaml"`
	}
	// The validate endpoint is only c.auth-gated (any member may lint a document),
	// so its cap matters more than the writer's, not less.
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, policyMaxBytes)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request body")
		return
	}
	if _, err := policy.Parse([]byte(req.Yaml)); err != nil {
		writeJSON(w, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	// Return the parsed structure from the authoritative parser so the editor can
	// render a live preview without a client-side YAML parser.
	var parsed map[string]any
	_ = yaml.Unmarshal([]byte(req.Yaml), &parsed)
	writeJSON(w, map[string]any{"valid": true, "policy": normalizeYAML(parsed)})
}

// handleRenderPolicy is the inverse of handleValidatePolicy: it takes the policy
// STRUCTURE the visual editor produced and returns the canonical YAML document,
// validated through the same authoritative parser that will store it.
//
// Both directions live on the server on purpose. The console ships no YAML parser
// or emitter, so a visual editor that serialized in the browser would be a second,
// subtly-different implementation of the policy schema — and the one place that
// must never drift is the document that decides who may reach what.
func (c *consoleAPI) handleRenderPolicy(w http.ResponseWriter, r *http.Request, _ *consoleUser) {
	var req struct {
		Policy map[string]any `json:"policy"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, policyMaxBytes)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request body")
		return
	}
	if len(req.Policy) == 0 {
		writeErr(w, http.StatusBadRequest, "policy is empty")
		return
	}
	doc, err := yaml.Marshal(req.Policy)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "render policy: "+err.Error())
		return
	}
	// Round-trip through the real parser. An invalid structure is a normal editor
	// state, so it comes back as {valid:false} with the rendering, not as an error:
	// the operator still needs to see (and fix) what they built.
	if _, perr := policy.Parse(doc); perr != nil {
		writeJSON(w, map[string]any{"valid": false, "error": perr.Error(), "yaml": string(doc)})
		return
	}
	writeJSON(w, map[string]any{"valid": true, "yaml": string(doc)})
}

// handleAudit serves a page of the workspace's audit records.
//
// It takes until + offset as well as since, and returns the matched total, so the
// log is actually walkable. Before this the query kept the TAIL of the matches
// with no cursor, which meant the newest N records counting back from now were
// all a console user could ever reach: narrowing `since` could not move the window
// backwards, because the tail of a longer window is the same tail.
func (c *consoleAPI) handleAudit(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	q := r.URL.Query()
	since, _ := strconv.ParseInt(q.Get("since"), 10, 64)
	until, _ := strconv.ParseInt(q.Get("until"), 10, 64)
	pg := pageParams(r)
	limit, offset := pg.normalize()

	// Force-filter to the caller's workspace: a tenant admin sees only their own
	// tenant's events, never another tenant's or cluster-scoped ones.
	page, err := c.s.audit.QueryPage(AuditQuery{
		SinceUnix: since,
		UntilUnix: until,
		Type:      q.Get("type"),
		Actor:     q.Get("actor"),
		Node:      q.Get("node"),
		Workspace: u.Workspace,
		Limit:     limit,
		Offset:    offset,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query audit")
		return
	}

	// ?format=jsonl streams the matched window as newline-delimited JSON, which is
	// what an operator hands to a SIEM or keeps as evidence. The records are the
	// verbatim chain lines, so their HMACs still verify outside this console.
	if strings.EqualFold(q.Get("format"), "jsonl") {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="audit.jsonl"`)
		for _, l := range page.Lines {
			_, _ = w.Write(l)
			_, _ = w.Write([]byte("\n"))
		}
		return
	}

	recs := make([]json.RawMessage, 0, len(page.Lines))
	for _, l := range page.Lines {
		recs = append(recs, json.RawMessage(l))
	}
	writeJSON(w, map[string]any{
		"records": recs,
		"chainOk": page.ChainOK,
		"total":   page.Total,
		"limit":   limit,
		"offset":  offset,
	})
}

func (c *consoleAPI) handleMintToken(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	var req struct {
		TTLSeconds  int64             `json:"ttlSeconds"`
		Labels      map[string]string `json:"labels"`
		MaxUses     int32             `json:"maxUses"`
		AutoApprove bool              `json:"autoApprove"`
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
	if err := c.s.store.PutToken(token, &TokenRecord{
		WorkspaceID: u.Workspace, Labels: req.Labels, ExpiresUnix: expires,
		MaxUses: req.MaxUses, AutoApprove: req.AutoApprove,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "store token")
		return
	}
	_ = c.s.audit.AppendWS(u.Workspace, "token_create", "console:"+u.Name, "", "", map[string]string{
		"ttl_seconds":  strconv.FormatInt(int64(ttl/time.Second), 10),
		"max_uses":     strconv.FormatInt(int64(req.MaxUses), 10),
		"auto_approve": boolStr(req.AutoApprove),
	})

	out := map[string]any{"token": token, "expiresUnix": expires, "autoApprove": req.AutoApprove}
	// The raw token is NOT what install.sh takes. Hand back the encoded
	// enrollment code and the finished one-liner as well, or a console user
	// pastes the token, gets "unknown argument", and has no way to discover the
	// right shape — the CLI's `geneza node enroll` was the only thing that
	// produced it. The code binds the token to the pinned root fingerprint and
	// the runtime endpoints, which is what makes curl|sh verifiable rather than
	// blind.
	if fp := c.s.rootFingerprint(); fp != "" {
		// The fetch base is the public front (publicly-trusted TLS, so curl on a
		// bare host trusts it); an unset console.external_url leaves it empty, and
		// emitting "curl -fsSL /install.sh" would be worse than emitting nothing —
		// so fall back to the controller's own runtime base like the CLI does.
		base := c.s.consoleExternalURL()
		if base == "" {
			base = c.s.controllerRuntimeBase()
		}
		out["enrollCode"] = enrollcode.Encode(enrollcode.Fields{
			Token:   token,
			RootFP:  fp,
			HTTP:    base,
			Runtime: c.s.controllerRuntimeBase(),
			GRPC:    c.s.controllerGRPCEndpoint(),
		})
		// Only advertise the one-liner when this controller actually serves
		// /install.sh. rootFingerprint() is non-empty for every release build (it
		// falls back to the compiled-in root), so it alone does not imply an
		// installer: with install_dir unset the URL 404s, or worse, an SPA catch-all
		// answers it with index.html and HTTP 200 — HTML piped into sudo sh.
		if c.s.cfg.InstallDir != "" && base != "" {
			out["installCommand"] = fmt.Sprintf("curl -fsSL %s/install.sh | sudo sh -s -- %s", base, out["enrollCode"])
		}
	}
	writeJSON(w, out)
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
// handleRebaselineNode blesses the binary a node is currently running.
//
// It is a SEPARATE action from approve on purpose. Approve cannot resolve a
// binary-drift quarantine — the baseline is preserved across it — so offering
// only approve is what makes the console appear to fix the node for one sweep
// and then silently re-quarantine it.
func (c *consoleAPI) handleRebaselineNode(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	var body struct {
		Reason     string `json:"reason"`
		ExpectHash string `json:"expectHash"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body)
	hash, approved, err := c.s.rebaselineNode(u.Workspace, r.PathValue("id"), body.Reason, body.ExpectHash, "console:"+u.Name)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			writeErr(w, http.StatusNotFound, "node not found")
		case errors.Is(err, errRebaselineReason), errors.Is(err, errNoMeasurement), errors.Is(err, errMeasurementChanged):
			writeErr(w, http.StatusBadRequest, err.Error())
		default:
			writeErr(w, http.StatusInternalServerError, "rebaseline")
		}
		return
	}
	writeJSON(w, map[string]any{"ok": true, "binaryHash": hash, "approved": approved})
}

func (c *consoleAPI) handleApproveNode(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	id := r.PathValue("id")
	node, err := c.s.store.FindNode(u.Workspace, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}
	var body struct {
		Approve bool   `json:"approve"`
		Reason  string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	by := "console:" + u.Name
	// Route through the same central entrypoint as the gRPC ClusterAPI so a console
	// deny writes the quarantine cause-row + revokes sessions, and a console
	// re-approval of a quarantined node still requires a recorded reason.
	if err := c.s.approveNodeWithReason(u.Workspace, node, body.Approve, body.Reason, by); err != nil {
		if errors.Is(err, errReasonRequired) {
			writeErr(w, http.StatusBadRequest, "a reason is required to re-approve a quarantined node")
			return
		}
		writeErr(w, http.StatusInternalServerError, "set approval")
		return
	}
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
	_ = c.s.audit.AppendWS(u.Workspace, "node_remove", "console:"+u.Name, node.ID, "", map[string]string{"name": node.Name})
	c.s.repushAllNetworks(u.Workspace) // symmetric teardown across co-members
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
	if strings.HasPrefix(r.URL.Path, embedPathPrefix) {
		c.embedFramingHeaders(w, r)
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
	if !s.cfg.ConsoleEnabled() || s.console == nil {
		return nil, nil
	}
	return &http.Server{
		Addr:              s.cfg.Console.Listen,
		Handler:           s.console.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}, nil
}

// controllerRuntimeBase and controllerGRPCEndpoint are the addresses an ENROLLING
// agent uses at runtime, as opposed to the public front it fetches the installer
// over. They differ on purpose: the fetch rides the ACME proxy so a bare `curl`
// trusts it, while the agent afterwards talks to this controller's own listeners
// and verifies them against the pinned Geneza CA roots — a different authority.
// Both prefer the first routable advertised DNS name, which is what the
// certificate covers; an IP-only advertise falls back to the first routable IP.
//
// Loopback entries are skipped while any routable one remains. This host is
// handed to REMOTE parties — it is embedded in every enrollment code the console
// mints — so "localhost" resolves on the wrong machine and enrollment fails with
// a connection refused that looks like the controller is down. `advertise`
// conventionally lists localhost for on-host use, so preferring the routable
// entry (rather than trusting the order) is what callers actually mean.
func (s *Server) advertisedHost() string {
	if h := firstRoutableHost(s.cfg.Advertise.DNSNames); h != "" {
		return h
	}
	if h := firstRoutableHost(s.cfg.Advertise.IPs); h != "" {
		return h
	}
	// Nothing routable advertised (a purely local lab): fall back to the declared
	// order rather than returning nothing, so on-host flows still work.
	if len(s.cfg.Advertise.DNSNames) > 0 {
		return s.cfg.Advertise.DNSNames[0]
	}
	if len(s.cfg.Advertise.IPs) > 0 {
		return s.cfg.Advertise.IPs[0]
	}
	return ""
}

// firstRoutableHost returns the first entry that a remote host could actually
// reach — i.e. not "localhost" and not a loopback literal.
func firstRoutableHost(hosts []string) string {
	for _, h := range hosts {
		if h == "" || strings.EqualFold(h, "localhost") {
			continue
		}
		if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
			continue
		}
		return h
	}
	return ""
}

func (s *Server) controllerRuntimeBase() string {
	host := s.advertisedHost()
	if host == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(s.cfg.HTTPListen)
	if err != nil || port == "" {
		port = "7402"
	}
	return "https://" + net.JoinHostPort(host, port)
}

func (s *Server) controllerGRPCEndpoint() string {
	host := s.advertisedHost()
	if host == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(s.cfg.GRPCListen)
	if err != nil || port == "" {
		port = "7401"
	}
	return net.JoinHostPort(host, port)
}
