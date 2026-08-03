package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Hosted-UI launch tests (docs/hosted-ui-launch-spec.md). These cover the
// properties the design is load-bearing on: a launch cannot be widened into a
// console session, cannot address a second node, cannot reach another project's
// VM, and cannot be spent twice.

const launchPolicyDoc = `
roles:
  ws-admin:
    allow:
      - actions: ["*"]
        node_labels: {"*": "*"}
  ws-viewer:
    allow:
      - actions: [shell]
        node_labels: {"*": "*"}
  natonly:
    allow:
      - actions: [shell]
        node_labels: {tier: prod}
        require_native: true
bindings: []
`

// buildLaunchServer makes a server with one launch-enabled cloud, a fake
// keystone verifier, and a bound project -> workspace.
func buildLaunchServer(t *testing.T, embed EmbedConfig) (*Server, *consoleAPI, *fakeVerifier) {
	t.Helper()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(launchPolicyDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		DataDir:                 filepath.Join(dir, "data"),
		ClusterName:             "t",
		RelayAddrs:              []string{"127.0.0.1:7403"},
		PolicyFile:              policyPath,
		AutoProvisionPolicyFile: policyPath,
		Clouds: map[string]CloudConfig{
			"kolla1": {
				Kind: "openstack", KeystoneURL: "https://k.example/v3",
				AllowHumanAutoProvision: true,
				RoleMap:                 map[string]string{"admin": roleWSAdmin, "member": "ws-viewer"},
				DefaultRole:             "ws-viewer",
				Launch: LaunchConfig{
					Allow: true, Actions: []string{"shell"}, Embed: embed,
				},
			},
		},
	}
	cfg.Console.ExternalURL = "https://console.example"
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	if err := InitDataDir(cfg); err != nil {
		t.Fatalf("init: %v", err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	fake := &fakeVerifier{}
	srv.clouds["kolla1"] = fake
	api, err := srv.newConsoleAPI()
	if err != nil {
		t.Fatalf("console api: %v", err)
	}
	return srv, api, fake
}

// keystoneCaller is a clean, project-scoped human token for the fake verifier.
func keystoneCaller(user, project string, roles ...string) osCaller {
	if len(roles) == 0 {
		roles = []string{"member"}
	}
	return osCaller{
		UserName: user, UserID: "ks-" + user, ProjectID: project,
		ProjectName: "team-" + project, ScopeProject: true, Roles: roles,
		ExpiresAt: time.Now().Add(time.Hour), TokenID: "gAAAA-" + user,
	}
}

// seedLaunchNode registers an enrolled OpenStack VM in ws with the TRUSTED
// enrollment labels the launch resolver keys on.
func seedLaunchNode(t *testing.T, srv *Server, ws, nodeID, instance, project string, extra map[string]string) {
	t.Helper()
	labels := map[string]string{launchInstanceLabel: instance, launchProjectLabel: project}
	for k, v := range extra {
		labels[k] = v
	}
	if err := srv.store.PutNode(ws, &NodeRecord{
		ID: nodeID, Name: nodeID, WorkspaceID: ws, Labels: labels, Approved: true,
	}); err != nil {
		t.Fatalf("put node: %v", err)
	}
}

// mintLaunch drives the portal's server-to-server call and returns the response.
func mintLaunch(t *testing.T, h http.Handler, body string) (int, map[string]any) {
	t.Helper()
	return doJSON(t, h, "POST", "/openstack/kolla1/launch", "", body)
}

// codeFromLaunchURL pulls the single-use code out of the URL fragment.
func codeFromLaunchURL(t *testing.T, launchURL string) string {
	t.Helper()
	i := strings.Index(launchURL, "#lc=")
	if i < 0 {
		t.Fatalf("launch url carries no fragment code: %q", launchURL)
	}
	return launchURL[i+len("#lc="):]
}

// redeemLaunch swaps a code (+ any companion cookie) for the scoped session token.
func redeemLaunch(t *testing.T, h http.Handler, code, origin string, cookies ...*http.Cookie) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/session/launch", strings.NewReader(`{"code":"`+code+`"}`))
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

// bindLaunch drives stage one of the TOP-LEVEL flow: GET the bind endpoint,
// which burns the portal's code and returns the browser-facing code (in the
// redirect fragment) plus its companion cookie.
func bindLaunch(t *testing.T, h http.Handler, launchURL string) (string, *http.Cookie) {
	t.Helper()
	i := strings.Index(launchURL, "/launch?")
	if i < 0 {
		t.Fatalf("not a top-level launch url: %q", launchURL)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", launchURL[i:], nil))
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("bind: want 303, got %d (%s)", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	var cookie *http.Cookie
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == launchCookie {
			cookie = ck
		}
	}
	if cookie == nil {
		t.Fatalf("bind set no companion cookie")
	}
	return codeFromLaunchURL(t, loc), cookie
}

// launchSession runs the whole TOP-LEVEL flow (mint -> bind -> redeem) and
// returns the scoped session token.
func launchSession(t *testing.T, srv *Server, api *consoleAPI, fake *fakeVerifier, user, project, instance string, roles ...string) string {
	t.Helper()
	h := api.handler()
	fake.session = &fakeSession{caller: keystoneCaller(user, project, roles...)}
	code, resp := mintLaunch(t, h, `{"token":"gAAAA-`+user+`","instance_id":"`+instance+`"}`)
	if code != 200 {
		t.Fatalf("mint: %d %v", code, resp)
	}
	browserCode, cookie := bindLaunch(t, h, resp["launch_url"].(string))
	rc, rresp := redeemLaunch(t, h, browserCode, "https://console.example", cookie)
	if rc != 200 {
		t.Fatalf("redeem: %d %v", rc, rresp)
	}
	return rresp["token"].(string)
}

// The happy path, and the two things that must be true about the URL itself:
// the keystone token never appears in it, and the code rides the fragment.
func TestLaunchMintAndRedeem(t *testing.T) {
	srv, api, fake := buildLaunchServer(t, EmbedConfig{})
	h := api.handler()
	fake.session = &fakeSession{caller: keystoneCaller("alice", "proj-a")}

	// Bind the project by letting the first human auto-provision the workspace.
	code, resp := mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	if code != http.StatusNotFound {
		t.Fatalf("no node yet: want 404, got %d %v", code, resp)
	}
	ws := launchWorkspace(t, srv, "proj-a")
	seedLaunchNode(t, srv, ws, "n-1", "i-1", "proj-a", nil)

	code, resp = mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	if code != 200 {
		t.Fatalf("mint: %d %v", code, resp)
	}
	launchURL := resp["launch_url"].(string)
	if strings.Contains(launchURL, "gAAAA") {
		t.Fatalf("keystone token leaked into the launch url: %q", launchURL)
	}
	if resp["node_id"] != "n-1" {
		t.Fatalf("resolved wrong node: %v", resp["node_id"])
	}

	// Stage one hands the browser a DIFFERENT code, in the fragment, plus the
	// companion cookie — so neither secret alone is enough from here on.
	browserCode, cookie := bindLaunch(t, h, launchURL)
	if strings.Contains(launchURL, browserCode) {
		t.Fatalf("the browser-facing code must not be the portal's code")
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("launch cookie is not hardened: %+v", cookie)
	}

	rc, rresp := redeemLaunch(t, h, browserCode, "https://console.example", cookie)
	if rc != 200 {
		t.Fatalf("redeem: %d %v", rc, rresp)
	}
	if rresp["token"] == nil || rresp["token"] == "" {
		t.Fatalf("redeem returned no session token: %v", rresp)
	}
	scope, _ := rresp["scope"].(map[string]any)
	if scope == nil || scope["nodeId"] != "n-1" {
		t.Fatalf("session is not node-scoped: %v", rresp)
	}
}

// The top-level flow's second secret: the fragment code alone is not enough, and
// an unbound portal code cannot be spent straight at the redeem endpoint.
func TestTopLevelLaunchRequiresTheCompanionCookie(t *testing.T) {
	srv, api, fake := buildLaunchServer(t, EmbedConfig{})
	h := api.handler()
	fake.session = &fakeSession{caller: keystoneCaller("alice", "proj-a")}
	_, _ = mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	ws := launchWorkspace(t, srv, "proj-a")
	seedLaunchNode(t, srv, ws, "n-1", "i-1", "proj-a", nil)

	// The portal's code must NOT be redeemable directly — it is awaiting a bind.
	_, resp := mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	portalURL := resp["launch_url"].(string)
	portalCode := portalURL[strings.Index(portalURL, "lt=")+len("lt="):]
	if c, _ := redeemLaunch(t, h, portalCode, "https://console.example"); c != http.StatusUnauthorized {
		t.Fatalf("an unbound top-level ticket must not be redeemable, got %d", c)
	}

	// After binding, the fragment code alone is refused; with the cookie it works.
	_, resp = mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	browserCode, cookie := bindLaunch(t, h, resp["launch_url"].(string))
	if c, _ := redeemLaunch(t, h, browserCode, "https://console.example"); c != http.StatusUnauthorized {
		t.Fatalf("fragment code without the cookie must be refused, got %d", c)
	}
	// That attempt burned the code, so a fresh one is needed to prove the pair works.
	_, resp = mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	browserCode, cookie = bindLaunch(t, h, resp["launch_url"].(string))
	if c, _ := redeemLaunch(t, h, browserCode, "https://console.example", cookie); c != 200 {
		t.Fatalf("code + cookie must succeed, got %d", c)
	}
	// A wrong cookie is refused.
	_, resp = mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	browserCode, _ = bindLaunch(t, h, resp["launch_url"].(string))
	bad := &http.Cookie{Name: launchCookie, Value: "not-the-secret"}
	if c, _ := redeemLaunch(t, h, browserCode, "https://console.example", bad); c != http.StatusUnauthorized {
		t.Fatalf("a wrong cookie must be refused, got %d", c)
	}
}

// The bind step is single-use: a leaked portal code (it does ride a query string
// and therefore an access log) is dead once the tenant's browser has used it.
func TestLaunchBindIsSingleUse(t *testing.T) {
	srv, api, fake := buildLaunchServer(t, EmbedConfig{})
	h := api.handler()
	fake.session = &fakeSession{caller: keystoneCaller("alice", "proj-a")}
	_, _ = mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	ws := launchWorkspace(t, srv, "proj-a")
	seedLaunchNode(t, srv, ws, "n-1", "i-1", "proj-a", nil)

	_, resp := mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	launchURL := resp["launch_url"].(string)
	_, _ = bindLaunch(t, h, launchURL)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", launchURL[strings.Index(launchURL, "/launch?"):], nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("replayed bind must be refused, got %d", rr.Code)
	}
}

// An embed launch is cookieless by necessity (a framed page may not be able to
// set a third-party cookie), and goes straight to the fragment.
func TestEmbedLaunchIsCookieless(t *testing.T) {
	srv, api, fake := buildLaunchServer(t, EmbedConfig{
		Allow: true, FrameAncestors: []string{"https://horizon.example.com"},
	})
	h := api.handler()
	fake.session = &fakeSession{caller: keystoneCaller("alice", "proj-a")}
	_, _ = mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	ws := launchWorkspace(t, srv, "proj-a")
	seedLaunchNode(t, srv, ws, "n-1", "i-1", "proj-a", nil)

	_, resp := mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1","embed":true}`)
	launchURL := resp["launch_url"].(string)
	if !strings.Contains(launchURL, "#lc=") {
		t.Fatalf("an embed launch must go straight to the fragment: %q", launchURL)
	}
	if q := strings.SplitN(launchURL, "#", 2)[0]; strings.Contains(q, "lc=") {
		t.Fatalf("launch code appears in the query string: %q", launchURL)
	}
	if c, _ := redeemLaunch(t, h, codeFromLaunchURL(t, launchURL), "https://console.example"); c != 200 {
		t.Fatalf("embed redeem must work without a cookie, got %d", c)
	}
}

// Renewal slides the idle window forward but can never pass the absolute
// ceiling, and stops entirely once authorization is withdrawn.
func TestLaunchSessionRenewal(t *testing.T) {
	srv, api, fake := buildLaunchServer(t, EmbedConfig{})
	h := api.handler()
	fake.session = &fakeSession{caller: keystoneCaller("alice", "proj-a")}
	_, _ = mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	ws := launchWorkspace(t, srv, "proj-a")
	seedLaunchNode(t, srv, ws, "n-1", "i-1", "proj-a", nil)
	tok := launchSession(t, srv, api, fake, "alice", "proj-a", "i-1")

	before, err := srv.store.GetAuthSession(hashToken(tok))
	if err != nil {
		t.Fatal(err)
	}
	if before.MaxExpiresUnix == 0 {
		t.Fatalf("a launch session must carry an absolute ceiling")
	}

	// Wind the expiry back so a renewal has something to extend.
	before.ExpiresUnix = time.Now().Add(time.Minute).Unix()
	if err := srv.store.PutAuthSession(before); err != nil {
		t.Fatal(err)
	}
	code, resp := doJSON(t, h, "POST", "/api/v1/session/renew", tok, "")
	if code != 200 {
		t.Fatalf("renew: %d %v", code, resp)
	}
	after, _ := srv.store.GetAuthSession(hashToken(tok))
	if after.ExpiresUnix <= before.ExpiresUnix {
		t.Fatalf("renew did not extend: %d -> %d", before.ExpiresUnix, after.ExpiresUnix)
	}
	if after.ExpiresUnix > after.MaxExpiresUnix {
		t.Fatalf("renew slid past the absolute ceiling: %d > %d", after.ExpiresUnix, after.MaxExpiresUnix)
	}

	// At the ceiling, renewal stops extending rather than running away.
	at := after
	at.ExpiresUnix = at.MaxExpiresUnix
	if err := srv.store.PutAuthSession(at); err != nil {
		t.Fatal(err)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/session/renew", tok, ""); code != 200 {
		t.Fatalf("renew at the ceiling should be a no-op, not an error: %d", code)
	}
	capped, _ := srv.store.GetAuthSession(hashToken(tok))
	if capped.ExpiresUnix != capped.MaxExpiresUnix {
		t.Fatalf("renew must not pass the ceiling: %d vs %d", capped.ExpiresUnix, capped.MaxExpiresUnix)
	}

	// A suspended principal cannot renew: revocation beats a live timer.
	if err := srv.store.SuspendPrincipal(capped.Workspace, capped.Provider, capped.Subject,
		capped.User, "test", "renewal must re-check authorization"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/session/renew", tok, ""); code == 200 {
		t.Fatalf("a suspended principal must not be able to renew")
	}
}

// An ordinary console session is not renewable — renewal exists for the launch
// plane and must not become a way to extend a full console session forever.
func TestOrdinaryConsoleSessionDoesNotRenew(t *testing.T) {
	srv, _, _ := buildLaunchServer(t, EmbedConfig{})
	tok, rec, err := srv.mintAuthSession(sessionInput{
		Provider: providerLocal, User: "op", Subject: "op",
		Workspace: defaultWorkspace, Roles: []string{roleWSAdmin},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.MaxExpiresUnix != 0 {
		t.Fatalf("an unscoped session must carry no renewal ceiling")
	}
	if _, err := srv.renewSession(hashToken(tok), time.Hour); err == nil {
		t.Fatalf("an unscoped session must not be renewable")
	}
}

// A launch session must be refused by the console API — every route that has not
// explicitly opted in, INCLUDING ones the caller's roles would otherwise permit.
func TestLaunchSessionIsRefusedByConsoleAPI(t *testing.T) {
	srv, api, fake := buildLaunchServer(t, EmbedConfig{})
	h := api.handler()
	// alice is a keystone admin -> ws-admin. Even so, her launch session must
	// have no console reach at all.
	fake.session = &fakeSession{caller: keystoneCaller("alice", "proj-a", "admin")}
	_, _ = mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	ws := launchWorkspace(t, srv, "proj-a")
	seedLaunchNode(t, srv, ws, "n-1", "i-1", "proj-a", nil)
	tok := launchSession(t, srv, api, fake, "alice", "proj-a", "i-1", "admin")

	for _, route := range []struct{ method, path string }{
		{"GET", "/api/v1/nodes"},
		{"GET", "/api/v1/overview"},
		{"GET", "/api/v1/audit"},
		{"GET", "/api/v1/policy"},
		{"PUT", "/api/v1/policy"},
		{"GET", "/api/v1/sessions"},
		{"GET", "/api/v1/recordings"},
		{"POST", "/api/v1/tokens"},
		{"GET", "/api/v1/members"},
		{"GET", "/api/v1/cves"},
		{"POST", "/api/v1/nodes/n-1/approve"},
		{"DELETE", "/api/v1/nodes/n-1"},
	} {
		code, _ := doJSON(t, h, route.method, route.path, tok, `{}`)
		if code != http.StatusForbidden {
			t.Errorf("%s %s: a scoped launch session must be refused (403), got %d", route.method, route.path, code)
		}
	}

	// And it is never a console admin, even though alice maps to ws-admin.
	code, me := doJSON(t, h, "GET", "/api/v1/session", tok, "")
	if code != 200 {
		t.Fatalf("session probe: %d %v", code, me)
	}
	if me["admin"] != false {
		t.Fatalf("a launch session must never be admin (alice is ws-admin): %v", me)
	}
}

// The node pin: a scoped session may not address a second node, even one it is
// entitled to reach through the ordinary console.
func TestLaunchSessionCannotAddressAnotherNode(t *testing.T) {
	srv, api, fake := buildLaunchServer(t, EmbedConfig{})
	h := api.handler()
	fake.session = &fakeSession{caller: keystoneCaller("alice", "proj-a")}
	_, _ = mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	ws := launchWorkspace(t, srv, "proj-a")
	seedLaunchNode(t, srv, ws, "n-1", "i-1", "proj-a", nil)
	seedLaunchNode(t, srv, ws, "n-2", "i-2", "proj-a", nil)

	tok := launchSession(t, srv, api, fake, "alice", "proj-a", "i-1")

	code, _ := doJSON(t, h, "POST", "/api/v1/nodes/n-2/shell-ticket", tok, `{}`)
	if code != http.StatusForbidden {
		t.Fatalf("shell-ticket on an unscoped node must be 403, got %d", code)
	}
	// The pinned node still works (the ticket mint itself is allowed).
	code, resp := doJSON(t, h, "POST", "/api/v1/nodes/n-1/shell-ticket", tok, `{}`)
	if code != 200 || resp["ticket"] == nil {
		t.Fatalf("shell-ticket on the scoped node must succeed, got %d %v", code, resp)
	}
}

// Cross-project isolation: a workspace may bind MANY projects, so "in my
// workspace" is strictly weaker than "in my project". The os:project label check
// is what stops one tenant reaching a co-bound tenant's VM.
func TestLaunchRefusesInstanceInAnotherProject(t *testing.T) {
	srv, api, fake := buildLaunchServer(t, EmbedConfig{})
	h := api.handler()
	fake.session = &fakeSession{caller: keystoneCaller("alice", "proj-a")}
	_, _ = mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	ws := launchWorkspace(t, srv, "proj-a")
	// A VM co-bound into the SAME workspace but owned by another project.
	seedLaunchNode(t, srv, ws, "n-other", "i-other", "proj-b", nil)

	code, resp := mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-other"}`)
	if code != http.StatusNotFound {
		t.Fatalf("cross-project instance must not resolve, got %d %v", code, resp)
	}
	if _, err := srv.resolveLaunchNode(ws, "proj-a", "i-other"); err == nil {
		t.Fatalf("resolveLaunchNode must reject a node whose os:project differs")
	}
}

// A launch code is single-use and burns on any redeem attempt.
func TestLaunchCodeIsSingleUse(t *testing.T) {
	srv, api, fake := buildLaunchServer(t, EmbedConfig{})
	h := api.handler()
	fake.session = &fakeSession{caller: keystoneCaller("alice", "proj-a")}
	_, _ = mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	ws := launchWorkspace(t, srv, "proj-a")
	seedLaunchNode(t, srv, ws, "n-1", "i-1", "proj-a", nil)

	_, resp := mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	code, cookie := bindLaunch(t, h, resp["launch_url"].(string))

	if c, _ := redeemLaunch(t, h, code, "https://console.example", cookie); c != 200 {
		t.Fatalf("first redeem must succeed, got %d", c)
	}
	if c, _ := redeemLaunch(t, h, code, "https://console.example", cookie); c != http.StatusUnauthorized {
		t.Fatalf("replayed launch code must be refused, got %d", c)
	}
	// A foreign origin cannot spend a code at all, cookie or not.
	_, resp2 := mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	code2, cookie2 := bindLaunch(t, h, resp2["launch_url"].(string))
	if c, _ := redeemLaunch(t, h, code2, "https://evil.example", cookie2); c != http.StatusForbidden {
		t.Fatalf("cross-origin redeem must be refused, got %d", c)
	}
}

// The two ticket kinds are mutually exclusive: a cookie-bound trusted-dashboard
// handoff must not be spendable through the cookieless launch path (that would
// silently drop its second secret), and vice versa.
func TestHandoffAndLaunchTicketsAreDisjoint(t *testing.T) {
	srv, _, _ := buildLaunchServer(t, EmbedConfig{})
	in := sessionInput{Provider: providerKeystone, User: "alice", Workspace: defaultWorkspace, Roles: []string{"ws-viewer"}}

	// A cookie-bound handoff redeemed as a launch: refused.
	if err := srv.store.PutHandoff(&HandoffRecord{
		CodeHash: hashToken("code-a"), CookieHash: hashToken("cookie-a"),
		Session: in, ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.store.RedeemLaunch("code-a", "cookie-a", time.Now().Unix()); err == nil {
		t.Fatalf("a plain handoff must not be redeemable as a launch ticket, even with its cookie")
	}

	// A cookieless launch ticket redeemed as a handoff: refused.
	scoped := in
	scoped.Scope = &SessionScope{NodeID: "n-1", Actions: []string{"shell"}}
	if err := srv.store.PutHandoff(&HandoffRecord{
		CodeHash: hashToken("code-b"), Session: scoped,
		ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.store.RedeemHandoff("code-b", "", time.Now().Unix()); err == nil {
		t.Fatalf("a cookieless launch ticket must not be redeemable as a handoff")
	}

	// The sharp one: a BOUND launch ticket carries a cookie just like a handoff
	// does, so discriminating on the cookie would let it through here — and the
	// handoff path mints an UNSCOPED session, silently turning a one-node launch
	// into a full console. The scope must be what tells them apart.
	if err := srv.store.PutHandoff(&HandoffRecord{
		CodeHash: hashToken("code-c"), CookieHash: hashToken("cookie-c"),
		Session: scoped, ExpiresUnix: time.Now().Add(time.Minute).Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.store.RedeemHandoff("code-c", "cookie-c", time.Now().Unix()); err == nil {
		t.Fatalf("a BOUND launch ticket must not be redeemable as a handoff (scope escalation)")
	}
}

// A launch minted for a require_native target must be refused at mint time, so
// the portal can grey out the button instead of handing over a dead URL.
func TestLaunchDeniedByPolicyAtMint(t *testing.T) {
	srv, api, fake := buildLaunchServer(t, EmbedConfig{})
	h := api.handler()
	fake.session = &fakeSession{caller: keystoneCaller("alice", "proj-a")}
	_, _ = mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	ws := launchWorkspace(t, srv, "proj-a")
	// ws-viewer's only rule allows shell on any node; give the node a label set
	// that no allow rule matches by binding alice to the native-only role.
	seedLaunchNode(t, srv, ws, "n-prod", "i-prod", "proj-a", map[string]string{"tier": "prod"})
	// alice is the first human in the project, so she is ws-admin: reserve the
	// prod tier for the native client for exactly that role.
	if err := srv.SetWorkspacePolicy(ws, []byte(`
roles:
  ws-admin:
    allow:
      - actions: [shell]
        node_labels: {tier: prod}
        require_native: true
bindings: []
`), "test"); err != nil {
		t.Fatalf("set workspace policy: %v", err)
	}

	code, resp := mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-prod"}`)
	if code != http.StatusForbidden {
		t.Fatalf("require_native target must deny the web-path launch at mint, got %d %v", code, resp)
	}
	// It must be the POLICY engine that denied, not a resolution miss — a miss is
	// a 404 with the resolver's message, so without the dry-run this would 200.
	// (A require_native rule simply does not match on the web path, so the
	// engine's reason is its generic no-rule-allows text, not a native-specific one.)
	if reason, _ := resp["error"].(string); !strings.Contains(reason, "allows shell") {
		t.Fatalf("expected a policy-engine denial reason, got %q", reason)
	}
}

// Framing: only /embed/ is ever framable, only for a cloud that opted in, and
// only from the exact origins named. Everything else keeps X-Frame-Options DENY.
func TestEmbedFrameAncestors(t *testing.T) {
	_, api, _ := buildLaunchServer(t, EmbedConfig{
		Allow: true, FrameAncestors: []string{"https://horizon.example.com"},
	})
	api.static = t.TempDir()
	if err := os.WriteFile(filepath.Join(api.static, "index.html"), []byte("<html></html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := api.handler()

	get := func(path string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		return rr
	}

	// The console proper is never framable.
	if xfo := get("/nodes").Header().Get("X-Frame-Options"); xfo != "DENY" {
		t.Fatalf("console must keep X-Frame-Options: DENY, got %q", xfo)
	}

	// The embed doc for the opted-in cloud carries the exact allow-list.
	rr := get("/embed/shell?cloud=kolla1")
	if csp := rr.Header().Get("Content-Security-Policy"); csp != "frame-ancestors https://horizon.example.com" {
		t.Fatalf("embed CSP = %q", csp)
	}
	if xfo := rr.Header().Get("X-Frame-Options"); xfo != "" {
		t.Fatalf("embed doc must not also send X-Frame-Options (it contradicts CSP), got %q", xfo)
	}

	// An unknown or missing cloud hint fails closed.
	for _, path := range []string{"/embed/shell", "/embed/shell?cloud=nope"} {
		rr := get(path)
		if csp := rr.Header().Get("Content-Security-Policy"); csp != "frame-ancestors 'none'" {
			t.Errorf("%s: want frame-ancestors 'none', got %q", path, csp)
		}
		if rr.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s: must fall back to X-Frame-Options DENY", path)
		}
	}
}

// A cloud that has not opted in to embedding gets no frame-ancestors at all.
func TestEmbedRefusedWhenCloudDidNotOptIn(t *testing.T) {
	_, api, _ := buildLaunchServer(t, EmbedConfig{})
	api.static = t.TempDir()
	if err := os.WriteFile(filepath.Join(api.static, "index.html"), []byte("<html></html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	api.handler().ServeHTTP(rr, httptest.NewRequest("GET", "/embed/shell?cloud=kolla1", nil))
	if csp := rr.Header().Get("Content-Security-Policy"); csp != "frame-ancestors 'none'" {
		t.Fatalf("embedding is opt-in: want 'none', got %q", csp)
	}
}

// Config-load gates: the tenant-facing knobs must fail loudly, not degrade.
func TestLaunchConfigValidation(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(launchPolicyDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	// base() must be valid APART from the launch block, or a negative case could
	// pass on an unrelated error and prove nothing.
	base := func(l LaunchConfig) *Config {
		c := &Config{
			DataDir: dir, ClusterName: "t", RelayAddrs: []string{"127.0.0.1:7403"},
			PolicyFile: policyPath,
			Clouds: map[string]CloudConfig{"c1": {
				Kind: "openstack", KeystoneURL: "https://k/v3", Launch: l,
			}},
		}
		c.Console.ExternalURL = "https://console.example"
		c.applyDefaults()
		return c
	}
	if err := base(LaunchConfig{}).validate(); err != nil {
		t.Fatalf("baseline config must be valid so the cases below isolate the launch block: %v", err)
	}
	for _, tc := range []struct {
		name string
		l    LaunchConfig
	}{
		{"unlaunchable action", LaunchConfig{Allow: true, Actions: []string{"sftp"}}},
		{"ticket ttl too long", LaunchConfig{Allow: true, TicketTTL: Duration(20 * time.Minute)}},
		{"ceiling below the idle window", LaunchConfig{Allow: true, MaxSessionTTL: Duration(2 * time.Hour), AbsoluteTTL: Duration(time.Hour)}},
		{"ceiling implausibly long", LaunchConfig{Allow: true, AbsoluteTTL: Duration(30 * 24 * time.Hour)}},
		{"embed without ancestors", LaunchConfig{Allow: true, Embed: EmbedConfig{Allow: true}}},
		{"embed without launch", LaunchConfig{Embed: EmbedConfig{Allow: true, FrameAncestors: []string{"https://a.example"}}}},
		{"wildcard ancestor", LaunchConfig{Allow: true, Embed: EmbedConfig{Allow: true, FrameAncestors: []string{"https://*.example.com"}}}},
		{"plain http ancestor", LaunchConfig{Allow: true, Embed: EmbedConfig{Allow: true, FrameAncestors: []string{"http://portal.example.com"}}}},
		{"ancestor with a path", LaunchConfig{Allow: true, Embed: EmbedConfig{Allow: true, FrameAncestors: []string{"https://a.example/dash"}}}},
		{"bare host ancestor", LaunchConfig{Allow: true, Embed: EmbedConfig{Allow: true, FrameAncestors: []string{"portal.example.com"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := base(tc.l).validate()
			if err == nil {
				t.Fatalf("%s must fail config load", tc.name)
			}
			if !strings.Contains(err.Error(), "launch") {
				t.Fatalf("%s failed for an unrelated reason: %v", tc.name, err)
			}
		})
	}
	// A launch-enabled cloud needs an absolute https console origin: the launch
	// URL handed to the portal is built from it, and the redeem's origin check
	// pins against it. These are separate cases because they fail on a field
	// OUTSIDE the cloud block, so base()'s cloud config alone can't express them.
	for _, tc := range []struct{ name, ext string }{
		{"no external_url", ""},
		{"relative external_url", "/console"},
		{"plain-http external_url", "http://console.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base(LaunchConfig{Allow: true})
			c.Console.ExternalURL = tc.ext
			err := c.validate()
			if err == nil {
				t.Fatalf("%s must fail config load when launch is enabled", tc.name)
			}
			if !strings.Contains(err.Error(), "external_url") {
				t.Fatalf("%s failed for an unrelated reason: %v", tc.name, err)
			}
		})
	}
	// ...but a cloud with launch OFF does not need one.
	off := base(LaunchConfig{})
	off.Console.ExternalURL = ""
	if err := off.validate(); err != nil {
		t.Fatalf("external_url must only be required when launch is enabled: %v", err)
	}

	// The good case loads.
	ok := base(LaunchConfig{Allow: true, Actions: []string{"shell"}, Embed: EmbedConfig{
		Allow: true, FrameAncestors: []string{"https://horizon.example.com:8443"},
	}})
	if err := ok.validate(); err != nil {
		t.Fatalf("valid launch config must load: %v", err)
	}
}

// launchWorkspace finds the workspace auto-provisioned for a project.
func launchWorkspace(t *testing.T, srv *Server, project string) string {
	t.Helper()
	wss, err := srv.store.ListWorkspaces()
	if err != nil {
		t.Fatalf("list workspaces: %v", err)
	}
	var have []string
	for _, w := range wss {
		have = append(have, w.ID)
		if strings.Contains(w.ID, project) {
			return w.ID
		}
	}
	t.Fatalf("no workspace provisioned for %q (have %v)", project, have)
	return ""
}
