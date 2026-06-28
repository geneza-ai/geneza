package controller

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"geneza.io/internal/ca"
	"geneza.io/internal/types"
)

// issueClusterCert mints a user cert carrying the requested roles straight from the
// CA (the break-glass path: stripReservedRoles is bypassed so the cluster admin role
// is actually present), parsed to an *x509.Certificate ready to drop into a request's
// VerifiedChains — exactly what the TLS handshake would hand the handler.
func issueClusterCert(t *testing.T, s *Server, name string, roles []string) *x509.Certificate {
	t.Helper()
	key, err := ca.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ca.MakeCSR(key, name)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := s.ca.IssueFromCSR(csr, ca.Profile{
		Kind:   ca.KindUser,
		Name:   name,
		TTL:    time.Hour,
		Claims: &ca.IdentityClaims{Roles: roles, Provider: "breakglass", Subject: name},
	})
	if err != nil {
		t.Fatalf("issue cluster cert: %v", err)
	}
	blk, _ := pem.Decode(certPEM)
	crt, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return crt
}

// reqWithCert builds a GET request whose TLS state presents leaf as a chain-verified
// client cert, so clusterAdminFromCert sees it the way the real mTLS listener would.
func reqWithCert(target string, leaf *x509.Certificate) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	if leaf != nil {
		r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
	}
	return r
}

func newClusterConsoleTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := testServerConfig(t)
	cfg.ClusterConsole.Listen = ":7407"
	if err := cfg.validateForServe(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := InitDataDir(cfg); err != nil {
		t.Fatalf("init: %v", err)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// decodeList runs the handler and returns the named list of objects from the JSON body.
func decodeList(t *testing.T, h http.Handler, r *http.Request, key string) (int, []map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		return w.Code, nil
	}
	var body map[string][]map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %s: %v (body %s)", key, err, w.Body.String())
	}
	return w.Code, body[key]
}

// seedNode writes a node into a workspace with a given reported agent version.
func seedNode(t *testing.T, s *Server, ws, id, name, agentVersion string) {
	t.Helper()
	if err := s.store.PutWorkspace(&WorkspaceRecord{ID: ws, Name: ws, OverlayCIDR: "100.64.0.0/24"}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.PutNode(ws, &NodeRecord{
		WorkspaceID: ws, ID: id, Name: name, Approved: true,
		Platform: PlatformRecord{AgentVersion: agentVersion},
	}); err != nil {
		t.Fatal(err)
	}
}

// A break-glass admin cert reaches /clusterconsole/v1/agents and sees nodes across MULTIPLE
// workspaces; a ws-admin (non-cluster-admin) cert is rejected on EVERY /clusterconsole/v1 route.
func TestClusterConsoleAdminCrossWorkspaceAndNonAdmin403(t *testing.T) {
	s := newClusterConsoleTestServer(t)
	h := s.clusterConsole.handler()

	if err := s.store.SetStableVersion("2.0.0"); err != nil {
		t.Fatal(err)
	}
	seedNode(t, s, "ws-a", "n1", "alpha", "2.0.0")
	seedNode(t, s, "ws-b", "n2", "beta", "1.0.0")

	admin := issueClusterCert(t, s, "root", []string{roleAdmin})
	code, agents := decodeList(t, h, reqWithCert("/clusterconsole/v1/agents", admin), "agents")
	if code != http.StatusOK {
		t.Fatalf("admin /agents = %d, want 200", code)
	}
	wss := map[string]bool{}
	for _, a := range agents {
		wss[a["workspace"].(string)] = true
	}
	if !wss["ws-a"] || !wss["ws-b"] {
		t.Fatalf("admin /agents must span workspaces, saw %v", wss)
	}

	// A workspace admin (the strongest LOGIN-derivable role) must be rejected on every
	// cluster route — the surface is break-glass-cluster-admin only.
	wsAdmin := issueClusterCert(t, s, "tenant-admin", []string{roleWSAdmin})
	for _, route := range []string{
		"/clusterconsole/v1/agents", "/clusterconsole/v1/agents/risk", "/clusterconsole/v1/workspaces",
		"/clusterconsole/v1/topology/controllers", "/clusterconsole/v1/topology/relays",
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, reqWithCert(route, wsAdmin))
		if w.Code != http.StatusForbidden {
			t.Fatalf("ws-admin %s = %d, want 403", route, w.Code)
		}
	}

	// No cert at all is likewise refused (the real listener fails the handshake; the
	// handler fails closed too).
	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithCert("/clusterconsole/v1/agents", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("no-cert /agents = %d, want 403", w.Code)
	}
}

// With a static dir configured, the operator SPA shell is served at / (index.html for
// an unknown client route) WITHOUT a cert so the SPA can drive the OIDC login; the
// API, by contrast, still 403s without cluster-admin authority, and API paths never
// fall through to the SPA.
func TestClusterConsoleServesSPABehindCertGate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html><title>Geneza Cluster</title>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("console.log(1)"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := testServerConfig(t)
	cfg.ClusterConsole.Listen = ":7407"
	cfg.ClusterConsole.StaticDir = dir
	if err := cfg.validateForServe(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := InitDataDir(cfg); err != nil {
		t.Fatalf("init: %v", err)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(s.Close)
	h := s.clusterConsole.handler()
	admin := issueClusterCert(t, s, "root", []string{roleAdmin})

	// Root serves index.html for an admin.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithCert("/", admin))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Geneza Cluster") {
		t.Fatalf("root for admin = %d body=%q, want index.html", w.Code, w.Body.String())
	}

	// An unknown client route falls back to index.html (SPA routing).
	w = httptest.NewRecorder()
	h.ServeHTTP(w, reqWithCert("/topology", admin))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Geneza Cluster") {
		t.Fatalf("client route fallback = %d, want index.html", w.Code)
	}

	// A real asset is served directly.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, reqWithCert("/app.js", admin))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "console.log") {
		t.Fatalf("asset = %d, want app.js", w.Code)
	}

	// The SPA shell is now anonymously loadable (no cert, or a ws-admin cert) — the
	// browser must reach it to run the OIDC login. The shell carries no privileged
	// data; the API is what stays gated.
	wsAdmin := issueClusterCert(t, s, "tenant-admin", []string{roleWSAdmin})
	for _, leaf := range []*x509.Certificate{wsAdmin, nil} {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, reqWithCert("/", leaf))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Geneza Cluster") {
			t.Fatalf("SPA shell without break-glass cert = %d, want 200 index.html", w.Code)
		}
	}

	// The API, however, is NOT anonymously reachable: a ws-admin cert and no cert both
	// 403, and an API path never falls through to the SPA.
	for _, leaf := range []*x509.Certificate{wsAdmin, nil} {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, reqWithCert("/clusterconsole/v1/agents", leaf))
		if w.Code != http.StatusForbidden {
			t.Fatalf("/clusterconsole/v1/agents without cluster admin = %d, want 403", w.Code)
		}
	}
}

// Outdated computation: a node at the stable version is current; a node behind is
// outdated; a canary-ring node is compared against the canary version, not stable.
func TestClusterConsoleOutdatedComputation(t *testing.T) {
	s := newClusterConsoleTestServer(t)
	h := s.clusterConsole.handler()

	if err := s.store.SetStableVersion("2.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetCanaryVersion("2.1.0"); err != nil {
		t.Fatal(err)
	}
	seedNode(t, s, "ws", "current", "current", "2.0.0") // at stable -> not outdated
	seedNode(t, s, "ws", "behind", "behind", "1.9.0")   // behind stable -> outdated
	seedNode(t, s, "ws", "canary", "canary", "2.1.0")   // in canary ring, at canary -> not outdated
	seedNode(t, s, "ws", "canolds", "canolds", "2.0.0") // in canary ring, at stable -> outdated vs canary
	if err := s.store.SetCanaryNodes([]string{"canary", "canolds"}); err != nil {
		t.Fatal(err)
	}

	_, agents := decodeList(t, h, reqWithCert("/clusterconsole/v1/agents", issueClusterCert(t, s, "root", []string{roleAdmin})), "agents")
	got := map[string]bool{}
	for _, a := range agents {
		got[a["nodeId"].(string)] = a["outdated"].(bool)
	}
	want := map[string]bool{"current": false, "behind": true, "canary": false, "canolds": true}
	for id, exp := range want {
		if got[id] != exp {
			t.Fatalf("node %s outdated=%v, want %v (all: %v)", id, got[id], exp, got)
		}
	}

	// desiredVersion must reflect the ring: canary nodes get the canary version.
	for _, a := range agents {
		if a["nodeId"].(string) == "canary" && a["desiredVersion"].(string) != "2.1.0" {
			t.Fatalf("canary node desiredVersion = %v, want 2.1.0", a["desiredVersion"])
		}
		if a["nodeId"].(string) == "current" && a["desiredVersion"].(string) != "2.0.0" {
			t.Fatalf("stable node desiredVersion = %v, want 2.0.0", a["desiredVersion"])
		}
	}

	// ?outdated=true narrows to the outdated set only.
	_, only := decodeList(t, h, reqWithCert("/clusterconsole/v1/agents?outdated=true", issueClusterCert(t, s, "root", []string{roleAdmin})), "agents")
	for _, a := range only {
		if !a["outdated"].(bool) {
			t.Fatalf("?outdated=true returned a current node: %v", a["nodeId"])
		}
	}
	if len(only) != 2 {
		t.Fatalf("?outdated=true count = %d, want 2", len(only))
	}
}

// /agents/risk ranks an outdated node carrying a KEV/critical finding above a
// current-or-clean one, and looks the CVE up in the node's OWN workspace.
func TestClusterConsoleAgentsRiskRanking(t *testing.T) {
	s := newClusterConsoleTestServer(t)
	h := s.clusterConsole.handler()

	if err := s.store.SetStableVersion("2.0.0"); err != nil {
		t.Fatal(err)
	}
	// risky: outdated AND a KEV/critical finding in its own workspace.
	seedNode(t, s, "ws-risky", "risky", "risky", "1.0.0")
	if err := s.store.UpsertNodeCVE(&NodeCVERecord{
		WorkspaceID: "ws-risky", NodeID: "risky", CVE: "CVE-2024-0001", Purl: "pkg:deb/openssl",
		Status: "affected", Severity: "CRITICAL", KEV: true,
	}); err != nil {
		t.Fatal(err)
	}
	// clean: current and no findings.
	seedNode(t, s, "ws-clean", "clean", "clean", "2.0.0")

	_, agents := decodeList(t, h, reqWithCert("/clusterconsole/v1/agents/risk", issueClusterCert(t, s, "root", []string{roleAdmin})), "agents")
	if len(agents) != 2 {
		t.Fatalf("risk list = %d, want 2", len(agents))
	}
	if agents[0]["nodeId"].(string) != "risky" {
		t.Fatalf("risk ranking: top node = %v, want risky", agents[0]["nodeId"])
	}
	top := agents[0]
	if top["worstSeverity"].(string) != "CRITICAL" || top["kevCount"].(float64) != 1 || top["cveCount"].(float64) != 1 {
		t.Fatalf("risky summary wrong: %v", top)
	}
	if !top["outdated"].(bool) {
		t.Fatalf("risky node should be outdated: %v", top)
	}
	// The clean node must show no findings — proving the CVE lookup used the node's OWN
	// workspace (ws-clean), not ws-risky, so the critical KEV did not bleed across.
	clean := agents[1]
	if clean["cveCount"].(float64) != 0 || clean["kevCount"].(float64) != 0 || clean["worstSeverity"].(string) != "" {
		t.Fatalf("clean node leaked another workspace's CVE: %v", clean)
	}
}

// The topology + workspaces routes serve the cross-workspace presence rows to a
// cluster admin (version field included).
func TestClusterConsoleTopologyAndWorkspaces(t *testing.T) {
	s := newClusterConsoleTestServer(t)
	h := s.clusterConsole.handler()
	admin := func() *x509.Certificate { return issueClusterCert(t, s, "root", []string{roleAdmin}) }

	now := time.Now().Unix()
	if err := s.store.UpsertController(&ControllerRecord{
		ControllerEndpoint: types.ControllerEndpoint{ControllerID: "gw1", Addrs: []string{"gw1:7401"}, RegionID: "eu"},
		LastSeenUnix:    now, Version: "3.1.0",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertController(&ControllerRecord{
		ControllerEndpoint: types.ControllerEndpoint{ControllerID: "gw-old", Addrs: []string{"old:7401"}, RegionID: "eu"},
		LastSeenUnix:    now - 3600, Version: "3.0.0",
	}); err != nil {
		t.Fatal(err)
	}
	_, gws := decodeList(t, h, reqWithCert("/clusterconsole/v1/topology/controllers", admin()), "controllers")
	online := map[string]bool{}
	ver := map[string]string{}
	for _, g := range gws {
		online[g["controllerId"].(string)] = g["online"].(bool)
		ver[g["controllerId"].(string)] = g["version"].(string)
	}
	if !online["gw1"] || online["gw-old"] {
		t.Fatalf("controller online flags wrong: %v", online)
	}
	if ver["gw1"] != "3.1.0" {
		t.Fatalf("controller version not surfaced: %v", ver)
	}

	if err := s.store.PutWorkspace(&WorkspaceRecord{ID: "ws-x", Name: "X", OverlayCIDR: "100.64.1.0/24"}); err != nil {
		t.Fatal(err)
	}
	_, wss := decodeList(t, h, reqWithCert("/clusterconsole/v1/workspaces", admin()), "workspaces")
	found := false
	for _, w := range wss {
		if w["id"].(string) == "ws-x" {
			found = true
		}
	}
	if !found {
		t.Fatalf("workspaces route missing ws-x: %v", wss)
	}
}

// postWithCert builds a JSON POST whose TLS state presents leaf as a chain-verified
// break-glass admin cert, for the cluster-console mutation routes.
func postWithCert(target string, leaf *x509.Certificate, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	if leaf != nil {
		r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
	}
	return r
}

// The cluster console drives the relay rollout ring: a break-glass admin can set
// the canary then promote to stable (subject to the same relay-aware health gate),
// read it back, and a non-admin is refused on every relay-update route.
func TestClusterConsoleRelayRollout(t *testing.T) {
	s := newClusterConsoleTestServer(t)
	h := s.clusterConsole.handler()
	admin := issueClusterCert(t, s, "root", []string{roleAdmin})

	do := func(r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	// Set the relay canary ring with one canary relay, candidate r-2.0.0.
	w := do(postWithCert("/clusterconsole/v1/relays/updates/rollout", admin,
		`{"ring":"canary","version":"r-2.0.0","canaryRelays":["r-eu-1"]}`))
	if w.Code != http.StatusOK {
		t.Fatalf("set relay canary = %d, body=%s", w.Code, w.Body.String())
	}

	// The canary relay reports the OLD version: stable promotion must be blocked (409).
	if err := s.store.UpsertRelay(&RelayRecord{
		RelayNode:    types.RelayNode{RegionID: "eu", RelayID: "r-eu-1", Addrs: []string{"r-eu-1:7404"}},
		LastSeenUnix: time.Now().Unix(), Version: "r-1.0.0",
	}); err != nil {
		t.Fatal(err)
	}
	w = do(postWithCert("/clusterconsole/v1/relays/updates/rollout", admin,
		`{"ring":"stable","version":"r-2.0.0"}`))
	if w.Code != http.StatusConflict {
		t.Fatalf("blocked promotion = %d, want 409 (body=%s)", w.Code, w.Body.String())
	}

	// Once the relay reports the candidate freshly, promotion succeeds.
	if err := s.store.UpsertRelay(&RelayRecord{
		RelayNode:    types.RelayNode{RegionID: "eu", RelayID: "r-eu-1", Addrs: []string{"r-eu-1:7404"}},
		LastSeenUnix: time.Now().Unix(), Version: "r-2.0.0",
	}); err != nil {
		t.Fatal(err)
	}
	w = do(postWithCert("/clusterconsole/v1/relays/updates/rollout", admin,
		`{"ring":"stable","version":"r-2.0.0"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("promotion = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}

	// GET desired reflects the ring.
	gw := do(reqWithCert("/clusterconsole/v1/relays/updates/desired", admin))
	if gw.Code != http.StatusOK {
		t.Fatalf("get relay desired = %d", gw.Code)
	}
	var desired map[string]any
	if err := json.Unmarshal(gw.Body.Bytes(), &desired); err != nil {
		t.Fatal(err)
	}
	if desired["stableVersion"] != "r-2.0.0" || desired["canaryVersion"] != "r-2.0.0" {
		t.Fatalf("relay desired = %v", desired)
	}

	// A non-admin (ws-admin) cert is refused on both relay-update routes.
	wsAdmin := issueClusterCert(t, s, "tenant", []string{roleWSAdmin})
	for _, r := range []*http.Request{
		reqWithCert("/clusterconsole/v1/relays/updates/desired", wsAdmin),
		postWithCert("/clusterconsole/v1/relays/updates/rollout", wsAdmin, `{"ring":"canary","version":"x"}`),
	} {
		if code := do(r).Code; code != http.StatusForbidden {
			t.Fatalf("non-admin %s = %d, want 403", r.URL.Path, code)
		}
	}
}
