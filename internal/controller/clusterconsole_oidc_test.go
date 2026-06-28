package controller

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- a minimal RSA-signed id_token + JWKS test IdP ----------------------------

type testIdP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	issuer string
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &testIdP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   idp.issuer,
			"jwks_uri": idp.issuer + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}) // 65537
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{"kty": "RSA", "kid": "test", "use": "sig", "alg": "RS256", "n": n, "e": e}},
		})
	})
	idp.srv = httptest.NewServer(mux)
	idp.issuer = idp.srv.URL
	t.Cleanup(idp.srv.Close)
	return idp
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signIDToken mints an RS256 id_token with the given claims.
func (idp *testIdP) signIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "test"})
	payload, _ := json.Marshal(claims)
	signingInput := b64url(header) + "." + b64url(payload)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, idp.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + b64url(sig)
}

// newClusterOIDCTestServer builds a cluster console wired to the test IdP.
func newClusterOIDCTestServer(t *testing.T, idp *testIdP) *Server {
	t.Helper()
	cfg := testServerConfig(t)
	cfg.ClusterConsole.Listen = ":7407"
	cfg.ClusterConsole.OIDC = &ClusterConsoleOIDCConfig{
		Issuer: idp.issuer, ClientID: "geneza-cluster-console",
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := cfg.validateForServe(); err != nil {
		t.Fatalf("validateForServe: %v", err)
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

func postOIDC(t *testing.T, h http.Handler, idToken string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"idToken": idToken})
	r := httptest.NewRequest(http.MethodPost, "/clusterconsole/auth/oidc", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// A cluster-console OIDC login is admitted ONLY with the required group: a valid token
// missing the group is 403; one carrying it mints a session that authenticates the API.
// A break-glass cert still works, and a TENANT session never authenticates this console.
func TestClusterConsoleOIDCGroupGate(t *testing.T) {
	idp := newTestIdP(t)
	s := newClusterOIDCTestServer(t, idp)
	h := s.clusterConsole.handler()
	seedNode(t, s, "ws", "n1", "alpha", "2.0.0")

	base := func(extra map[string]any) map[string]any {
		c := map[string]any{
			"iss": idp.issuer, "aud": "geneza-cluster-console",
			"sub": "u-123", "preferred_username": "gadmin",
			"exp": float64(time.Now().Add(time.Hour).Unix()),
		}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}

	// 1) Valid token WITHOUT the required group -> 403, no session minted.
	code, out := postOIDC(t, h, idp.signIDToken(t, base(map[string]any{"groups": []any{"some-other-group"}})))
	if code != http.StatusForbidden {
		t.Fatalf("login without group = %d, want 403 (body %v)", code, out)
	}
	if out["token"] != nil {
		t.Fatalf("a token was minted for a non-cluster-admin: %v", out)
	}

	// 2) Valid token WITH the required group -> 200 + a bearer.
	code, out = postOIDC(t, h, idp.signIDToken(t, base(map[string]any{"groups": []any{"geneza-cluster-admins"}})))
	if code != http.StatusOK {
		t.Fatalf("login with group = %d, want 200 (body %v)", code, out)
	}
	token, _ := out["token"].(string)
	if token == "" {
		t.Fatalf("no bearer minted for a cluster admin: %v", out)
	}

	// The minted cluster session authenticates the API.
	r := httptest.NewRequest(http.MethodGet, "/clusterconsole/v1/agents", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("API with cluster session = %d, want 200", w.Code)
	}

	// /clusterconsole/v1/session reports the OIDC principal.
	r = httptest.NewRequest(http.MethodGet, "/clusterconsole/v1/session", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var me map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &me)
	if w.Code != http.StatusOK || me["user"] != "gadmin" || me["auth"] != "oidc" {
		t.Fatalf("/session = %d body=%v, want gadmin/oidc", w.Code, me)
	}

	// 3) A break-glass cert authenticates the API with NO bearer.
	admin := issueClusterCert(t, s, "root", []string{roleAdmin})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, reqWithCert("/clusterconsole/v1/agents", admin))
	if w.Code != http.StatusOK {
		t.Fatalf("API with break-glass cert = %d, want 200", w.Code)
	}

	// 4) A TENANT session bearer must NOT authenticate the cluster console.
	tenantTok, _, err := s.mintAuthSession(sessionInput{
		Provider: providerOIDC, User: "gadmin", Subject: "u-123",
		Workspace: "ws", Roles: []string{roleWSAdmin},
	})
	if err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest(http.MethodGet, "/clusterconsole/v1/agents", nil)
	r.Header.Set("Authorization", "Bearer "+tenantTok)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant session against cluster console = %d, want 403", w.Code)
	}

	// 5) Logout kills the cluster session immediately.
	r = httptest.NewRequest(http.MethodDelete, "/clusterconsole/v1/session", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("logout = %d, want 200", w.Code)
	}
	r = httptest.NewRequest(http.MethodGet, "/clusterconsole/v1/agents", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("API after logout = %d, want 403", w.Code)
	}
}

// Changing a node's agent module set emits the audit type "agent_modules_set"
// (renamed from "node_modules_set", which collided with npm's node_modules); the old
// type must no longer appear.
func TestAgentModulesSetAuditType(t *testing.T) {
	cfg := testServerConfig(t)
	cfg.Console.Listen = ":7406"
	cfg.Console.StaticDir = t.TempDir()
	if err := cfg.validate(); err != nil {
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
	seedNode(t, s, defaultWorkspace, "n1", "alpha", "2.0.0")

	body, _ := json.Marshal(map[string]any{
		"modules": []map[string]any{{"name": "node-exporter", "enabled": true}},
	})
	r := httptest.NewRequest(http.MethodPut, "/api/v1/nodes/n1/modules", strings.NewReader(string(body)))
	r.SetPathValue("id", "n1")
	w := httptest.NewRecorder()
	u := &consoleUser{Name: "op", Workspace: defaultWorkspace, Roles: []string{roleWSAdmin}, Admin: true}
	s.console.handleSetNodeModules(w, r, u)
	if w.Code != http.StatusOK {
		t.Fatalf("set modules = %d, want 200 (body %s)", w.Code, w.Body.String())
	}

	if lines, _, err := s.audit.Query(0, "agent_modules_set", "", 10); err != nil || len(lines) == 0 {
		t.Fatalf("no agent_modules_set audit record (err %v, n %d)", err, len(lines))
	}
	if lines, _, _ := s.audit.Query(0, "node_modules_set", "", 10); len(lines) != 0 {
		t.Fatalf("the old node_modules_set audit type is still emitted (%d records)", len(lines))
	}
}

// A cluster session minted here must NOT authenticate the TENANT console (the reverse
// of case 4): the two namespaces are disjoint in both directions.
func TestClusterSessionRejectedByTenantConsole(t *testing.T) {
	cfg := testServerConfig(t)
	cfg.Console.Listen = ":7406"
	cfg.Console.StaticDir = t.TempDir()
	if err := cfg.validate(); err != nil {
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

	clusterTok, _, err := s.mintClusterSession(clusterSessionInput{
		Source: "https://idp", User: "gadmin", Subject: "u-123",
		Groups: []string{"geneza-cluster-admins"},
	})
	if err != nil {
		t.Fatal(err)
	}
	th := s.console.handler()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil)
	r.Header.Set("Authorization", "Bearer "+clusterTok)
	w := httptest.NewRecorder()
	th.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("cluster session against tenant console = %d, want 401", w.Code)
	}
}
