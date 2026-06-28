package controller

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func doJSON(t *testing.T, h http.Handler, method, path, bearer, body string) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func TestConsoleLocalLoginLifecycle(t *testing.T) {
	_, api := testConsoleServer(t)
	h := api.handler()

	// /config advertises local (testServerConfig has no oidc/clouds).
	code, cfg := doJSON(t, h, "GET", "/api/v1/config", "", "")
	if code != 200 {
		t.Fatalf("config: %d", code)
	}
	auth := cfg["auth"].(map[string]any)
	if auth["local"] != true || auth["oidc"] != nil {
		t.Fatalf("config auth advertisement wrong: %v", auth)
	}

	// Local login -> opaque session bound to the default workspace + policy roles.
	code, resp := doJSON(t, h, "POST", "/api/v1/session/local", "", `{"username":"alice","password":"hunter2"}`)
	if code != 200 {
		t.Fatalf("login: %d %v", code, resp)
	}
	token, _ := resp["token"].(string)
	if token == "" || resp["workspace"] != defaultWorkspace {
		t.Fatalf("login response wrong: %v", resp)
	}
	roles := resp["roles"].([]any)
	if len(roles) != 1 || roles[0] != "ops" {
		t.Fatalf("roles wrong: %v", roles)
	}

	// The session authenticates the bootstrap probe.
	code, me := doJSON(t, h, "GET", "/api/v1/session", token, "")
	if code != 200 || me["user"] != "alice" {
		t.Fatalf("session probe: %d %v", code, me)
	}

	// Bad password -> 401, no token.
	if code, _ := doJSON(t, h, "POST", "/api/v1/session/local", "", `{"username":"alice","password":"nope"}`); code != 401 {
		t.Fatalf("bad password: want 401 got %d", code)
	}

	// Logout deletes the session server-side; the token is then dead.
	if code, _ := doJSON(t, h, "DELETE", "/api/v1/session", token, ""); code != 200 {
		t.Fatalf("logout: %d", code)
	}
	if code, _ := doJSON(t, h, "GET", "/api/v1/session", token, ""); code != 401 {
		t.Fatalf("post-logout probe: want 401 got %d", code)
	}
}

func TestConsoleLoginForeignWorkspaceDenied(t *testing.T) {
	_, api := testConsoleServer(t)
	h := api.handler()
	// alice is a member of `default` only; requesting another workspace is 403
	// (a client-supplied workspace is only ever a choice among the candidates the
	// server has already vetted for the user, never a way to escalate scope).
	code, _ := doJSON(t, h, "POST", "/api/v1/session/local", "", `{"username":"alice","password":"hunter2","workspace":"someone-elses-ws"}`)
	if code != http.StatusForbidden {
		t.Fatalf("foreign workspace: want 403 got %d", code)
	}
}

func TestConsoleLoginAmbiguousWorkspace(t *testing.T) {
	// Two open workspaces -> a login with no workspace returns the candidates and
	// NO token; the SPA must choose.
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(testPolicyDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	cfg := &Config{
		DataDir:     filepath.Join(dir, "data"),
		ClusterName: "t",
		RelayAddrs:  []string{"127.0.0.1:7403"},
		PolicyFile:  policyPath,
		LocalUsers:  []LocalUser{{Username: "alice", PasswordBcrypt: string(hash), Groups: []string{"admins"}}},
		Workspaces: []WorkspaceConfig{
			{ID: defaultWorkspace, Name: "Default", PolicyFile: policyPath},
			{ID: "team-b", Name: "Team B", PolicyFile: policyPath},
		},
	}
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
	api, _ := srv.newConsoleAPI()
	h := api.handler()

	code, resp := doJSON(t, h, "POST", "/api/v1/session/local", "", `{"username":"alice","password":"pw"}`)
	if code != 200 {
		t.Fatalf("ambiguous login: %d %v", code, resp)
	}
	if _, hasTok := resp["token"]; hasTok {
		t.Fatalf("ambiguous login must NOT return a token: %v", resp)
	}
	avail, _ := resp["availableWorkspaces"].([]any)
	if len(avail) != 2 {
		t.Fatalf("want 2 candidate workspaces, got %v", resp["availableWorkspaces"])
	}

	// Choosing one yields a token scoped to it.
	code, resp = doJSON(t, h, "POST", "/api/v1/session/local", "", `{"username":"alice","password":"pw","workspace":"team-b"}`)
	if code != 200 || resp["workspace"] != "team-b" || resp["token"] == "" {
		t.Fatalf("workspace choice: %d %v", code, resp)
	}
}
