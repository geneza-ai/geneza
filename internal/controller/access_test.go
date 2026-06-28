package controller

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const autoProvisionPolicyDoc = `
roles:
  ws-admin:
    allow:
      - actions: ["*"]
        node_labels: {"*": "*"}
  ws-member:
    allow:
      - actions: [shell, exec, attach]
        node_labels: {"*": "*"}
  ws-viewer:
    allow:
      - actions: [attach]
        node_labels: {"*": "*"}
bindings: []
`

func TestValidateHumanKeystoneToken(t *testing.T) {
	cl := CloudConfig{Kind: "openstack", KeystoneURL: "https://k/v3"}
	good := osCaller{UserName: "alice", ProjectID: "p1", ProjectName: "team-a", ScopeProject: true, Roles: []string{"member"}}
	if err := validateHumanKeystoneToken(good, cl); err != nil {
		t.Fatalf("clean human project token must pass: %v", err)
	}
	for _, tc := range []struct {
		name   string
		caller osCaller
	}{
		{"unscoped", osCaller{UserName: "a", ScopeProject: false}},
		{"domain-scoped", osCaller{UserName: "a", ProjectID: "", ScopeDomain: true}},
		{"service-project", osCaller{UserName: "a", ProjectID: "p", ProjectName: "service", ScopeProject: true}},
		{"service-user", osCaller{UserName: "nova", ProjectID: "p", ProjectName: "team", ScopeProject: true}},
		{"service-role", osCaller{UserName: "a", ProjectID: "p", ProjectName: "team", ScopeProject: true, Roles: []string{"service"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateHumanKeystoneToken(tc.caller, cl); err == nil {
				t.Fatalf("%s must be rejected (#9/#10)", tc.name)
			}
		})
	}
}

func TestMapKeystoneRoles(t *testing.T) {
	// Default (no role_map): least privilege.
	def := CloudConfig{}
	if got := def.mapKeystoneRoles([]string{"member"}); len(got) != 1 || got[0] != "ws-viewer" {
		t.Fatalf("default member -> ws-viewer, got %v", got)
	}
	if got := def.mapKeystoneRoles([]string{"admin"}); len(got) != 1 || got[0] != roleWSAdmin {
		t.Fatalf("default admin -> ws-admin, got %v", got)
	}
	// Explicit role_map + default_role fallback.
	cl := CloudConfig{RoleMap: map[string]string{"geneza-operator": "ws-member"}, DefaultRole: "ws-viewer"}
	if got := cl.mapKeystoneRoles([]string{"geneza-operator"}); got[0] != "ws-member" {
		t.Fatalf("mapped operator -> ws-member, got %v", got)
	}
	if got := cl.mapKeystoneRoles([]string{"unknownrole"}); len(got) != 1 || got[0] != "ws-viewer" {
		t.Fatalf("unmapped -> default_role ws-viewer, got %v", got)
	}
}

// buildAccessServer makes a server with one cloud whose verifier is a fake, plus
// an auto-provision (role-name) policy. Returns the console api + the fake so a
// test can set the PasswordLogin result.
func buildAccessServer(t *testing.T, allowAutoProvision bool) (*Server, *consoleAPI, *fakeVerifier) {
	t.Helper()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(testPolicyDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	autoPath := filepath.Join(dir, "auto.yaml")
	if err := os.WriteFile(autoPath, []byte(autoProvisionPolicyDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		DataDir:                 filepath.Join(dir, "data"),
		ClusterName:             "t",
		RelayAddrs:              []string{"127.0.0.1:7403"},
		PolicyFile:              policyPath,
		AutoProvisionPolicyFile: autoPath,
		Clouds: map[string]CloudConfig{
			"kolla1": {
				Kind: "openstack", KeystoneURL: "https://k.example/v3",
				AllowHumanAutoProvision: allowAutoProvision,
				AllowTrustedDashboard:   true,
				RoleMap:                 map[string]string{"admin": roleWSAdmin, "member": "ws-viewer"},
				DefaultRole:             "ws-viewer",
			},
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
	fake := &fakeVerifier{}
	srv.clouds["kolla1"] = fake
	api, err := srv.newConsoleAPI()
	if err != nil {
		t.Fatalf("console api: %v", err)
	}
	return srv, api, fake
}

func TestKeystoneAccessFirstUserBecomesWsAdmin(t *testing.T) {
	srv, api, fake := buildAccessServer(t, true)
	h := api.handler()

	// First human in an unbound project: auto-provision + ws-admin.
	fake.pwCaller = osCaller{
		UserName: "alice", UserID: "ks-alice", ProjectID: "proj-uuid-123456789",
		ProjectName: "research", ScopeProject: true, Roles: []string{"member"},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	code, resp := doJSON(t, h, "POST", "/api/v1/session/keystone", "", `{"cloud":"kolla1","username":"alice","password":"x"}`)
	if code != 200 {
		t.Fatalf("first keystone login: %d %v", code, resp)
	}
	if resp["token"] == "" {
		t.Fatalf("expected a session token, got %v", resp)
	}
	roles := resp["roles"].([]any)
	if len(roles) != 1 || roles[0] != roleWSAdmin || resp["admin"] != true {
		t.Fatalf("first user must be ws-admin, got roles=%v admin=%v", roles, resp["admin"])
	}
	ws := resp["workspace"].(string)

	// A binding now exists for the project, mapping to the new workspace.
	if b, err := srv.store.GetSourceBinding(osProjectBindingKey("kolla1", "proj-uuid-123456789")); err != nil || b.WorkspaceID != ws {
		t.Fatalf("project binding missing/wrong: %v err=%v", b, err)
	}

	// Second human in the SAME project: joins via role_map (member -> ws-viewer),
	// NOT admin. Coexists with the keystone-admin in the same workspace.
	fake.pwCaller = osCaller{
		UserName: "bob", UserID: "ks-bob", ProjectID: "proj-uuid-123456789",
		ProjectName: "research", ScopeProject: true, Roles: []string{"member"},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	code, resp = doJSON(t, h, "POST", "/api/v1/session/keystone", "", `{"cloud":"kolla1","username":"bob","password":"y"}`)
	if code != 200 {
		t.Fatalf("second keystone login: %d %v", code, resp)
	}
	if resp["workspace"] != ws {
		t.Fatalf("second user must land in the SAME workspace, got %v want %v", resp["workspace"], ws)
	}
	roles = resp["roles"].([]any)
	if len(roles) != 1 || roles[0] != "ws-viewer" || resp["admin"] != false {
		t.Fatalf("second user must be ws-viewer (not admin), got roles=%v admin=%v", roles, resp["admin"])
	}

	members, _ := srv.store.ListMembers(ws)
	if len(members) != 2 {
		t.Fatalf("workspace should have 2 members, got %d", len(members))
	}
}

func TestKeystoneUnboundProjectDeniedWhenAutoProvisionOff(t *testing.T) {
	_, api, fake := buildAccessServer(t, false) // allow_human_auto_provision = false
	h := api.handler()
	fake.pwCaller = osCaller{
		UserName: "alice", UserID: "ks-alice", ProjectID: "p-unbound",
		ProjectName: "orphan", ScopeProject: true, Roles: []string{"member"}, ExpiresAt: time.Now().Add(time.Hour),
	}
	code, _ := doJSON(t, h, "POST", "/api/v1/session/keystone", "", `{"cloud":"kolla1","username":"alice","password":"x"}`)
	if code != 403 {
		t.Fatalf("unbound project with auto-provision OFF must be 403, got %d", code)
	}
}

func TestKeystoneServiceTokenRejected(t *testing.T) {
	_, api, fake := buildAccessServer(t, true)
	h := api.handler()
	// A service-project-scoped token must never establish a session.
	fake.pwCaller = osCaller{
		UserName: "admin", UserID: "ks-admin", ProjectID: "svc", ProjectName: "service",
		ScopeProject: true, Roles: []string{"admin", "service"}, ExpiresAt: time.Now().Add(time.Hour),
	}
	code, _ := doJSON(t, h, "POST", "/api/v1/session/keystone", "", `{"cloud":"kolla1","username":"admin","password":"x"}`)
	if code != 403 {
		t.Fatalf("service token must be rejected, got %d", code)
	}
}

func TestKeystoneProjectPicker(t *testing.T) {
	_, api, fake := buildAccessServer(t, true)
	h := api.handler()
	// Several projects, none chosen -> the picker list, no session.
	fake.pwProjects = []osProjectRef{{ID: "p1", Name: "alpha"}, {ID: "p2", Name: "beta"}}
	code, resp := doJSON(t, h, "POST", "/api/v1/session/keystone", "", `{"cloud":"kolla1","username":"alice","password":"x"}`)
	if code != 200 {
		t.Fatalf("project picker: %d %v", code, resp)
	}
	if _, hasTok := resp["token"]; hasTok {
		t.Fatalf("picker response must not carry a token")
	}
	projs, _ := resp["availableProjects"].([]any)
	if len(projs) != 2 {
		t.Fatalf("expected 2 candidate projects, got %v", resp["availableProjects"])
	}
}
