package controller

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"geneza.io/internal/enrollcode"
)

// --- fakes ---

type fakeSession struct {
	caller   osCaller
	servers  map[string]osServer
	projects map[string]osProject
}

func (f *fakeSession) Caller() osCaller { return f.caller }
func (f *fakeSession) GetServer(_ context.Context, id string) (osServer, error) {
	s, ok := f.servers[id]
	if !ok {
		return osServer{}, errOSNotFound{"instance"}
	}
	return s, nil
}
func (f *fakeSession) ResolveProject(_ context.Context, id string) (osProject, error) {
	p, ok := f.projects[id]
	if !ok {
		return osProject{}, errOSNotFound{"project"}
	}
	return p, nil
}

type fakeVerifier struct {
	validErr error
	session  *fakeSession
	// access-plane (PasswordLogin) fakes
	pwCaller   osCaller
	pwProjects []osProjectRef
	pwErr      error
}

func (f *fakeVerifier) Validate(_ context.Context, _ string) (cloudSession, error) {
	if f.validErr != nil {
		return nil, f.validErr
	}
	return f.session, nil
}

func (f *fakeVerifier) PasswordLogin(_ context.Context, _ passwordAuth) (osCaller, []osProjectRef, error) {
	return f.pwCaller, f.pwProjects, f.pwErr
}

// --- harness ---

func testServerWithCloud(t *testing.T, uid string, cloud CloudConfig, extraWS ...WorkspaceConfig) *Server {
	t.Helper()
	cfg := testServerConfig(t)
	cfg.Workspaces = append(cfg.Workspaces, extraWS...)
	cfg.Clouds = map[string]CloudConfig{uid: cloud}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		t.Fatalf("config validate: %v", err)
	}
	if err := InitDataDir(cfg); err != nil {
		t.Fatalf("init: %v", err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return srv
}

func postVendordata(t *testing.T, srv *Server, uid, token string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", "/openstack/vendordata/"+uid, strings.NewReader(string(b)))
	r.SetPathValue("service_uid", uid)
	if token != "" {
		r.Header.Set("X-Auth-Token", token)
	}
	w := httptest.NewRecorder()
	srv.handleVendordata(w, r)
	return w
}

// tokenFromCloudInit extracts the join token from the rendered cloud-init the
// handler returns (a JSON string): it pulls the single-quoted gzk_ enrollment
// code passed to `sh -s --` and decodes the token out of it.
func tokenFromCloudInit(t *testing.T, body []byte) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatalf("response is not a JSON string: %v (%s)", err, body)
	}
	i := strings.Index(s, "sh -s -- '")
	if i < 0 {
		return ""
	}
	rest := s[i+len("sh -s -- '"):]
	j := strings.Index(rest, "'")
	if j < 0 {
		return ""
	}
	f, ok := enrollcode.Decode(rest[:j])
	if !ok {
		t.Fatalf("cloud-init enrollment code not decodable: %q", rest[:j])
	}
	return f.Token
}

func okCloud() CloudConfig {
	return CloudConfig{
		Kind:          "openstack",
		KeystoneURL:   "https://keystone.example/v3",
		AutoProvision: true,
		AutoApprove:   true,
		DefaultLabels: map[string]string{"env": "lab"},
	}
}

// --- tests ---

func TestVendordataUnknownCloud404(t *testing.T) {
	srv := testServerWithCloud(t, "kolla1", okCloud())
	w := postVendordata(t, srv, "nope", "tok", map[string]any{"instance-id": "i1"})
	if w.Code != 404 {
		t.Fatalf("unknown cloud: want 404, got %d", w.Code)
	}
}

func TestVendordataMissingToken401(t *testing.T) {
	srv := testServerWithCloud(t, "kolla1", okCloud())
	w := postVendordata(t, srv, "kolla1", "", map[string]any{"instance-id": "i1"})
	if w.Code != 401 {
		t.Fatalf("missing token: want 401, got %d", w.Code)
	}
}

func TestVendordataNonServiceTokenForbidden(t *testing.T) {
	srv := testServerWithCloud(t, "kolla1", okCloud())
	srv.clouds["kolla1"] = &fakeVerifier{session: &fakeSession{
		caller:  osCaller{ProjectName: "tenant-a"}, // NOT "service"
		servers: map[string]osServer{"i1": {TenantID: "p1", Status: "BUILD"}},
	}}
	w := postVendordata(t, srv, "kolla1", "tok", map[string]any{"instance-id": "i1", "project-id": "p1"})
	if w.Code != 403 {
		t.Fatalf("non-service token: want 403, got %d (%s)", w.Code, w.Body)
	}
}

func TestVendordataInstanceNotFound404(t *testing.T) {
	srv := testServerWithCloud(t, "kolla1", okCloud())
	srv.clouds["kolla1"] = &fakeVerifier{session: &fakeSession{
		caller:  osCaller{ProjectName: "service"},
		servers: map[string]osServer{}, // no such instance
	}}
	w := postVendordata(t, srv, "kolla1", "tok", map[string]any{"instance-id": "ghost"})
	if w.Code != 404 {
		t.Fatalf("instance not found: want 404, got %d", w.Code)
	}
}

// THE critical one: the binding key must use Nova's authoritative tenant_id, not
// the attacker-supplied body project-id, so a caller cannot bind another
// tenant's project by lying about project-id in the request body.
func TestVendordataConfusedDeputyUsesNovaProject(t *testing.T) {
	srv := testServerWithCloud(t, "kolla1", okCloud())
	srv.clouds["kolla1"] = &fakeVerifier{session: &fakeSession{
		caller:  osCaller{ProjectName: "service"},
		servers: map[string]osServer{"i1": {TenantID: "REAL-proj", Status: "BUILD"}},
	}}
	w := postVendordata(t, srv, "kolla1", "tok", map[string]any{
		"instance-id": "i1",
		"project-id":  "VICTIM-proj", // attacker lie — must be ignored
	})
	if w.Code != 200 {
		t.Fatalf("want 200, got %d (%s)", w.Code, w.Body)
	}
	if _, err := srv.store.GetSourceBinding(osProjectBindingKey("kolla1", "REAL-proj")); err != nil {
		t.Fatalf("binding for Nova's tenant_id not created: %v", err)
	}
	if _, err := srv.store.GetSourceBinding(osProjectBindingKey("kolla1", "VICTIM-proj")); err == nil {
		t.Fatalf("SECURITY: binding created for attacker-supplied body project-id")
	}
}

func TestVendordataAutoProvisionCreatesIsolatedWorkspace(t *testing.T) {
	srv := testServerWithCloud(t, "kolla1", okCloud())
	srv.clouds["kolla1"] = &fakeVerifier{session: &fakeSession{
		caller:   osCaller{ProjectName: "service"},
		servers:  map[string]osServer{"i1": {TenantID: "proj-aaaaaaaa1111", Status: "BUILD"}},
		projects: map[string]osProject{"proj-aaaaaaaa1111": {Name: "Engineering", DomainID: "d1"}},
	}}
	w := postVendordata(t, srv, "kolla1", "tok", map[string]any{"instance-id": "i1"})
	if w.Code != 200 {
		t.Fatalf("want 200, got %d (%s)", w.Code, w.Body)
	}
	b, err := srv.store.GetSourceBinding(osProjectBindingKey("kolla1", "proj-aaaaaaaa1111"))
	if err != nil {
		t.Fatalf("binding missing: %v", err)
	}
	if !b.AutoProvisioned {
		t.Fatalf("binding not marked auto-provisioned")
	}
	if _, err := srv.store.GetWorkspace(b.WorkspaceID); err != nil {
		t.Fatalf("auto-provisioned workspace missing: %v", err)
	}
	if !strings.HasPrefix(b.WorkspaceID, "engineering-") {
		t.Fatalf("workspace slug = %q, want engineering-<short>", b.WorkspaceID)
	}
	// The new workspace must have a real (non-deny-all) policy engine at runtime.
	if _, ok := srv.policyEngines[b.WorkspaceID]; !ok {
		t.Fatalf("auto-provisioned workspace has no policy engine")
	}
}

func TestVendordataUnboundNoAutoProvisionPends(t *testing.T) {
	cloud := okCloud()
	cloud.AutoProvision = false
	srv := testServerWithCloud(t, "kolla1", cloud)
	srv.clouds["kolla1"] = &fakeVerifier{session: &fakeSession{
		caller:  osCaller{ProjectName: "service"},
		servers: map[string]osServer{"i1": {TenantID: "unbound", Status: "BUILD"}},
	}}
	w := postVendordata(t, srv, "kolla1", "tok", map[string]any{"instance-id": "i1"})
	if w.Code != 200 {
		t.Fatalf("pending: want 200 empty cloud-init, got %d", w.Code)
	}
	var s string
	_ = json.Unmarshal(w.Body.Bytes(), &s)
	if strings.Contains(s, "install.sh") {
		t.Fatalf("unbound project must NOT get an install one-liner, got: %q", s)
	}
}

func TestVendordataPreBoundWorkspace(t *testing.T) {
	cloud := okCloud()
	cloud.AutoProvision = false
	srv := testServerWithCloud(t, "kolla1", cloud, WorkspaceConfig{
		ID:           "eng",
		Bindings:     []string{osProjectBindingKey("kolla1", "p-eng")},
		MemberGroups: []string{"eng"},
	})
	srv.clouds["kolla1"] = &fakeVerifier{session: &fakeSession{
		caller:  osCaller{ProjectName: "service"},
		servers: map[string]osServer{"i1": {TenantID: "p-eng", Status: "ACTIVE"}},
	}}
	w := postVendordata(t, srv, "kolla1", "tok", map[string]any{"instance-id": "i1"})
	if w.Code != 200 {
		t.Fatalf("want 200, got %d (%s)", w.Code, w.Body)
	}
	tok := tokenFromCloudInit(t, w.Body.Bytes())
	if tok == "" {
		t.Fatalf("no token in cloud-init: %s", w.Body)
	}
	rec, err := srv.store.UseToken(tok, time.Now())
	if err != nil {
		t.Fatalf("minted token invalid: %v", err)
	}
	if rec.WorkspaceID != "eng" {
		t.Fatalf("token workspace = %q, want eng", rec.WorkspaceID)
	}
}

// Nova hits the vendordata endpoint ~5x per boot — every retry for the same
// instance must get back the SAME token, so a single boot mints exactly one.
func TestVendordataIdempotentMint(t *testing.T) {
	srv := testServerWithCloud(t, "kolla1", okCloud())
	srv.clouds["kolla1"] = &fakeVerifier{session: &fakeSession{
		caller:  osCaller{ProjectName: "service"},
		servers: map[string]osServer{"i1": {TenantID: "p1", Status: "BUILD"}},
	}}
	var first string
	for i := 0; i < 5; i++ {
		w := postVendordata(t, srv, "kolla1", "tok", map[string]any{"instance-id": "i1"})
		if w.Code != 200 {
			t.Fatalf("hit %d: want 200, got %d", i, w.Code)
		}
		tok := tokenFromCloudInit(t, w.Body.Bytes())
		if i == 0 {
			first = tok
		} else if tok != first {
			t.Fatalf("hit %d minted a DIFFERENT token (%q != %q): idempotency broken", i, tok, first)
		}
	}
	// And exactly one of the 5 identical tokens is still redeemable once.
	if _, err := srv.store.UseToken(first, time.Now()); err != nil {
		t.Fatalf("the single minted token should be redeemable once: %v", err)
	}
}

func TestDeriveOSLabelsNamespacing(t *testing.T) {
	vd := vendordataBody{
		InstanceID: "i1",
		BootRoles:  "admin, member",
		Metadata:   map[string]string{"geneza.role": "db", "other": "ignored"},
	}
	got := deriveOSLabels("kolla1", "p1", vd, map[string]string{"env": "lab"})
	want := map[string]string{
		"env":                       "lab", // operator default, trusted
		"os:cloud":                  "kolla1",
		"os:project":                "p1",
		"os:instance":               "i1",
		"os.claim:boot-role:admin":  "1",
		"os.claim:boot-role:member": "1",
		"os.claim:role":             "db",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("label %q = %q, want %q", k, got[k], v)
		}
	}
	if _, leaked := got["other"]; leaked {
		t.Errorf("non-geneza metadata leaked into labels")
	}
	// A tenant must NOT be able to mint a bare operator-style label.
	if _, bad := got["role"]; bad {
		t.Errorf("tenant metadata escaped the os.claim: namespace")
	}
}

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"Engineering":     "engineering",
		"My Project!":     "my-project",
		"  spaced  out  ": "spaced-out",
		"":                "",
		"___":             "",
	}
	for in, want := range cases {
		if got := slugify(in); got != want {
			t.Errorf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCloudsConfigValidation(t *testing.T) {
	mk := func(clouds map[string]CloudConfig) error {
		cfg := &Config{
			DataDir: "/x", ClusterName: "t", PolicyFile: "/p",
			Clouds: clouds,
		}
		cfg.applyDefaults()
		return cfg.validate()
	}
	// require_nova_service_token is forced true regardless of the file.
	c := map[string]CloudConfig{"a": {Kind: "openstack", KeystoneURL: "https://k/v3", RequireNovaServiceToken: false}}
	cfg := &Config{DataDir: "/x", ClusterName: "t", PolicyFile: "/p", Clouds: c}
	cfg.applyDefaults()
	if !cfg.Clouds["a"].RequireNovaServiceToken {
		t.Fatalf("require_nova_service_token must be forced true regardless of the file value")
	}
	// Duplicate keystone_url across two service-uids is rejected (trailing-slash
	// normalized) so two clouds can't share one Keystone and impersonate each other.
	err := mk(map[string]CloudConfig{
		"a": {Kind: "openstack", KeystoneURL: "https://k:5000/v3"},
		"b": {Kind: "openstack", KeystoneURL: "https://k:5000/v3/"},
	})
	if err == nil || !strings.Contains(err.Error(), "share keystone_url") {
		t.Fatalf("dup keystone: want share-keystone error, got %v", err)
	}
	// Bad endpoint_interface rejected.
	if err := mk(map[string]CloudConfig{"a": {Kind: "openstack", KeystoneURL: "https://k/v3", EndpointInterface: "bogus"}}); err == nil {
		t.Fatalf("bad endpoint_interface: want error")
	}
	// Happy path.
	if err := mk(map[string]CloudConfig{"a": {Kind: "openstack", KeystoneURL: "https://k/v3"}}); err != nil {
		t.Fatalf("valid cloud rejected: %v", err)
	}
}

func TestSourceBindingStore(t *testing.T) {
	s, err := OpenStore(t.TempDir() + "/s.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	key := "openstack:project:kolla1:p1"
	if err := s.PutSourceBinding(&SourceBinding{Key: key, WorkspaceID: "w1"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSourceBinding(key)
	if err != nil || got.WorkspaceID != "w1" {
		t.Fatalf("get binding: %v %+v", err, got)
	}
	all, _ := s.ListSourceBindings()
	if len(all) != 1 {
		t.Fatalf("list: want 1, got %d", len(all))
	}
	if err := s.DeleteSourceBinding(key); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSourceBinding(key); err != ErrNotFound {
		t.Fatalf("after delete: want ErrNotFound, got %v", err)
	}
}

func TestOSMintOnce(t *testing.T) {
	s, err := OpenStore(t.TempDir() + "/s.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	n := 0
	mk := func() (string, error) { n++; return "gz-tok-" + strconv.Itoa(n), nil }
	tok := &TokenRecord{WorkspaceID: "w1", MaxUses: 1, ExpiresUnix: now.Add(time.Hour).Unix()}
	t1, reused, err := s.OSMintOnce("kolla1#i1", now, time.Hour, tok, mk)
	if err != nil || reused {
		t.Fatalf("first mint: reused=%v err=%v", reused, err)
	}
	t2, reused2, err := s.OSMintOnce("kolla1#i1", now, time.Hour, tok, mk)
	if err != nil || !reused2 || t2 != t1 {
		t.Fatalf("second mint must reuse: reused=%v t2=%q t1=%q err=%v", reused2, t2, t1, err)
	}
	// A different instance gets a different token.
	t3, _, _ := s.OSMintOnce("kolla1#i2", now, time.Hour, tok, mk)
	if t3 == t1 {
		t.Fatalf("different instance must get a different token")
	}
}
