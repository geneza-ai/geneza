package controller

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"geneza.io/internal/enrollcode"
)

// buildInstanceServer is buildAccessServer with the launch plane enabled, which is
// what gates these endpoints: they exist to make an instance launchable.
func buildInstanceServer(t *testing.T) (*Server, *consoleAPI, *fakeVerifier) {
	t.Helper()
	srv, api, fake := buildAccessServer(t, true)
	cl := srv.cfg.Clouds["kolla1"]
	cl.Launch.Allow = true
	srv.cfg.Clouds["kolla1"] = cl
	// The enrollment code binds the token to the pinned root fingerprint; without a
	// root the code is withheld entirely and a test asserting on it would be
	// silently vacuous. Give it one.
	rootPub := filepath.Join(t.TempDir(), "root.pub")
	if err := os.WriteFile(rootPub, []byte(
		"-----BEGIN PUBLIC KEY-----\n"+
			"MCowBQYDK2VwAyEALaKgDFdpt/6Ka0BZkCY7qCa6TKUPNhS7CSEMUpQnXtw=\n"+
			"-----END PUBLIC KEY-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv.cfg.RootPubkeyFile = rootPub
	if srv.rootFingerprint() == "" {
		t.Fatal("precondition: the server must serve a root fingerprint")
	}
	return srv, api, fake
}

func instanceCaller(project string) osCaller {
	return osCaller{
		UserName: "alice", UserID: "ks-alice", ProjectID: project,
		ProjectName: "research", ScopeProject: true, Roles: []string{"member"},
		ExpiresAt: time.Now().Add(time.Hour), TokenID: "gAAAA-token",
	}
}

// The instance id a caller sends is a REQUEST, never an assertion. It is believed
// only after Nova confirms the instance exists AND that its authoritative tenant_id
// is the caller's own project — residual risk #1's prescribed fix applied to a
// tenant-driven path. Without that check any project member could mint a token
// stamping another project's instance onto their machine and collect its shells.
func TestEnrollTokenRefusesAnInstanceOutsideTheCallersProject(t *testing.T) {
	const mine, theirs = "proj-uuid-abcdef01", "someone-elses-project"

	t.Run("nova says the instance belongs to another project", func(t *testing.T) {
		_, api, fake := buildInstanceServer(t)
		fake.session = &fakeSession{
			caller:  instanceCaller(mine),
			servers: map[string]osServer{"i-1": {TenantID: theirs, Status: "ACTIVE"}},
		}
		rr := postPortalJSON(t, api.handler(), "/openstack/kolla1/enroll-token",
			`{"token":"gAAAA-token","instance_id":"i-1"}`)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("want 403 for a foreign instance, got %d (%s)", rr.Code, rr.Body.String())
		}
	})

	t.Run("nova does not know the instance", func(t *testing.T) {
		_, api, fake := buildInstanceServer(t)
		// No entry for the id: the fake returns the same not-found Nova would.
		fake.session = &fakeSession{caller: instanceCaller(mine), servers: map[string]osServer{}}
		rr := postPortalJSON(t, api.handler(), "/openstack/kolla1/enroll-token",
			`{"token":"gAAAA-token","instance_id":"i-nope"}`)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("want 404 for an unknown instance, got %d (%s)", rr.Code, rr.Body.String())
		}
	})

	t.Run("token in the query string is refused", func(t *testing.T) {
		_, api, fake := buildInstanceServer(t)
		fake.session = &fakeSession{caller: instanceCaller(mine), servers: map[string]osServer{}}
		rr := postPortalJSON(t, api.handler(), "/openstack/kolla1/enroll-token?token=x",
			`{"instance_id":"i-1"}`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rr.Code)
		}
	})

	t.Run("service tokens are refused, as everywhere else on the access plane", func(t *testing.T) {
		_, api, fake := buildInstanceServer(t)
		c := instanceCaller(mine)
		c.UserName, c.ProjectName = "nova", "service"
		fake.session = &fakeSession{caller: c, servers: map[string]osServer{"i-1": {TenantID: mine}}}
		rr := postPortalJSON(t, api.handler(), "/openstack/kolla1/enroll-token",
			`{"token":"gAAAA-token","instance_id":"i-1"}`)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("want 403 for a service token, got %d", rr.Code)
		}
	})
}

// The happy path must stamp the three trusted keys from VERIFIED sources: the
// instance Nova confirmed, the caller's own authoritative project, and the routed
// cloud. Anything the caller sent beyond the instance request is irrelevant.
func TestEnrollTokenStampsVerifiedLabels(t *testing.T) {
	const mine = "proj-uuid-abcdef01"
	srv, api, fake := buildInstanceServer(t)
	fake.session = &fakeSession{
		caller:  instanceCaller(mine),
		servers: map[string]osServer{"i-42": {TenantID: mine, Status: "ACTIVE"}},
	}

	rr := postPortalJSON(t, api.handler(), "/openstack/kolla1/enroll-token",
		`{"token":"gAAAA-token","instance_id":"i-42"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var out enrollTokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.EnrollCode == "" {
		t.Fatal("no enrollment code returned")
	}
	if out.Instance != "i-42" || out.Project != mine {
		t.Fatalf("response instance/project = %q/%q", out.Instance, out.Project)
	}

	// The minted token must carry the trusted labels, or the enrolled node is not
	// launchable and the whole exercise is pointless.
	f, ok := enrollcode.Decode(out.EnrollCode)
	if !ok {
		t.Fatalf("enrollment code does not decode: %q", out.EnrollCode)
	}
	rec, err := srv.store.UseToken(f.Token, time.Now())
	if err != nil {
		t.Fatalf("minted token is not usable: %v", err)
	}
	if rec.Labels[launchInstanceLabel] != "i-42" {
		t.Errorf("os:instance = %q, want i-42", rec.Labels[launchInstanceLabel])
	}
	if rec.Labels[launchProjectLabel] != mine {
		t.Errorf("os:project = %q, want the caller's own project", rec.Labels[launchProjectLabel])
	}
	if rec.Labels[osCloudLabel] != "kolla1" {
		t.Errorf("os:cloud = %q, want the routed cloud", rec.Labels[osCloudLabel])
	}
	if rec.MaxUses != 1 {
		t.Errorf("maxUses = %d, want 1: an enrollment credential is not reusable", rec.MaxUses)
	}
}

// Minting for an instance that already has a node would hand out a credential whose
// enrollment is guaranteed to be refused by the uniqueness rule, so it is refused
// up front with the reason rather than failing later on the VM.
func TestEnrollTokenRefusesAnAlreadyEnrolledInstance(t *testing.T) {
	const mine = "proj-uuid-abcdef01"
	srv, api, fake := buildInstanceServer(t)
	fake.session = &fakeSession{
		caller:  instanceCaller(mine),
		servers: map[string]osServer{"i-42": {TenantID: mine, Status: "ACTIVE"}},
	}
	// Seed a node already wearing the instance, in the workspace the caller resolves to.
	rr := postPortalJSON(t, api.handler(), "/openstack/kolla1/instance-status",
		`{"token":"gAAAA-token","instance_id":"i-42"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status probe: %d (%s)", rr.Code, rr.Body.String())
	}
	var st instanceStatusResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &st)
	if st.Enrolled {
		t.Fatal("nothing is enrolled yet")
	}

	b, err := srv.store.GetSourceBinding(osProjectBindingKey("kolla1", mine))
	if err != nil {
		t.Fatalf("no binding for the caller's project: %v", err)
	}
	ws := b.WorkspaceID
	if err := srv.store.PutNode(ws, &NodeRecord{
		ID: "n-existing", Name: "web-01",
		Labels: map[string]string{
			launchInstanceLabel: "i-42", launchProjectLabel: mine, osCloudLabel: "kolla1",
		},
	}); err != nil {
		t.Fatal(err)
	}

	rr = postPortalJSON(t, api.handler(), "/openstack/kolla1/enroll-token",
		`{"token":"gAAAA-token","instance_id":"i-42"}`)
	if rr.Code != http.StatusConflict {
		t.Fatalf("want 409 for an already-enrolled instance, got %d (%s)", rr.Code, rr.Body.String())
	}

	// And the status probe now reports it, which is what the portal branches on.
	rr = postPortalJSON(t, api.handler(), "/openstack/kolla1/instance-status",
		`{"token":"gAAAA-token","instance_id":"i-42"}`)
	_ = json.Unmarshal(rr.Body.Bytes(), &st)
	if !st.Enrolled || st.NodeName != "web-01" {
		t.Fatalf("status = %+v, want enrolled web-01", st)
	}
}

// The response drives what the portal tells the customer, so it must describe what
// the token actually does. Reporting the cloud's vendordata auto_approve setting
// here made the portal warn that every enrolment would land pending, when this path
// mints an auto-approving token regardless of that setting.
func TestEnrollTokenReportsTheTokensOwnAutoApprove(t *testing.T) {
	const mine = "proj-uuid-abcdef01"
	srv, api, fake := buildInstanceServer(t)
	// The cloud's vendordata setting is false, as it is on a production cloud.
	cl := srv.cfg.Clouds["kolla1"]
	cl.AutoApprove = false
	srv.cfg.Clouds["kolla1"] = cl
	fake.session = &fakeSession{
		caller:  instanceCaller(mine),
		servers: map[string]osServer{"i-77": {TenantID: mine, Status: "ACTIVE"}},
	}

	rr := postPortalJSON(t, api.handler(), "/openstack/kolla1/enroll-token",
		`{"token":"gAAAA-token","instance_id":"i-77"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var out enrollTokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.AutoApprove {
		t.Error("response says the enrolment will land pending, but the token auto-approves")
	}
	f, ok := enrollcode.Decode(out.EnrollCode)
	if !ok {
		t.Fatal("code does not decode")
	}
	rec, err := srv.store.UseToken(f.Token, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !rec.AutoApprove {
		t.Error("the minted token does not auto-approve, so the customer must wait for an operator")
	}
	if rec.AutoApprove != out.AutoApprove {
		t.Errorf("response (%v) disagrees with the token (%v)", out.AutoApprove, rec.AutoApprove)
	}
}
