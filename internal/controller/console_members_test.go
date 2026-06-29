package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newMembersTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatalf("init: %v", err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv
}

// TestPerWorkspaceMemberGroups proves a member row's groups are authoritative for
// that workspace: the same principal resolves to different roles depending on the
// row's groups, and the global authn groups apply only when no row exists.
func TestPerWorkspaceMemberGroups(t *testing.T) {
	srv := newMembersTestServer(t) // test policy binds group "admins" -> role "ops"

	// No row: the global authn groups drive resolution (back-compat).
	if r := srv.rolesForMember(defaultWorkspace, providerLocal, "carol", "carol", []string{"admins"}); len(r) != 1 || r[0] != "ops" {
		t.Fatalf("no-row carol with global group admins should map to [ops], got %v", r)
	}

	// Row with groups=[admins]: row groups are authoritative -> [ops] even with NO
	// global groups passed.
	if err := srv.store.PutMember(defaultWorkspace, &MemberRecord{
		Provider: providerLocal, Username: "carol", Subject: "carol", Groups: []string{"admins"},
	}); err != nil {
		t.Fatal(err)
	}
	if r := srv.rolesForMember(defaultWorkspace, providerLocal, "carol", "carol", nil); len(r) != 1 || r[0] != "ops" {
		t.Fatalf("row group admins should map to [ops] regardless of global groups, got %v", r)
	}

	// Row with NO groups + a direct role: the row overrides the global groups, so the
	// global "admins" no longer leaks in -> no "ops"; only the stored role remains.
	if err := srv.store.PutMember(defaultWorkspace, &MemberRecord{
		Provider: providerLocal, Username: "carol", Subject: "carol", Roles: []string{roleWSMember},
	}); err != nil {
		t.Fatal(err)
	}
	r := srv.rolesForMember(defaultWorkspace, providerLocal, "carol", "carol", []string{"admins"})
	if contains(r, "ops") {
		t.Fatalf("an empty-group member row must override the global groups, got %v", r)
	}
	if !contains(r, roleWSMember) {
		t.Fatalf("stored role missing: %v", r)
	}
}

func TestConsoleMembersCRUD(t *testing.T) {
	srv := newMembersTestServer(t)
	c := &consoleAPI{s: srv}
	adm := &consoleUser{Name: "adm", Provider: providerLocal, Subject: "adm", Workspace: defaultWorkspace, Roles: []string{roleWSAdmin}, Admin: true}

	put := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/members", strings.NewReader(body))
		w := httptest.NewRecorder()
		c.handlePutMember(w, r, adm)
		return w
	}

	// A reserved cluster role is refused.
	if w := put(`{"username":"dave","roles":["admin"]}`); w.Code != http.StatusForbidden {
		t.Fatalf("reserved role must be refused, got %d", w.Code)
	}
	// An unknown / non-workspace role is refused.
	if w := put(`{"username":"dave","roles":["root"]}`); w.Code != http.StatusForbidden {
		t.Fatalf("non-grantable role must be refused, got %d", w.Code)
	}
	// A valid assignment lands in the session's workspace, subject defaults to username.
	if w := put(`{"username":"dave","roles":["ws-member"],"groups":["ops"]}`); w.Code != http.StatusOK {
		t.Fatalf("valid put failed: %d %s", w.Code, w.Body.String())
	}
	m, err := srv.store.GetMember(defaultWorkspace, providerLocal, "dave")
	if err != nil {
		t.Fatalf("member not persisted: %v", err)
	}
	if m.Subject != "dave" || len(m.Roles) != 1 || m.Roles[0] != roleWSMember || len(m.Groups) != 1 || m.Groups[0] != "ops" {
		t.Fatalf("member stored wrong: %+v", m)
	}

	// It is scoped to the session workspace — a different tenant does not see it.
	other := &consoleUser{Name: "adm2", Workspace: "prod", Roles: []string{roleWSAdmin}, Admin: true}
	rw := httptest.NewRecorder()
	c.handleListMembers(rw, httptest.NewRequest(http.MethodGet, "/api/v1/members", nil), other)
	var listed struct {
		Members []map[string]any `json:"members"`
	}
	_ = json.Unmarshal(rw.Body.Bytes(), &listed)
	for _, mm := range listed.Members {
		if mm["subject"] == "dave" {
			t.Fatal("member leaked across workspaces")
		}
	}

	// List in the right workspace shows dave.
	rw = httptest.NewRecorder()
	c.handleListMembers(rw, httptest.NewRequest(http.MethodGet, "/api/v1/members", nil), adm)
	if !strings.Contains(rw.Body.String(), `"dave"`) {
		t.Fatalf("dave missing from own-workspace list: %s", rw.Body.String())
	}

	// Delete removes it.
	dr := httptest.NewRequest(http.MethodDelete, "/api/v1/members/local/dave", nil)
	dr.SetPathValue("provider", "local")
	dr.SetPathValue("subject", "dave")
	dw := httptest.NewRecorder()
	c.handleDeleteMember(dw, dr, adm)
	if dw.Code != http.StatusOK {
		t.Fatalf("delete failed: %d %s", dw.Code, dw.Body.String())
	}
	if _, err := srv.store.GetMember(defaultWorkspace, providerLocal, "dave"); err == nil {
		t.Fatal("member still present after delete")
	}
}
