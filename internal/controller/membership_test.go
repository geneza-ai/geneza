package controller

import (
	"errors"
	"sync"
	"testing"
)

func TestMembershipCRUDAndCrossProvider(t *testing.T) {
	s := testStore(t)

	// keystone:alice and oidc:alice are DISTINCT principals that coexist.
	ksAlice := &MemberRecord{Provider: providerKeystone, Username: "alice", Subject: "ks-uid-1", SourceUID: "kolla1", Roles: []string{"ws-member"}}
	oidcAlice := &MemberRecord{Provider: providerOIDC, Username: "alice", Subject: "oidc-sub-9", Roles: []string{roleWSAdmin}}
	if err := s.PutMember("ws1", ksAlice); err != nil {
		t.Fatalf("put ks alice: %v", err)
	}
	if err := s.PutMember("ws1", oidcAlice); err != nil {
		t.Fatalf("put oidc alice: %v", err)
	}

	got, err := s.GetMember("ws1", providerKeystone, "ks-uid-1")
	if err != nil || len(got.Roles) != 1 || got.Roles[0] != "ws-member" {
		t.Fatalf("ks alice roles: %v err=%v", got, err)
	}
	got2, err := s.GetMember("ws1", providerOIDC, "oidc-sub-9")
	if err != nil || got2.Roles[0] != roleWSAdmin {
		t.Fatalf("oidc alice roles: %v err=%v", got2, err)
	}
	if list, _ := s.ListMembers("ws1"); len(list) != 2 {
		t.Fatalf("want 2 members, got %d", len(list))
	}

	// Cross-tenant isolation: the same key in another workspace is NotFound.
	if _, err := s.GetMember("ws2", providerKeystone, "ks-uid-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant read must be NotFound, got %v", err)
	}

	// ListMemberWorkspaces only returns workspaces the principal is actually in.
	if err := s.PutMember("ws2", &MemberRecord{Provider: providerOIDC, Username: "alice", Subject: "oidc-sub-9", Roles: []string{"ws-viewer"}}); err != nil {
		t.Fatalf("put oidc alice ws2: %v", err)
	}
	wss, _ := s.ListMemberWorkspaces(providerOIDC, "oidc-sub-9")
	if len(wss) != 2 || wss[0] != "ws1" || wss[1] != "ws2" {
		t.Fatalf("oidc alice workspaces: %v", wss)
	}
	ksWss, _ := s.ListMemberWorkspaces(providerKeystone, "ks-uid-1")
	if len(ksWss) != 1 || ksWss[0] != "ws1" {
		t.Fatalf("ks alice workspaces: %v", ksWss)
	}

	// Delete removes only the targeted principal.
	if err := s.DeleteMember("ws1", providerKeystone, "ks-uid-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetMember("ws1", providerKeystone, "ks-uid-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted member must be NotFound, got %v", err)
	}
	if _, err := s.GetMember("ws1", providerOIDC, "oidc-sub-9"); err != nil {
		t.Fatalf("sibling member must survive delete, got %v", err)
	}
}

func TestPutMemberStripsReservedRoles(t *testing.T) {
	s := testStore(t)
	if err := s.PutMember("ws1", &MemberRecord{Provider: providerKeystone, Username: "evil", Subject: "x", Roles: []string{roleAdmin, rolePlatformAdmin, roleWSAdmin}}); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, _ := s.GetMember("ws1", providerKeystone, "x")
	for _, r := range got.Roles {
		if reservedRoles[r] {
			t.Fatalf("a persisted member must never carry a reserved cluster role, got %v", got.Roles)
		}
	}
	if len(got.Roles) != 1 || got.Roles[0] != roleWSAdmin {
		t.Fatalf("want [ws-admin], got %v", got.Roles)
	}
}

func TestMemberKeyRejectsColon(t *testing.T) {
	s := testStore(t)
	if err := s.PutMember("ws1", &MemberRecord{Provider: providerKeystone, Username: "a", Subject: "has:colon", Roles: []string{"ws-viewer"}}); err == nil {
		t.Fatalf("a subject containing ':' must be rejected (it would corrupt the provider:subject member key)")
	}
}

// TestUpsertFirstAdminRace: exactly one of N concurrent first logins into an
// empty workspace wins ws-admin; everyone else gets their mapped role.
func TestUpsertFirstAdminRace(t *testing.T) {
	s := testStore(t)
	const n = 12
	var wg sync.WaitGroup
	firstCount := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := &MemberRecord{
				Provider: providerKeystone,
				Username: "u",
				Subject:  subjectN(i),
				Roles:    []string{"ws-viewer"}, // the role_map default for non-first joiners
				AddedBy:  "auto:keystone:role_map",
			}
			isFirst, err := s.UpsertFirstAdmin("auto-ws", rec)
			if err != nil {
				t.Errorf("upsert %d: %v", i, err)
				return
			}
			firstCount[i] = isFirst
		}(i)
	}
	wg.Wait()

	admins := 0
	for i := 0; i < n; i++ {
		if firstCount[i] {
			admins++
		}
	}
	if admins != 1 {
		t.Fatalf("exactly one first-admin expected, got %d", admins)
	}
	// And exactly one stored member carries ws-admin; the rest ws-viewer.
	members, _ := s.ListMembers("auto-ws")
	if len(members) != n {
		t.Fatalf("want %d members, got %d", n, len(members))
	}
	wsAdmins := 0
	for _, m := range members {
		switch {
		case contains(m.Roles, roleWSAdmin):
			wsAdmins++
		case !contains(m.Roles, "ws-viewer"):
			t.Fatalf("non-admin member should be ws-viewer, got %v", m.Roles)
		}
	}
	if wsAdmins != 1 {
		t.Fatalf("exactly one stored ws-admin expected, got %d", wsAdmins)
	}
}

// TestUpsertFirstAdminRelogin: an existing member re-logging in keeps their
// roles (a promotion sticks) and never re-triggers first-admin.
func TestUpsertFirstAdminRelogin(t *testing.T) {
	s := testStore(t)
	rec := &MemberRecord{Provider: providerKeystone, Username: "boss", Subject: "s1", Roles: []string{"ws-viewer"}}
	first, _ := s.UpsertFirstAdmin("ws", rec)
	if !first || !contains(rec.Roles, roleWSAdmin) {
		t.Fatalf("first joiner must be ws-admin, got first=%v roles=%v", first, rec.Roles)
	}
	// Re-login with a different (mapped) role set must NOT downgrade the admin.
	rec2 := &MemberRecord{Provider: providerKeystone, Username: "boss-renamed", Subject: "s1", Roles: []string{"ws-viewer"}, Groups: []string{"g"}}
	first2, _ := s.UpsertFirstAdmin("ws", rec2)
	if first2 {
		t.Fatalf("re-login must not be first-admin")
	}
	if !contains(rec2.Roles, roleWSAdmin) {
		t.Fatalf("re-login must preserve the stored ws-admin role, got %v", rec2.Roles)
	}
	stored, _ := s.GetMember("ws", providerKeystone, "s1")
	if stored.Username != "boss-renamed" || len(stored.Groups) != 1 {
		t.Fatalf("re-login must refresh display name/groups, got %+v", stored)
	}
}

func subjectN(i int) string {
	return "subj-" + string(rune('a'+i))
}

// TestRolesForMemberProviderQualified: the config policy `users:[alice]` binding
// applies to the LOCAL/OIDC alice but NEVER to a keystone principal that happens
// to share the name — keystone roles come only from store membership.
func TestRolesForMemberProviderQualified(t *testing.T) {
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatalf("init: %v", err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// local alice -> policy binding grants "ops".
	if r := srv.rolesForMember(defaultWorkspace, providerLocal, "alice", "alice", nil); len(r) != 1 || r[0] != "ops" {
		t.Fatalf("local alice should get [ops] from policy, got %v", r)
	}
	// keystone "alice" (different person) gets NOTHING from the config binding.
	if r := srv.rolesForMember(defaultWorkspace, providerKeystone, "alice", "ks-sub-1", nil); len(r) != 0 {
		t.Fatalf("keystone alice must not inherit the config policy binding, got %v", r)
	}
	// Once joined via store membership, keystone alice gets her mapped role.
	if err := srv.store.PutMember(defaultWorkspace, &MemberRecord{Provider: providerKeystone, Username: "alice", Subject: "ks-sub-1", Roles: []string{"ws-member"}}); err != nil {
		t.Fatalf("put member: %v", err)
	}
	if r := srv.rolesForMember(defaultWorkspace, providerKeystone, "alice", "ks-sub-1", nil); len(r) != 1 || r[0] != "ws-member" {
		t.Fatalf("keystone alice should get [ws-member] from store, got %v", r)
	}
	// A reserved role injected into a member row never surfaces.
	if err := srv.store.PutMember(defaultWorkspace, &MemberRecord{Provider: providerOIDC, Username: "x", Subject: "oidc-x", Roles: []string{"ws-member"}}); err != nil {
		t.Fatalf("put member x: %v", err)
	}
	for _, r := range srv.rolesForMember(defaultWorkspace, providerOIDC, "x", "oidc-x", nil) {
		if reservedRoles[r] {
			t.Fatalf("rolesForMember leaked a reserved role: %v", r)
		}
	}
}
