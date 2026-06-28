package controller

import (
	"net/http"
	"testing"
)

// TestConsoleSubdomainRoutes drives the reservation REST surface through the real
// console mux: an admin reserves, lists, and releases; the cap and uniqueness are
// enforced; a non-admin member is denied the mutations but may list.
func TestConsoleSubdomainRoutes(t *testing.T) {
	srv := newReplayServer(t)
	srv.cfg.ManagedDomain = ManagedDomainConfig{
		Domains: []ManagedDomainEntry{{Base: "geneza.app", DNSProvider: "cf"}},
	}
	api, err := srv.newConsoleAPI()
	if err != nil {
		t.Fatalf("console api: %v", err)
	}
	h := api.handler()
	const ws = defaultWorkspace
	admin := mintConsoleSession(t, srv, ws, "adm", roleWSAdmin)
	member := mintConsoleSession(t, srv, ws, "mem", roleWSMember)

	// List starts empty, advertises the domain and cap.
	code, resp := doJSON(t, h, "GET", "/api/v1/subdomains", member, "")
	if code != http.StatusOK {
		t.Fatalf("list: %d", code)
	}
	if resp["enabled"] != true || resp["max"].(float64) != 3 {
		t.Fatalf("list metadata: %v", resp)
	}
	if doms, _ := resp["domains"].([]any); len(doms) != 1 || doms[0] != "geneza.app" {
		t.Fatalf("domains: %v", resp["domains"])
	}

	// A member cannot reserve.
	if code, _ := doJSON(t, h, "POST", "/api/v1/subdomains", member, `{"domain":"geneza.app","label":"acme"}`); code != http.StatusForbidden {
		t.Fatalf("member reserve: want 403, got %d", code)
	}

	// Admin reserves a label.
	code, resp = doJSON(t, h, "POST", "/api/v1/subdomains", admin, `{"domain":"geneza.app","label":"acme"}`)
	if code != http.StatusOK {
		t.Fatalf("reserve: %d %v", code, resp)
	}
	if resp["zone"] != "acme.geneza.app" {
		t.Fatalf("zone: %v", resp)
	}

	// An unknown domain is rejected.
	if code, _ := doJSON(t, h, "POST", "/api/v1/subdomains", admin, `{"domain":"evil.com","label":"x"}`); code != http.StatusBadRequest {
		t.Fatalf("unknown domain: want 400, got %d", code)
	}

	// Re-reserving the same label by the same workspace is idempotent (200).
	if code, _ := doJSON(t, h, "POST", "/api/v1/subdomains", admin, `{"domain":"geneza.app","label":"acme"}`); code != http.StatusOK {
		t.Fatalf("idempotent reserve: %d", code)
	}

	// Cap: two more (total 3) ok, the fourth is a 409.
	for _, l := range []string{"b", "c"} {
		if code, _ := doJSON(t, h, "POST", "/api/v1/subdomains", admin, `{"domain":"geneza.app","label":"`+l+`"}`); code != http.StatusOK {
			t.Fatalf("reserve %s: %d", l, code)
		}
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/subdomains", admin, `{"domain":"geneza.app","label":"d"}`); code != http.StatusConflict {
		t.Fatalf("over cap: want 409, got %d", code)
	}

	// A different workspace cannot take an owned label.
	other := mintConsoleSession(t, srv, "wsOther", "mallory", roleWSAdmin)
	if err := srv.store.PutWorkspace(&WorkspaceRecord{ID: "wsOther", OverlayCIDR: "100.64.1.0/24"}); err != nil {
		t.Fatal(err)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/subdomains", other, `{"domain":"geneza.app","label":"acme"}`); code != http.StatusConflict {
		t.Fatalf("cross-workspace claim: want 409, got %d", code)
	}

	// List now shows three for ws.
	code, resp = doJSON(t, h, "GET", "/api/v1/subdomains", admin, "")
	if recs, _ := resp["reservations"].([]any); code != http.StatusOK || len(recs) != 3 {
		t.Fatalf("list after reserve: %d %v", code, resp["reservations"])
	}

	// Release one, then the label is free again.
	if code, _ := doJSON(t, h, "DELETE", "/api/v1/subdomains/geneza.app/acme", admin, ""); code != http.StatusOK {
		t.Fatalf("release: %d", code)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/subdomains", other, `{"domain":"geneza.app","label":"acme"}`); code != http.StatusOK {
		t.Fatalf("reclaim after release: %d", code)
	}
}
