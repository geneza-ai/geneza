package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func postForm(t *testing.T, h http.Handler, path string, form url.Values, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestTrustedDashboardHandoff(t *testing.T) {
	srv, api, fake := buildAccessServer(t, true)
	h := api.handler()
	// The validated keystone token is a clean human project-scoped token.
	fake.session = &fakeSession{caller: osCaller{
		UserName: "alice", UserID: "ks-alice", ProjectID: "proj-uuid-abcdef01",
		ProjectName: "research", ScopeProject: true, Roles: []string{"admin"},
		ExpiresAt: time.Now().Add(time.Hour), TokenID: "gAAAA-token",
	}}

	// 1. Horizon websso form-POSTs the token; we 303 to a clean URL + set a cookie.
	rr := postForm(t, h, "/openstack/kolla1", url.Values{"token": {"gAAAA-token"}}, nil)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("websso POST: want 303, got %d (%s)", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/?handoff=") {
		t.Fatalf("redirect has no handoff code: %q", loc)
	}
	if strings.Contains(loc, "token") || strings.Contains(loc, "gAAAA") {
		t.Fatalf("keystone token leaked into the redirect URL: %q", loc)
	}
	if rr.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("missing no-referrer policy")
	}
	code := loc[strings.Index(loc, "handoff=")+len("handoff="):]
	var cookie *http.Cookie
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == handoffCookie {
			cookie = ck
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("handoff cookie missing or not hardened: %+v", cookie)
	}

	// 2. The SPA swaps the code (+cookie) for the session.
	redeem := func(withCookie bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/v1/session/handoff", strings.NewReader(`{"code":`+jsonStr(code)+`}`))
		req.Header.Set("Content-Type", "application/json")
		if withCookie {
			req.AddCookie(cookie)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	rr = redeem(true)
	if rr.Code != 200 {
		t.Fatalf("handoff redeem: %d %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["token"] == "" || resp["provider"] != nil && resp["provider"] != "keystone" {
		// provider isn't in sessionResponse; assert the session works instead.
	}
	tok, _ := resp["token"].(string)
	if tok == "" || resp["workspace"] == "" {
		t.Fatalf("handoff did not yield a session: %v", resp)
	}
	// The minted session is keystone-sourced ws-admin (alice = first user).
	if resp["admin"] != true {
		t.Fatalf("alice (keystone admin / first user) should be ws-admin: %v", resp)
	}

	// 3. The handoff code is single-use: replaying it fails.
	if rr := redeem(true); rr.Code == 200 {
		t.Fatalf("replayed handoff code must fail, got 200")
	}

	// The session authenticates the probe.
	if code, _ := doJSON(t, h, "GET", "/api/v1/session", tok, ""); code != 200 {
		t.Fatalf("handoff session probe: %d", code)
	}
	_ = srv
}

func TestTrustedDashboardRejectsQueryTokenAndService(t *testing.T) {
	srv, api, fake := buildAccessServer(t, true)
	_ = srv
	h := api.handler()

	// A token in the QUERY string is refused without processing.
	rr := postForm(t, h, "/openstack/kolla1?token=leak", url.Values{}, nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("query-string token must be 400, got %d", rr.Code)
	}

	// A service-scoped token is rejected.
	fake.session = &fakeSession{caller: osCaller{
		UserName: "nova", ProjectID: "svc", ProjectName: "service", ScopeProject: true,
		Roles: []string{"service"}, ExpiresAt: time.Now().Add(time.Hour),
	}}
	rr = postForm(t, h, "/openstack/kolla1", url.Values{"token": {"svc-token"}}, nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("service token must be 403, got %d (%s)", rr.Code, rr.Body.String())
	}

	// A handoff redeem without the cookie fails (the code plus the cookie form a double secret).
	fake.session = &fakeSession{caller: osCaller{
		UserName: "bob", UserID: "ks-bob", ProjectID: "p2", ProjectName: "team",
		ScopeProject: true, Roles: []string{"member"}, ExpiresAt: time.Now().Add(time.Hour),
	}}
	rr = postForm(t, h, "/openstack/kolla1", url.Values{"token": {"t"}}, nil)
	loc := rr.Header().Get("Location")
	code := loc[strings.Index(loc, "handoff=")+len("handoff="):]
	req := httptest.NewRequest("POST", "/api/v1/session/handoff", strings.NewReader(`{"code":`+jsonStr(code)+`}`))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req) // no cookie
	if rr.Code == 200 {
		t.Fatalf("handoff redeem without the cookie must fail, got 200")
	}
}
