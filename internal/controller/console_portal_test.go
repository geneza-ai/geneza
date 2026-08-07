package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func postPortalJSON(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func humanCaller() osCaller {
	return osCaller{
		UserName: "alice", UserID: "ks-alice", ProjectID: "proj-uuid-abcdef01",
		ProjectName: "research", ScopeProject: true, Roles: []string{"admin"},
		ExpiresAt: time.Now().Add(time.Hour), TokenID: "gAAAA-token",
	}
}

// The portal mints server-to-server and gets back a URL whose only credential is
// a single-use code; the customer's keystone token must never reach the browser.
// The resulting session is WORKSPACE-wide — that is the whole point, as opposed to
// a launch session pinned to one node — so the customer can manage their fleet.
func TestPortalConsoleHandoffYieldsAWorkspaceSession(t *testing.T) {
	srv, api, fake := buildAccessServer(t, true)
	h := api.handler()
	fake.session = &fakeSession{caller: humanCaller()}

	rr := postPortalJSON(t, h, "/openstack/kolla1/console", `{"token":"gAAAA-token"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("mint: want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var mint portalConsoleResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &mint); err != nil {
		t.Fatal(err)
	}
	if mint.Workspace == "" {
		t.Fatal("mint returned no workspace")
	}
	if strings.Contains(mint.ConsoleURL, "gAAAA") {
		t.Fatalf("keystone token leaked into the console URL: %q", mint.ConsoleURL)
	}
	if !strings.Contains(mint.ConsoleURL, "/console-bind?") || !strings.Contains(mint.ConsoleURL, "ct=") {
		t.Fatalf("unexpected console URL shape: %q", mint.ConsoleURL)
	}

	// Browser leg: burns the portal's code, delivers the companion cookie.
	ct := mint.ConsoleURL[strings.Index(mint.ConsoleURL, "ct=")+len("ct="):]
	req := httptest.NewRequest("GET", "/console-bind?cloud=kolla1&ct="+ct, nil)
	bind := httptest.NewRecorder()
	h.ServeHTTP(bind, req)
	if bind.Code != http.StatusSeeOther {
		t.Fatalf("bind: want 303, got %d (%s)", bind.Code, bind.Body.String())
	}
	loc := bind.Header().Get("Location")
	if !strings.Contains(loc, "/?handoff=") {
		t.Fatalf("bind redirect has no handoff code: %q", loc)
	}
	var cookie *http.Cookie
	for _, ck := range bind.Result().Cookies() {
		if ck.Name == handoffCookie {
			cookie = ck
		}
	}
	if cookie == nil {
		t.Fatal("bind delivered no companion cookie; the code alone would be enough to replay")
	}
	if !cookie.HttpOnly || !cookie.Secure {
		t.Fatalf("companion cookie must be HttpOnly+Secure, got %+v", cookie)
	}

	// The portal's code is single-use: a second bind must fail, or a leaked URL
	// in an access log would still be spendable.
	replay := httptest.NewRecorder()
	h.ServeHTTP(replay, httptest.NewRequest("GET", "/console-bind?cloud=kolla1&ct="+ct, nil))
	if replay.Code == http.StatusSeeOther {
		t.Fatal("the portal code was accepted twice")
	}

	// Swap for the real session and confirm it is workspace-wide, not node-pinned.
	code := loc[strings.Index(loc, "handoff=")+len("handoff="):]
	// The swap needs the companion cookie, so build the request directly.
	req2 := httptest.NewRequest("POST", "/api/v1/session/handoff", strings.NewReader(`{"code":"`+code+`"}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.AddCookie(cookie)
	sw := httptest.NewRecorder()
	h.ServeHTTP(sw, req2)
	if sw.Code != http.StatusOK {
		t.Fatalf("session swap: want 200, got %d (%s)", sw.Code, sw.Body.String())
	}
	var out sessionResponse
	if err := json.Unmarshal(sw.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Workspace != mint.Workspace {
		t.Fatalf("session workspace %q != minted %q", out.Workspace, mint.Workspace)
	}

	// Prove it behaviourally rather than by poking at storage: a node-pinned launch
	// session is refused by every console route that has not opted into scoped
	// sessions, so reaching a plain workspace route is what distinguishes the two.
	// This is the capability the whole feature exists for — fleet management, not
	// one shell.
	fleet := httptest.NewRequest("GET", "/api/v1/nodes", nil)
	fleet.Header.Set("Authorization", "Bearer "+out.Token)
	fr := httptest.NewRecorder()
	h.ServeHTTP(fr, fleet)
	if fr.Code != http.StatusOK {
		t.Fatalf("fleet listing: want 200 for a workspace session, got %d (%s)", fr.Code, fr.Body.String())
	}

	// And it must be able to mint an enrollment credential — the reason a customer
	// with a pre-existing VM needs this at all.
	mintTok := httptest.NewRequest("POST", "/api/v1/tokens", strings.NewReader(`{"ttlSeconds":600}`))
	mintTok.Header.Set("Authorization", "Bearer "+out.Token)
	mintTok.Header.Set("Content-Type", "application/json")
	mr := httptest.NewRecorder()
	h.ServeHTTP(mr, mintTok)
	if mr.Code != http.StatusOK {
		t.Fatalf("enrollment mint: want 200, got %d (%s)", mr.Code, mr.Body.String())
	}
	_ = srv
}

// The guards are the same ones every other access-plane entrypoint enforces; a
// portal must not be able to sidestep them by using this route instead.
func TestPortalConsoleGuards(t *testing.T) {
	t.Run("token in the query string is refused", func(t *testing.T) {
		_, api, fake := buildAccessServer(t, true)
		fake.session = &fakeSession{caller: humanCaller()}
		rr := postPortalJSON(t, api.handler(), "/openstack/kolla1/console?token=gAAAA-token", `{}`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400 for a query-string token, got %d (%s)", rr.Code, rr.Body.String())
		}
	})

	t.Run("service token is refused", func(t *testing.T) {
		_, api, fake := buildAccessServer(t, true)
		c := humanCaller()
		// The service project name is what the guard checks (plus the service role).
		c.UserName, c.ProjectName, c.ScopeProject = "nova", "service", true
		fake.session = &fakeSession{caller: c}
		rr := postPortalJSON(t, api.handler(), "/openstack/kolla1/console", `{"token":"gAAAA-token"}`)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("want 403 for a service token, got %d (%s)", rr.Code, rr.Body.String())
		}
	})

	t.Run("unknown cloud is a routing 404, never an auth decision", func(t *testing.T) {
		_, api, fake := buildAccessServer(t, true)
		fake.session = &fakeSession{caller: humanCaller()}
		rr := postPortalJSON(t, api.handler(), "/openstack/nosuchcloud/console", `{"token":"gAAAA-token"}`)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("want 404 for an unknown cloud, got %d", rr.Code)
		}
	})

	t.Run("disabled for the cloud", func(t *testing.T) {
		_, api, fake := buildAccessServer(t, false)
		fake.session = &fakeSession{caller: humanCaller()}
		rr := postPortalJSON(t, api.handler(), "/openstack/kolla1/console", `{"token":"gAAAA-token"}`)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("want 403 when the cloud has not opted in, got %d (%s)", rr.Code, rr.Body.String())
		}
	})
}
