package controller

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// The workspace policy lives in ONE settings key that each save overwrites, so an
// edit used to be unrecoverable: no diff, no rollback, no way to answer "what did
// this say before" — for the document that decides who may reach what.
func TestPolicyEditsAreRecoverable(t *testing.T) {
	srv, api, _ := buildLaunchServer(t, EmbedConfig{})
	tok := mintConsoleSession(t, srv, defaultWorkspace, "admin", roleWSAdmin)

	save := func(doc string) {
		t.Helper()
		r := httptest.NewRequest("PUT", "/api/v1/policy",
			strings.NewReader(`{"yaml":`+jsonString(doc)+`}`))
		r.Header.Set("Authorization", "Bearer "+tok)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		api.handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("save policy: %d %s", w.Code, w.Body.String())
		}
	}

	first := launchPolicyDoc
	// A trailing comment is a real edit that still parses.
	second := first + "\n# edited\n"
	save(first)
	save(second)

	r := httptest.NewRequest("GET", "/api/v1/policy/history", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	api.handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("history: %d %s", w.Code, w.Body.String())
	}
	var body struct {
		Revisions []struct {
			Yaml      string `json:"yaml"`
			UpdatedBy string `json:"updatedBy"`
		} `json:"revisions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Revisions) == 0 {
		t.Fatal("the replaced document must be retained so the edit can be undone")
	}
	// Newest-first: revision[0] is what the LAST save replaced.
	if !strings.Contains(body.Revisions[0].Yaml, "ws-admin") {
		t.Fatalf("unexpected retained revision: %.80q", body.Revisions[0].Yaml)
	}
	if body.Revisions[0].UpdatedBy == "" {
		t.Fatal("a revision must carry who wrote it, or provenance is lost")
	}

	// Saving the same document twice must not fill the history with duplicates.
	before := len(body.Revisions)
	save(second)
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/api/v1/policy/history", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	api.handler().ServeHTTP(w, r)
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Revisions) != before {
		t.Fatalf("a no-op save must not add a revision: %d -> %d", before, len(body.Revisions))
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
