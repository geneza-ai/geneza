package controller

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// The visual editor edits a structure; the server turns it back into the canonical
// document. Both directions must go through the SAME parser that stores it, or the
// console gets a second, drifting implementation of the schema that decides who may
// reach what.
func TestPolicyRendersFromStructureAndRoundTrips(t *testing.T) {
	srv, api, _ := buildLaunchServer(t, EmbedConfig{})
	tok := mintConsoleSession(t, srv, defaultWorkspace, "admin", roleWSAdmin)

	post := func(path, body string) map[string]any {
		t.Helper()
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+tok)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		api.handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// Structure -> YAML.
	rendered := post("/api/v1/policy/render", `{"policy":{
		"roles":{"ws-admin":{"allow":[{"actions":["*"],"node_labels":{"*":"*"}}]}},
		"bindings":[{"role":"ws-admin","users":["alice"]}]
	}}`)
	if rendered["valid"] != true {
		t.Fatalf("a well-formed structure must render as valid: %v", rendered)
	}
	yamlDoc, _ := rendered["yaml"].(string)
	if !strings.Contains(yamlDoc, "ws-admin") || !strings.Contains(yamlDoc, "alice") {
		t.Fatalf("rendered document lost content: %q", yamlDoc)
	}

	// YAML -> structure, and it must describe the same policy.
	validated := post("/api/v1/policy/validate", `{"yaml":`+jsonString(yamlDoc)+`}`)
	if validated["valid"] != true {
		t.Fatalf("the rendering must parse: %v", validated)
	}
	parsed, _ := validated["policy"].(map[string]any)
	roles, _ := parsed["roles"].(map[string]any)
	if _, ok := roles["ws-admin"]; !ok {
		t.Fatalf("round-trip lost the role: %v", parsed)
	}

	// And it must be storable — the same document, through the same writer.
	r := httptest.NewRequest("PUT", "/api/v1/policy", strings.NewReader(`{"yaml":`+jsonString(yamlDoc)+`}`))
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("a rendered document must be storable: %d %s", w.Code, w.Body.String())
	}
}

// An invalid structure is a normal editor state: return the rendering AND the
// error, so the operator can see what they built and fix it.
func TestPolicyRenderReportsInvalidStructure(t *testing.T) {
	srv, api, _ := buildLaunchServer(t, EmbedConfig{})
	tok := mintConsoleSession(t, srv, defaultWorkspace, "admin", roleWSAdmin)

	r := httptest.NewRequest("POST", "/api/v1/policy/render",
		strings.NewReader(`{"policy":{"roles":"not-a-map"}}`))
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("an invalid structure is an editor state, not an HTTP error: %d", w.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["valid"] != false || out["error"] == "" {
		t.Fatalf("expected a validation failure with a reason: %v", out)
	}
	if _, ok := out["yaml"].(string); !ok {
		t.Fatalf("the rendering must come back even when invalid, so the operator can fix it: %v", out)
	}
}
