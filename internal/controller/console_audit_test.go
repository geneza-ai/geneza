package controller

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

// The audit query kept the TAIL of the matches with no cursor, so the newest N
// records counting back from now were everything a console user could ever see.
// Narrowing `since` could not walk backwards — the tail of a longer window is the
// same tail — which made older events unreachable rather than merely inconvenient.
func TestAuditPagingReachesOlderRecords(t *testing.T) {
	srv, api, _ := buildLaunchServer(t, EmbedConfig{})
	tok := mintConsoleSession(t, srv, defaultWorkspace, "admin", roleWSAdmin)

	const n = 250
	for i := 0; i < n; i++ {
		if err := srv.audit.AppendWS(defaultWorkspace, "test_event", "admin", "", "",
			map[string]string{"i": fmt.Sprintf("%03d", i)}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	get := func(query string) map[string]any {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/v1/audit"+query, nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		api.handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("audit%s: %d %s", query, w.Code, w.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	first := get("?type=test_event&limit=50")
	if total, _ := first["total"].(float64); int(total) != n {
		t.Fatalf("total = %v, want %d — the filter's full match count must be reported", first["total"], n)
	}
	rows, _ := first["records"].([]any)
	if len(rows) != 50 {
		t.Fatalf("page size = %d, want 50", len(rows))
	}

	// The offset must move the window; page 2 must not repeat page 1.
	second := get("?type=test_event&limit=50&offset=50")
	srows, _ := second["records"].([]any)
	if len(srows) != 50 {
		t.Fatalf("second page size = %d, want 50", len(srows))
	}
	detailOf := func(v any) string {
		b, _ := json.Marshal(v)
		return string(b)
	}
	if detailOf(rows[0]) == detailOf(srows[0]) {
		t.Fatalf("offset did not move the window — page 2 repeats page 1")
	}

	// And the oldest record must be reachable at all.
	last := get(fmt.Sprintf("?type=test_event&limit=50&offset=%d", n-50))
	lrows, _ := last["records"].([]any)
	if len(lrows) == 0 || !strings.Contains(detailOf(lrows[0]), `"000"`) {
		t.Fatalf("the oldest record must be reachable by paging; got %s", detailOf(lrows))
	}
}

// The JSONL export must emit the verbatim chain lines, so their HMACs still
// verify outside the console — an export that reserializes is not evidence.
func TestAuditJSONLExportIsVerbatim(t *testing.T) {
	srv, api, _ := buildLaunchServer(t, EmbedConfig{})
	tok := mintConsoleSession(t, srv, defaultWorkspace, "admin", roleWSAdmin)
	if err := srv.audit.AppendWS(defaultWorkspace, "test_event", "admin", "", "", nil); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("GET", "/api/v1/audit?type=test_event&format=jsonl", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	api.handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("export: %d %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "ndjson") {
		t.Fatalf("content-type %q", ct)
	}
	body := strings.TrimSpace(w.Body.String())
	if body == "" {
		t.Fatal("empty export")
	}
	for _, line := range strings.Split(body, "\n") {
		var e AuditEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("export line is not a chain record: %v (%s)", err, line)
		}
		if e.Hash == "" || e.Seq == 0 {
			t.Fatalf("export dropped chain fields, so it cannot be verified: %s", line)
		}
	}
}
