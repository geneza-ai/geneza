package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

// doRaw drives a console request that returns a non-JSON body (the ciphertext
// blob), returning the status, the raw bytes and the response headers — the JSON
// helper can't read an octet-stream.
func doRaw(t *testing.T, h http.Handler, method, path, bearer string) (int, []byte, http.Header) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes(), rec.Result().Header
}

// TestConsoleRecordingRoutes drives the recording REST bridge through the real
// console mux: an auditor lists the index and fetches the verified ciphertext (the
// served bytes equal the stored blob, and the fetch is audited); a ws-member is
// denied list and fetch (replay is privileged); and a missing recording is a 404.
func TestConsoleRecordingRoutes(t *testing.T) {
	srv := newReplayServer(t)
	srv.setClusterConfig(2, signedConfigWithAudit(t, srv, 2, testAuditRecipient))
	nc := newNodeCert(t)
	const ws, node, sid = defaultWorkspace, "n1", "s-aaaaaaaaaaaa"
	seedSession(t, srv, ws, node, sid)
	cipher := []byte("opaque-age-ciphertext-payload")
	if err := uploadRecording(t, srv, ws, node, nc, sid, cipher, "ignored"); err != nil {
		t.Fatalf("upload: %v", err)
	}

	api, err := srv.newConsoleAPI()
	if err != nil {
		t.Fatalf("console api: %v", err)
	}
	h := api.handler()
	auditor := mintConsoleSession(t, srv, ws, "carol", roleWSAuditor)

	// List: the auditor sees the one recording with its index fields.
	code, resp := doJSON(t, h, "GET", "/api/v1/recordings", auditor, "")
	if code != 200 {
		t.Fatalf("list recordings: %d %v", code, resp)
	}
	if resp["total"].(float64) != 1 {
		t.Fatalf("list recordings: want total 1, got %v", resp["total"])
	}
	rows := resp["recordings"].([]any)
	row := rows[0].(map[string]any)
	if row["sessionId"] != sid {
		t.Fatalf("list recordings: want session %q, got %v", sid, row["sessionId"])
	}
	sum := sha256.Sum256(cipher)
	if row["sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("list recordings: sha256 mismatch, got %v", row["sha256"])
	}

	// Listing is audited (who-recorded-what is sensitive).
	if _, ok := lastAudit(t, srv, "recording_listed"); !ok {
		t.Fatal("a successful list must be audited")
	}

	// Fetch: the served bytes equal the stored ciphertext and the manifest rides
	// the headers for client-side verification.
	code, body, hdr := doRaw(t, h, "GET", "/api/v1/recordings/"+sid, auditor)
	if code != 200 {
		t.Fatalf("fetch recording: %d", code)
	}
	if string(body) != string(cipher) {
		t.Fatalf("served bytes != stored ciphertext: got %q", body)
	}
	if hdr.Get("X-Geneza-Recording-Sha256") != hex.EncodeToString(sum[:]) {
		t.Fatalf("manifest sha256 header missing/wrong: %q", hdr.Get("X-Geneza-Recording-Sha256"))
	}
	if hdr.Get("X-Geneza-Recording-Node-Sig") == "" {
		t.Fatal("manifest node-sig header missing")
	}

	// Fetching is audited (the auditor is audited).
	if _, ok := lastAudit(t, srv, "recording_fetched"); !ok {
		t.Fatal("a fetch must be audited")
	}

	// A ws-member is too low: replay is privileged, NOT default operator.
	member := mintConsoleSession(t, srv, ws, "bob", roleWSMember)
	if code, _ := doJSON(t, h, "GET", "/api/v1/recordings", member, ""); code != 403 {
		t.Fatalf("member list: want 403, got %d", code)
	}
	if code, _, _ := doRaw(t, h, "GET", "/api/v1/recordings/"+sid, member); code != 403 {
		t.Fatalf("member fetch: want 403, got %d", code)
	}

	// A missing recording is a 404, never a leak.
	if code, _, _ := doRaw(t, h, "GET", "/api/v1/recordings/s-ffffffffffff", auditor); code != 404 {
		t.Fatalf("missing recording: want 404, got %d", code)
	}
}

// TestConsoleRecordingWorkspaceIsolation proves a fully-privileged auditor of one
// workspace cannot list or fetch another workspace's recording: the workspace is
// taken from the authenticated session, never the request, so the bypass is
// unreachable even when the caller holds the replay capability.
func TestConsoleRecordingWorkspaceIsolation(t *testing.T) {
	srv := newReplayServer(t)
	const sid = "s-bbbbbbbbbbbb"
	sum := sha256.Sum256([]byte("ciphertext"))
	if err := srv.store.PutRecording("wsB", &RecordingRecord{
		SessionID: sid, NodeID: "n9", Principal: "user:eve",
		BlobRef: "local:" + sid + ".cast.age", SHA256: hex.EncodeToString(sum[:]), StoredUnix: 1700,
	}); err != nil {
		t.Fatalf("seed wsB recording: %v", err)
	}

	api, err := srv.newConsoleAPI()
	if err != nil {
		t.Fatalf("console api: %v", err)
	}
	h := api.handler()
	// A privileged auditor, but in workspace A.
	auditor := mintConsoleSession(t, srv, "wsA", "carol", roleWSAuditor)

	code, resp := doJSON(t, h, "GET", "/api/v1/recordings", auditor, "")
	if code != 200 || resp["total"].(float64) != 0 {
		t.Fatalf("cross-workspace list: want empty, got %d %v", code, resp)
	}
	if code, _, _ := doRaw(t, h, "GET", "/api/v1/recordings/"+sid, auditor); code != 404 {
		t.Fatalf("cross-workspace fetch: want 404, got %d", code)
	}
}
