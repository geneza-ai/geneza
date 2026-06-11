package gateway

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// A torn final line (crash mid-append) must be repaired on open, not brick the
// gateway; an interior tamper must still be fatal.
func TestAuditTornTailRepairAndTamperDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	a, err := openAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := a.Append("test", "actor", "", "", map[string]string{"i": "x"}); err != nil {
			t.Fatal(err)
		}
	}
	a.Close()

	// Append a torn (newline-less, truncated-JSON) final line.
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	f.WriteString(`{"ts":1,"type":"torn","prev":"deadbeef`)
	f.Close()

	// Open must repair the torn tail and succeed, leaving the 3 good records.
	a2, err := openAudit(path)
	if err != nil {
		t.Fatalf("torn tail should be repaired, got: %v", err)
	}
	n, err := a2.Verify()
	if err != nil || n != 3 {
		t.Fatalf("want 3 verified records, got n=%d err=%v", n, err)
	}
	// New appends still chain correctly after repair.
	if err := a2.Append("test", "a", "", "", nil); err != nil {
		t.Fatal(err)
	}
	a2.Close()

	// Now corrupt an INTERIOR complete record: open must fail closed.
	data, _ := os.ReadFile(path)
	data[10] ^= 0xff // flip a byte in the first record's complete line
	os.WriteFile(path, data, 0o600)
	if _, err := openAudit(path); err == nil {
		t.Fatal("interior tamper must be fatal")
	}
}

// Without the audit key, an attacker who rewrites a record AND recomputes a
// plausible chain cannot produce a valid MAC — verification with the real key
// still fails. (Demonstrates the keyed property: file-write is not enough.)
func TestAuditKeyedForgeryResistance(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	a, err := openAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	a.Append("login_success", "alice", "", "", nil)
	a.Close()
	// Replace the audit key with a different one the "attacker" controls and
	// rebuild a fully self-consistent chain over forged content.
	forgedKey := filepath.Join(dir, "forged.key")
	fk, _ := openAuditWithKey(t, path+".forged", forgedKey)
	fk.Append("login_success", "eve", "", "", nil) // eve forges a record under her key
	fk.Close()
	forged, _ := os.ReadFile(path + ".forged")
	os.WriteFile(path, forged, 0o600) // swap the real log for the forged one
	// Verified against the REAL key, the forged chain fails.
	if _, err := verifyAudit(path); err == nil {
		t.Fatal("forged chain (signed with a different key) must not verify under the real key")
	}
}

func openAuditWithKey(t *testing.T, path, keyPath string) (*Audit, error) {
	t.Helper()
	return OpenAudit(path, keyPath, path+".chk", nopSink{}, slog.Default())
}
