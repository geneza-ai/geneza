package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// A torn final line (crash mid-append) must be repaired on open, not brick the
// gateway; an interior tamper must still be fatal.
func TestAuditTornTailRepairAndTamperDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	a, err := OpenAudit(path)
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
	a2, err := OpenAudit(path)
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
	if _, err := OpenAudit(path); err == nil {
		t.Fatal("interior tamper must be fatal")
	}
}
