package controller

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func auditPaths(path string) (key, chk string) { return path + ".key", path + ".chk" }

func openAudit(path string) (*Audit, error) {
	k, c := auditPaths(path)
	return OpenAudit(path, k, c, nopSink{}, slog.Default())
}

func verifyAudit(path string) (int, error) {
	k, _ := auditPaths(path)
	return VerifyAuditFile(path, k)
}

func TestAuditChainAppendVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := openAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := a.Append("session_request", "alice", "n-1", "s-1", map[string]string{"i": string(rune('0' + i))}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if n, err := a.Verify(); err != nil || n != 5 {
		t.Fatalf("verify: n=%d err=%v", n, err)
	}
	a.Close()

	// Reopen and extend: the chain must continue from the last hash.
	a2, err := openAudit(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := a2.Append("login_success", "bob", "", "", nil); err != nil {
		t.Fatal(err)
	}
	if n, err := a2.Verify(); err != nil || n != 6 {
		t.Fatalf("verify after reopen: n=%d err=%v", n, err)
	}
	a2.Close()
}

func TestAuditTamperDetection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := openAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range []string{"alice", "bob", "carol"} {
		if err := a.Append("login_success", actor, "", "", nil); err != nil {
			t.Fatal(err)
		}
	}
	a.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Tamper with the middle record's actor — even though the attacker rewrote
	// the line, they cannot recompute the HMAC without the audit key.
	tampered := bytes.Replace(raw, []byte(`"actor":"bob"`), []byte(`"actor":"eve"`), 1)
	if bytes.Equal(raw, tampered) {
		t.Fatal("test setup: replace did not apply")
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAudit(path); err == nil {
		t.Fatal("tampered chain must not verify")
	}
	// A tampered chain must also refuse to be extended.
	if _, err := openAudit(path); err == nil {
		t.Fatal("OpenAudit must fail on a broken chain")
	}
}

func TestAuditInteriorDeletionBreaksChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := openAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := a.Append("enroll", "token", "n-1", "", nil); err != nil {
			t.Fatal(err)
		}
	}
	a.Close()
	raw, _ := os.ReadFile(path)
	lines := bytes.SplitAfter(raw, []byte("\n"))
	// Drop the middle line: prev linkage AND seq both break.
	if err := os.WriteFile(path, append(append([]byte(nil), lines[0]...), lines[2]...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAudit(path); err == nil {
		t.Fatal("deleted record must break the chain")
	}
}

// Dropping the FINAL record(s) leaves a file that scans clean on its own, but
// the checkpoint remembers the higher seq → OpenAudit must fail closed.
func TestAuditTailTruncationDetectedByCheckpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := openAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if err := a.Append("enroll", "token", "n-1", "", nil); err != nil {
			t.Fatal(err)
		}
	}
	a.Close()
	raw, _ := os.ReadFile(path)
	lines := bytes.SplitAfter(raw, []byte("\n"))
	// Keep only the first 2 complete records (a clean prefix), drop the rest.
	if err := os.WriteFile(path, append(append([]byte(nil), lines[0]...), lines[1]...), 0o600); err != nil {
		t.Fatal(err)
	}
	// The truncated file scans clean by itself...
	if _, err := verifyAudit(path); err != nil {
		t.Fatalf("a clean prefix should self-verify: %v", err)
	}
	// ...but OpenAudit cross-checks the checkpoint (seq 4) and refuses.
	if _, err := openAudit(path); err == nil {
		t.Fatal("tail truncation must be detected via the checkpoint")
	}
}
