package gateway

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditChainAppendVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := OpenAudit(path)
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
	a2, err := OpenAudit(path)
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
	a, err := OpenAudit(path)
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
	// Tamper with the middle record's actor.
	tampered := bytes.Replace(raw, []byte(`"actor":"bob"`), []byte(`"actor":"eve"`), 1)
	if bytes.Equal(raw, tampered) {
		t.Fatal("test setup: replace did not apply")
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := VerifyAuditFile(path)
	if err == nil {
		t.Fatal("tampered chain must not verify")
	}
	if n != 1 {
		t.Fatalf("expected 1 valid record before the break, got %d", n)
	}
	// A tampered chain must also refuse to be extended.
	if _, err := OpenAudit(path); err == nil {
		t.Fatal("OpenAudit must fail on a broken chain")
	}
}

func TestAuditTruncationDetection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := OpenAudit(path)
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
	// Drop the middle line: the third record's prev no longer matches.
	if err := os.WriteFile(path, append(append([]byte(nil), lines[0]...), lines[2]...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAuditFile(path); err == nil {
		t.Fatal("deleted record must break the chain")
	}
}
