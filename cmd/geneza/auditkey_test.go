package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// runAuditKey executes the audit-key command tree with args, returning stdout
// only (the recipient channel; the "safeguard it" notice goes to stderr).
func runAuditKey(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newAuditKeyCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// TestAuditKeyGenerate proves generate yields a 0600 identity file plus a
// recipient on stdout, the recipient parses as an age recipient, and the written
// identity decrypts data sealed to that recipient.
func TestAuditKeyGenerate(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit-identity.key")

	stdout, err := runAuditKey(t, "generate", "-o", keyPath)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	recipientStr := strings.TrimSpace(stdout)
	if !strings.HasPrefix(recipientStr, "age1") {
		t.Fatalf("recipient line is not an age recipient: %q", recipientStr)
	}

	// The private identity must land at 0600 — it is the auditor's secret.
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat identity: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("identity file mode = %o, want 0600", perm)
	}

	// The printed recipient parses, and the on-disk identity decrypts a cast sealed
	// to it — the full custody round-trip an auditor relies on.
	recipient, err := age.ParseX25519Recipient(recipientStr)
	if err != nil {
		t.Fatalf("printed recipient does not parse: %v", err)
	}
	cipher := sealCast(t, []byte(validCast), recipient)
	plain, err := decryptRecording(cipher, keyPath)
	if err != nil {
		t.Fatalf("decrypt with generated identity: %v", err)
	}
	if !bytes.Equal(plain, []byte(validCast)) {
		t.Fatalf("generated identity did not round-trip the cast")
	}
}

// TestAuditKeyGenerateNoClobber proves generate refuses to overwrite an existing
// file, so a custodian cannot silently destroy a key that may be the only
// decryptor of stored recordings.
func TestAuditKeyGenerateNoClobber(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "audit-identity.key")
	if _, err := runAuditKey(t, "generate", "-o", keyPath); err != nil {
		t.Fatalf("first generate: %v", err)
	}
	if _, err := runAuditKey(t, "generate", "-o", keyPath); err == nil {
		t.Fatalf("second generate overwrote an existing identity file")
	}
}

// TestAuditKeyRecipientRoundTrip proves recipient -i recovers the exact recipient
// of an existing identity file, so an operator can re-derive it without
// regenerating (and orphaning) the key.
func TestAuditKeyRecipientRoundTrip(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "audit-identity.key")
	genOut, err := runAuditKey(t, "generate", "-o", keyPath)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	want := strings.TrimSpace(genOut)

	recOut, err := runAuditKey(t, "recipient", "-i", keyPath)
	if err != nil {
		t.Fatalf("recipient: %v", err)
	}
	if got := strings.TrimSpace(recOut); got != want {
		t.Fatalf("recipient round-trip = %q, want %q", got, want)
	}
}

// TestAuditKeyGenerateStdout proves -o - writes the private identity to stdout
// alongside the recipient, for piping into a vault without touching disk.
func TestAuditKeyGenerateStdout(t *testing.T) {
	out, err := runAuditKey(t, "generate", "-o", "-")
	if err != nil {
		t.Fatalf("generate -o -: %v", err)
	}
	if !strings.Contains(out, "AGE-SECRET-KEY-") {
		t.Fatalf("stdout missing the private identity: %q", out)
	}
	if !strings.Contains(out, "age1") {
		t.Fatalf("stdout missing the recipient: %q", out)
	}
}
