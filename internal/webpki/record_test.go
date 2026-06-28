package webpki

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecRecordManager(t *testing.T) {
	dir := t.TempDir()
	logf := filepath.Join(dir, "calls.log")
	script := filepath.Join(dir, "dns.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho \"$@\" >> "+logf+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rm, err := NewRecordManager(DNS01Config{Provider: "exec", Exec: ExecConfig{Program: script}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := rm.SetA(ctx, "app.geneza.app", []string{"1.1.1.1", "2.2.2.2"}); err != nil {
		t.Fatalf("set-a: %v", err)
	}
	if err := rm.RemoveA(ctx, "app.geneza.app"); err != nil {
		t.Fatalf("remove-a: %v", err)
	}
	out, err := os.ReadFile(logf)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, "set-a app.geneza.app 1.1.1.1,2.2.2.2") {
		t.Errorf("set-a invocation missing: %q", got)
	}
	if !strings.Contains(got, "remove-a app.geneza.app") {
		t.Errorf("remove-a invocation missing: %q", got)
	}
}

func TestNewRecordManager(t *testing.T) {
	// Cloudflare with a token is now natively supported.
	if _, err := NewRecordManager(DNS01Config{Provider: "cloudflare", Cloudflare: CloudflareConfig{APIToken: "t"}}); err != nil {
		t.Errorf("cloudflare A-record manager: %v", err)
	}
	if _, err := NewRecordManager(DNS01Config{Provider: "cloudflare"}); err == nil {
		t.Error("cloudflare without api_token should fail")
	}
	if _, err := NewRecordManager(DNS01Config{Provider: "exec"}); err == nil {
		t.Error("exec without program should fail")
	}
	if _, err := NewRecordManager(DNS01Config{Provider: "route53"}); err == nil {
		t.Error("unsupported provider should fail")
	}
}
