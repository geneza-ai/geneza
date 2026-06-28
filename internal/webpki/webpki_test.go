package webpki

import (
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/lego"
)

func validAccount(t *testing.T) Account {
	t.Helper()
	key, err := GenerateAccountKey()
	if err != nil {
		t.Fatalf("GenerateAccountKey: %v", err)
	}
	return Account{Email: "ops@example.com", AccountKeyPEM: key}
}

func cloudflareDNS() DNS01Config {
	return DNS01Config{Provider: "cloudflare", Cloudflare: CloudflareConfig{APIToken: "tok"}}
}

func TestAccountValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(a *Account)
		wantErr string
	}{
		{"ok", func(*Account) {}, ""},
		{"no email", func(a *Account) { a.Email = "" }, "email is required"},
		{"no key", func(a *Account) { a.AccountKeyPEM = nil }, "account key is required"},
		{"eab missing hmac", func(a *Account) { a.EAB = &EABConfig{KID: "k"} }, "eab requires both"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := validAccount(t)
			tt.mutate(&a)
			err := a.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("want ok, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestDNS01Validate(t *testing.T) {
	if err := cloudflareDNS().Validate(); err != nil {
		t.Fatalf("cloudflare ok: %v", err)
	}
	if err := (DNS01Config{Provider: ""}).Validate(); err == nil {
		t.Error("missing provider should fail")
	}
	if err := (DNS01Config{Provider: "bind9"}).Validate(); err == nil {
		t.Error("unknown provider should fail")
	}
	if err := (DNS01Config{Provider: "cloudflare"}).Validate(); err == nil {
		t.Error("cloudflare without token should fail")
	}
}

func TestDirectory(t *testing.T) {
	a := validAccount(t)
	if got := a.directory(); got != lego.LEDirectoryStaging {
		t.Errorf("default should be staging, got %q", got)
	}
	a.Production = true
	if got := a.directory(); got != lego.LEDirectoryProduction {
		t.Errorf("production directory, got %q", got)
	}
	a.DirectoryURL = "https://pebble.test/dir"
	if got := a.directory(); got != "https://pebble.test/dir" {
		t.Errorf("explicit directory should win, got %q", got)
	}
}

func TestAccountKeyRoundTrip(t *testing.T) {
	pem, err := GenerateAccountKey()
	if err != nil {
		t.Fatalf("GenerateAccountKey: %v", err)
	}
	if _, err := parsePrivateKey(pem); err != nil {
		t.Fatalf("parse generated key: %v", err)
	}
	if _, err := parsePrivateKey(nil); err == nil {
		t.Error("empty key should fail")
	}
	if _, err := parsePrivateKey([]byte("not pem")); err == nil {
		t.Error("garbage should fail")
	}
}

func TestNewBuildsOffline(t *testing.T) {
	// New must not contact the network: registration is deferred to Issue.
	if _, err := New(validAccount(t), cloudflareDNS()); err != nil {
		t.Fatalf("New with valid config: %v", err)
	}
	if _, err := New(validAccount(t), DNS01Config{Provider: "cloudflare"}); err == nil {
		t.Fatal("New should reject a provider with no credentials")
	}
	bad := validAccount(t)
	bad.Email = ""
	if _, err := New(bad, cloudflareDNS()); err == nil {
		t.Fatal("New should reject an invalid account")
	}
}

func TestProviderConstruction(t *testing.T) {
	if _, err := cloudflareDNS().provider(); err != nil {
		t.Fatalf("cloudflare provider: %v", err)
	}
	if _, err := (DNS01Config{Provider: "route53"}).provider(); err == nil {
		t.Error("unshipped provider should fail until imported")
	}
	if _, err := (DNS01Config{Provider: "exec", Exec: ExecConfig{Program: "/bin/true"}}).provider(); err != nil {
		t.Errorf("exec provider: %v", err)
	}
	if err := (DNS01Config{Provider: "exec"}).Validate(); err == nil {
		t.Error("exec without program should fail")
	}
}
