package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIPClass(t *testing.T) {
	cases := map[string]string{
		"203.0.113.5":   "public",
		"8.8.8.8":       "public",
		"10.0.0.4":      "private",
		"192.168.1.10":  "private",
		"172.16.5.5":    "private",
		"100.64.0.2":    "private", // CGNAT / overlay
		"not-an-ip":     "",
	}
	for ip, want := range cases {
		if got := ipClass(ip); got != want {
			t.Errorf("ipClass(%q) = %q, want %q", ip, got, want)
		}
	}
}

func TestBuildCandidates(t *testing.T) {
	// Public egress hint leads; public local next; private local last.
	c := buildCandidates([]string{"192.168.1.10", "203.0.113.9"}, "198.51.100.7")
	if len(c) != 3 {
		t.Fatalf("want 3 candidates, got %d: %+v", len(c), c)
	}
	if c[0].ip != "198.51.100.7" || c[1].ip != "203.0.113.9" || c[2].ip != "192.168.1.10" {
		t.Fatalf("ordering wrong: %+v", c)
	}
	// Dedup + private egress not preferred.
	c = buildCandidates([]string{"203.0.113.9"}, "203.0.113.9")
	if len(c) != 1 {
		t.Fatalf("dedup failed: %+v", c)
	}
}

func TestPromptSelect(t *testing.T) {
	cands := []ipCandidate{{"198.51.100.7", "egress"}, {"203.0.113.9", "local"}}
	// Empty input -> default (first).
	if ip, _ := promptSelect(&strings.Builder{}, strings.NewReader("\n"), cands); ip != "198.51.100.7" {
		t.Errorf("empty -> default: got %q", ip)
	}
	// Numeric choice.
	if ip, _ := promptSelect(&strings.Builder{}, strings.NewReader("2\n"), cands); ip != "203.0.113.9" {
		t.Errorf("choice 2: got %q", ip)
	}
	// Custom IP path.
	if ip, _ := promptSelect(&strings.Builder{}, strings.NewReader("c\n9.9.9.9\n"), cands); ip != "9.9.9.9" {
		t.Errorf("custom: got %q", ip)
	}
	// Typed IP directly.
	if ip, _ := promptSelect(&strings.Builder{}, strings.NewReader("1.2.3.4\n"), cands); ip != "1.2.3.4" {
		t.Errorf("typed ip: got %q", ip)
	}
	// Invalid choice.
	if _, err := promptSelect(&strings.Builder{}, strings.NewReader("99\n"), cands); err == nil {
		t.Error("out-of-range choice should error")
	}
}

func TestDiscoverEgressIP(t *testing.T) {
	jsonSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"ip":"203.0.113.50"}`))
	}))
	defer jsonSrv.Close()
	plainSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("203.0.113.51\n"))
	}))
	defer plainSrv.Close()

	if ip, err := discoverEgressIP(context.Background(), http.DefaultClient, jsonSrv.URL); err != nil || ip != "203.0.113.50" {
		t.Errorf("json whoami: %q %v", ip, err)
	}
	if ip, err := discoverEgressIP(context.Background(), http.DefaultClient, plainSrv.URL); err != nil || ip != "203.0.113.51" {
		t.Errorf("plain whoami: %q %v", ip, err)
	}
}

func TestWritePublicIP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.yaml")

	// Append when absent.
	os.WriteFile(path, []byte("listen: \":7403\"\nfunnel_listen: \":443\"\n"), 0o644)
	if err := writePublicIP(path, "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "public_ip: 203.0.113.9") {
		t.Fatalf("append: %s", b)
	}

	// Replace when present (preserving indentation).
	os.WriteFile(path, []byte("listen: \":7403\"\npublic_ip: 1.1.1.1\nfunnel_listen: \":443\"\n"), 0o644)
	if err := writePublicIP(path, "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	if strings.Contains(string(b), "1.1.1.1") || !strings.Contains(string(b), "public_ip: 203.0.113.9") {
		t.Fatalf("replace: %s", b)
	}
	if !strings.Contains(string(b), "funnel_listen") {
		t.Fatalf("rest of file not preserved: %s", b)
	}
}
