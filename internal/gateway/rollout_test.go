package gateway

import "testing"

func TestResolveDesired(t *testing.T) {
	canaryNodes := []string{"n-canary1", "n-canary2"}
	cases := []struct {
		name           string
		stable, canary string
		node           string
		want           string
	}{
		{"canary node gets canary", "1.0.0", "1.1.0", "n-canary1", "1.1.0"},
		{"other node gets stable", "1.0.0", "1.1.0", "n-other", "1.0.0"},
		{"empty canary falls back to stable", "1.0.0", "", "n-canary1", "1.0.0"},
		{"nothing set yet", "", "", "n-other", ""},
		{"canary set, stable empty, non-canary node", "", "1.1.0", "n-other", ""},
	}
	for _, c := range cases {
		if got := resolveDesired(c.stable, c.canary, canaryNodes, c.node); got != c.want {
			t.Errorf("%s: resolveDesired(%q,%q,%q) = %q, want %q", c.name, c.stable, c.canary, c.node, got, c.want)
		}
	}
	if got := resolveDesired("1.0.0", "1.1.0", nil, "n-canary1"); got != "1.0.0" {
		t.Errorf("empty ring: got %q, want stable", got)
	}
}

func TestExampleConfigParses(t *testing.T) {
	cfg, err := LoadConfig("testdata/gateway.example.yaml")
	if err != nil {
		t.Fatalf("example config must parse: %v", err)
	}
	if cfg.GRPCListen != ":7401" || cfg.HTTPListen != ":7402" {
		t.Fatalf("listen defaults: %q %q", cfg.GRPCListen, cfg.HTTPListen)
	}
	if cfg.OIDC == nil || cfg.OIDC.UsernameClaim != "preferred_username" || cfg.OIDC.GroupsClaim != "groups" {
		t.Fatalf("oidc claim defaults: %+v", cfg.OIDC)
	}
	if err := cfg.validateForServe(); err != nil {
		t.Fatalf("example config must be servable: %v", err)
	}
}
