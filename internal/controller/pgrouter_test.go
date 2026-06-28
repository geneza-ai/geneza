package controller

import (
	"strings"
	"testing"
)

// A doorbell principal payload round-trips, including identity fields that contain
// arbitrary OIDC characters (the unit separator never appears in them).
func TestEncDecPrincipal(t *testing.T) {
	cases := [][3]string{
		{"ws1", "keystone", "alice"},
		{"default", "device:oidc", "user@example.com|weird"},
		{"", "", ""},
	}
	for _, c := range cases {
		ws, p, s := decPrincipal(encPrincipal(c[0], c[1], c[2]))
		if ws != c[0] || p != c[1] || s != c[2] {
			t.Fatalf("round-trip %v -> %q/%q/%q", c, ws, p, s)
		}
	}
}

// An agent-push doorbell round-trips, including a revoke reason that carries spaces
// and punctuation (only the unit separator is reserved, and reason is the last
// field so it can hold anything else).
func TestEncDecDoorbell(t *testing.T) {
	cases := [][5]string{
		{opNetcfg, "ws1", "node-abc", "", ""},
		{opModcfg, "default", "n1", "", ""},
		{opRevoke, "ws1", "node-xyz", "sess-7", "suspended: keystone (admin lock)"},
		{"", "", "", "", ""},
	}
	for _, c := range cases {
		op, ws, n, sid, reason := decDoorbell(encDoorbell(c[0], c[1], c[2], c[3], c[4]))
		if op != c[0] || ws != c[1] || n != c[2] || sid != c[3] || reason != c[4] {
			t.Fatalf("round-trip %v -> %q/%q/%q/%q/%q", c, op, ws, n, sid, reason)
		}
	}
}

// The per-owner channel stays a valid Postgres channel (≤ 63 bytes) for a typical
// id, and config validation rejects an id that would overflow it.
func TestControllerChannelLength(t *testing.T) {
	if got := gwChannel("geneza-core"); len(got) > 63 {
		t.Fatalf("channel %q exceeds 63 bytes", got)
	}
	cfg := &Config{
		PolicyFile: "/p.yaml", RelayAddrs: []string{"r:7403"}, Router: "pg",
		StoreBackend: "postgres", StoreDSN: "postgres://x/y",
		ControllerID: strings.Repeat("g", 60),
	}
	if err := cfg.validateForServe(); err == nil {
		t.Fatal("an over-long controller_id must be rejected for router=pg")
	}
}

// router=pg requires the shared SQL store; bbolt would split-brain the deny path.
func TestRouterPGRequiresSQL(t *testing.T) {
	base := func() *Config {
		return &Config{PolicyFile: "/p.yaml", RelayAddrs: []string{"r:7403"}, Router: "pg"}
	}
	bbolt := base()
	bbolt.StoreBackend = "bbolt"
	if err := bbolt.validateForServe(); err == nil {
		t.Fatal("router=pg with bbolt must be rejected")
	}
	pg := base()
	pg.StoreBackend = "postgres"
	pg.StoreDSN = "postgres://x/y"
	if err := pg.validateForServe(); err != nil {
		t.Fatalf("router=pg with postgres+dsn must be accepted: %v", err)
	}
}

// The only routers are inproc (default, empty) and pg; a retired or mistyped value
// is rejected rather than silently treated as single-node.
func TestRouterAllowlist(t *testing.T) {
	base := func(router string) *Config {
		return &Config{
			PolicyFile: "/p.yaml", RelayAddrs: []string{"r:7403"}, Router: router,
			StoreBackend: "postgres", StoreDSN: "postgres://x/y",
		}
	}
	for _, ok := range []string{"", "inproc", "pg"} {
		if err := base(ok).validateForServe(); err != nil {
			t.Fatalf("router=%q must be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{"nats", "redis", "grpc"} {
		if err := base(bad).validateForServe(); err == nil {
			t.Fatalf("router=%q must be rejected", bad)
		}
	}
}
