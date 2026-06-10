package agentd

import (
	"encoding/json"
	"testing"
	"time"

	"osie.cloud/geneza/internal/wire"
)

func TestExecCommandAllowed(t *testing.T) {
	cases := []struct {
		grant, requested string
		want             bool
	}{
		{"ls -la /tmp", "ls -la /tmp", true},
		{"ls -la /tmp", "ls -la /etc", false},
		{"ls -la /tmp", "ls -la /tmp ", false}, // trailing space: not byte-equal
		{"ls", "ls; rm -rf /", false},          // injection via suffix
		{"", "", false},                        // empty grant command never allows anything
		{"", "ls", false},
		{"ls", "", false},
		{"echo ünïcode", "echo ünïcode", true},
	}
	for _, c := range cases {
		if got := ExecCommandAllowed(c.grant, c.requested); got != c.want {
			t.Errorf("ExecCommandAllowed(%q, %q) = %v, want %v", c.grant, c.requested, got, c.want)
		}
	}
}

func TestForwardTargetAllowed(t *testing.T) {
	cases := []struct {
		target string
		dest   string
		port   uint32
		want   bool
	}{
		{"db.internal:5432", "db.internal", 5432, true},
		{"db.internal:5432", "db.internal", 5433, false},
		{"db.internal:5432", "other.internal", 5432, false},
		{"10.0.0.5:80", "10.0.0.5", 80, true},
		{"[::1]:80", "::1", 80, true}, // JoinHostPort brackets IPv6
		{"[::1]:80", "[::1]", 80, false},
		{"", "db.internal", 5432, false}, // empty target fails closed
	}
	for _, c := range cases {
		if got := ForwardTargetAllowed(c.target, c.dest, c.port); got != c.want {
			t.Errorf("ForwardTargetAllowed(%q, %q, %d) = %v, want %v", c.target, c.dest, c.port, got, c.want)
		}
	}
}

// TestRelayHelloShape pins the exact JSON the agent puts on the wire for the
// relay rendezvous; the relay parses this without sharing Go types.
func TestRelayHelloShape(t *testing.T) {
	b, err := json.Marshal(wire.RelayHello{V: 1, Token: "gz-abc", Role: wire.RoleResponder})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"v":1,"token":"gz-abc","role":"r"}`
	if string(b) != want {
		t.Fatalf("RelayHello JSON = %s, want %s", b, want)
	}
	var back wire.RelayHello
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.V != 1 || back.Token != "gz-abc" || back.Role != "r" {
		t.Fatalf("round-trip mismatch: %+v", back)
	}
}

func TestNeedsRenewal(t *testing.T) {
	nb := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	na := nb.Add(24 * time.Hour)
	cases := []struct {
		now  time.Time
		want bool
	}{
		{nb.Add(time.Hour), false},                 // fresh
		{nb.Add(15 * time.Hour), false},            // 9h left (> 8h = 1/3)
		{nb.Add(16*time.Hour + time.Minute), true}, // < 1/3 left
		{na.Add(time.Hour), true},                  // already expired
	}
	for _, c := range cases {
		if got := needsRenewal(nb, na, c.now); got != c.want {
			t.Errorf("needsRenewal(now=%s) = %v, want %v", c.now, got, c.want)
		}
	}
}
