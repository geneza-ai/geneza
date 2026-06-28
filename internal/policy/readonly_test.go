package policy

import (
	"testing"
	"time"
)

// A read_only rule still allows access but flags the decision read-only, which the
// controller turns into a downgrade delta. The merge is MOST-RESTRICTIVE: a user who
// also matches a non-read-only rule for the same access is still read-only.
func TestReadOnlyRule(t *testing.T) {
	doc := []byte(`
roles:
  ro:
    allow:
      - actions: [shell]
        node_labels: {env: lab}
        read_only: true
  rw:
    allow:
      - actions: [shell]
        node_labels: {env: lab}
bindings:
  - role: ro
    users: [alice]
  - role: rw
    users: [bob, alice]
`)
	eng, err := Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	base := Input{NodeName: "n1", NodeLabels: map[string]string{"env": "lab"}, Action: "shell", Now: time.Now()}

	// bob (rw only): allowed, not read-only.
	b := base
	b.User = "bob"
	if d := eng.Evaluate(b); !d.Allow || d.ReadOnly {
		t.Fatalf("bob should be allowed read-write, got allow=%v readonly=%v", d.Allow, d.ReadOnly)
	}
	// alice (ro + rw): allowed, but read-only wins (most-restrictive).
	a := base
	a.User = "alice"
	if d := eng.Evaluate(a); !d.Allow || !d.ReadOnly {
		t.Fatalf("alice should be allowed but read-only, got allow=%v readonly=%v", d.Allow, d.ReadOnly)
	}
}

// read_only_time_window imposes read-only only during the clock window.
func TestReadOnlyTimeWindow(t *testing.T) {
	doc := []byte(`
roles:
  maint:
    allow:
      - actions: [shell]
        node_labels: {env: lab}
        read_only_time_window: {start: "00:00", end: "23:59"}
bindings:
  - role: maint
    users: [carol]
`)
	eng, err := Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	in := Input{User: "carol", NodeName: "n1", NodeLabels: map[string]string{"env": "lab"}, Action: "shell",
		Now: time.Date(2026, 6, 15, 12, 0, 0, 0, time.Local)}
	if d := eng.Evaluate(in); !d.Allow || !d.ReadOnly {
		t.Fatalf("inside the read-only window carol must be read-only, got allow=%v readonly=%v", d.Allow, d.ReadOnly)
	}
}
