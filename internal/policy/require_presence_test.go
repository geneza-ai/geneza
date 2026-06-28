package policy

import (
	"testing"
	"time"
)

// require_presence merges MOST-RESTRICTIVE (like require_native): a broad allow
// rule cannot disable presence on a sensitive target. Test both rule orders.
func TestRequirePresenceRestrictiveMerge(t *testing.T) {
	doc := []byte(`
roles:
  broad:
    allow:
      - actions: [shell]
        node_labels: {env: lab}
  sensitive:
    allow:
      - actions: [shell]
        node_labels: {env: lab}
        require_presence: true
bindings:
  - role: broad
    users: [alice, bob]
  - role: sensitive
    users: [alice]
`)
	eng, err := Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	base := Input{NodeName: "n1", NodeLabels: map[string]string{"env": "lab"}, Action: "shell", Now: time.Now()}

	// bob (broad only): allowed, presence not required.
	b := base
	b.User = "bob"
	if d := eng.Evaluate(b); !d.Allow || d.RequirePresence {
		t.Fatalf("bob should be allowed without presence, got allow=%v presence=%v", d.Allow, d.RequirePresence)
	}
	// alice (broad + sensitive): allowed, but presence REQUIRED (restrictive wins),
	// regardless of which role's rule matched first.
	a := base
	a.User = "alice"
	if d := eng.Evaluate(a); !d.Allow || !d.RequirePresence {
		t.Fatalf("alice should be allowed AND require presence, got allow=%v presence=%v", d.Allow, d.RequirePresence)
	}
}
