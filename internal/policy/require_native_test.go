package policy

import (
	"testing"
	"time"
)

// A require_native rule must fail closed: an unknown/empty client path does not
// satisfy it (only a proven native path does).
func TestRequireNativeFailsClosed(t *testing.T) {
	doc := []byte(`
roles:
  sensitive:
    allow:
      - actions: [shell]
        node_labels: {env: prod}
        require_native: true
bindings:
  - role: sensitive
    users: [alice]
`)
	eng, err := Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	base := Input{User: "alice", NodeName: "p1", NodeLabels: map[string]string{"env": "prod"}, Action: "shell", Now: time.Now()}

	if d := eng.Evaluate(base); d.Allow { // empty client path
		t.Fatalf("empty client_path must NOT satisfy require_native, got allow: %s", d.Reason)
	}
	web := base
	web.ClientPath = "web"
	if d := eng.Evaluate(web); d.Allow {
		t.Fatalf("web client_path must NOT satisfy require_native")
	}
	native := base
	native.ClientPath = "native"
	if d := eng.Evaluate(native); !d.Allow {
		t.Fatalf("native client_path must satisfy require_native, got deny: %s", d.Reason)
	}
}

// A malformed time_window day must not panic evaluation.
func TestMalformedTimeWindowDayNoPanic(t *testing.T) {
	doc := []byte(`
roles:
  r:
    allow:
      - actions: ["*"]
        node_labels: {"*": "*"}
        time_window: {days: ["X", "Mon"], start: "00:00", end: "23:59"}
bindings:
  - role: r
    users: [bob]
`)
	eng, err := Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	// Must not panic regardless of the current weekday.
	_ = eng.Evaluate(Input{User: "bob", Action: "shell", Now: time.Now()})
}
