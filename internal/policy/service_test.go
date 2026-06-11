package policy

import (
	"testing"
	"time"
)

func svcEngine(t *testing.T) *Static {
	t.Helper()
	eng, err := Parse([]byte(`
roles:
  dba:
    allow:
      - service_kinds: [postgres]
        node_labels: {env: prod}
  desktop:
    allow:
      - services: [corp-rdp]
  netadmin:
    allow:
      - service_kinds: [subnet-route, exit-node]
bindings:
  - {role: dba, users: [alice]}
  - {role: desktop, users: [bob]}
  - {role: netadmin, users: [carol]}
`))
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func TestServiceKindMatching(t *testing.T) {
	eng := svcEngine(t)
	now := time.Now()
	// alice may reach a postgres service on a prod node...
	if d := eng.Evaluate(Input{User: "alice", Action: "forward", Service: "pg1", ServiceKind: "postgres",
		NodeLabels: map[string]string{"env": "prod"}, Now: now}); !d.Allow {
		t.Fatalf("dba should reach postgres on prod: %s", d.Reason)
	}
	// ...but NOT a plain shell on that node (service-scoped rule != node access).
	if d := eng.Evaluate(Input{User: "alice", Action: "shell", NodeLabels: map[string]string{"env": "prod"}, Now: now}); d.Allow {
		t.Fatal("dba's postgres rule must not grant a shell")
	}
	// ...and not a postgres service on a non-prod node.
	if d := eng.Evaluate(Input{User: "alice", Action: "forward", Service: "pg2", ServiceKind: "postgres",
		NodeLabels: map[string]string{"env": "dev"}, Now: now}); d.Allow {
		t.Fatal("dba must not reach postgres on dev")
	}
}

func TestNamedServiceMatching(t *testing.T) {
	eng := svcEngine(t)
	if d := eng.Evaluate(Input{User: "bob", Action: "forward", Service: "corp-rdp", ServiceKind: "rdp", Now: time.Now()}); !d.Allow {
		t.Fatalf("bob should reach corp-rdp: %s", d.Reason)
	}
	if d := eng.Evaluate(Input{User: "bob", Action: "forward", Service: "other-rdp", ServiceKind: "rdp", Now: time.Now()}); d.Allow {
		t.Fatal("bob is scoped to corp-rdp only")
	}
}

func TestVPNServiceMatching(t *testing.T) {
	eng := svcEngine(t)
	if d := eng.Evaluate(Input{User: "carol", Action: "vpn", Service: "lan", ServiceKind: "subnet-route", Now: time.Now()}); !d.Allow {
		t.Fatalf("netadmin should use subnet-route: %s", d.Reason)
	}
	if d := eng.Evaluate(Input{User: "carol", Action: "vpn", Service: "exit", ServiceKind: "exit-node", Now: time.Now()}); !d.Allow {
		t.Fatalf("netadmin should use exit-node: %s", d.Reason)
	}
	// A user with no vpn grant cannot use it (vpn is new; no legacy rule grants it).
	if d := eng.Evaluate(Input{User: "bob", Action: "vpn", ServiceKind: "exit-node", Now: time.Now()}); d.Allow {
		t.Fatal("bob has no vpn/exit grant")
	}
}
