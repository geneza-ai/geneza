package agentd

import (
	"log/slog"
	"testing"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

func TestFunnelManagerReconcile(t *testing.T) {
	m := newFunnelManager(slog.Default())
	m.reconcile(&genezav1.FunnelServe{Routes: []*genezav1.FunnelRoute{
		{Hostname: "app.acme.geneza.app", Target: "127.0.0.1:8080", Mode: "http", RelayAddrs: []string{"r1:7403"}},
		{Hostname: "db.acme.geneza.app", Target: "127.0.0.1:5432", Mode: "tcp"},
	}})
	if got := m.served(); len(got) != 2 {
		t.Fatalf("want 2 routes, got %v", got)
	}
	// Declarative: a push omitting db drops it.
	m.reconcile(&genezav1.FunnelServe{Routes: []*genezav1.FunnelRoute{
		{Hostname: "app.acme.geneza.app", Target: "127.0.0.1:8080", Mode: "http"},
	}})
	if got := m.served(); len(got) != 1 || got[0] != "app.acme.geneza.app" {
		t.Fatalf("after drop want [app], got %v", got)
	}
	// Empty push clears all.
	m.reconcile(&genezav1.FunnelServe{})
	if got := m.served(); len(got) != 0 {
		t.Fatalf("empty push should clear, got %v", got)
	}
}
