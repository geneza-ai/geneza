package controller

import (
	"context"
	"sync"
	"testing"
	"time"

	"geneza.io/internal/types"
	"geneza.io/internal/webpki"
)

type fakeRecordManager struct {
	mu      sync.Mutex
	records map[string][]string
}

func newFakeRM() *fakeRecordManager { return &fakeRecordManager{records: map[string][]string{}} }

func (f *fakeRecordManager) SetA(_ context.Context, fqdn string, ips []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[fqdn] = append([]string(nil), ips...)
	return nil
}
func (f *fakeRecordManager) RemoveA(_ context.Context, fqdn string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.records, fqdn)
	return nil
}
func (f *fakeRecordManager) get(fqdn string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.records[fqdn]
}

func relay(id, ip string, draining bool, seen time.Time) *RelayRecord {
	return &RelayRecord{
		RelayNode:    types.RelayNode{RegionID: "d", RelayID: id, Draining: draining},
		FunnelIP:     ip,
		LastSeenUnix: seen.Unix(),
	}
}

func TestFunnelDNSReconcile(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	// Two healthy funnel relays, one draining, one stale — only the first two count.
	for _, r := range []*RelayRecord{
		relay("r1", "1.1.1.1", false, now),
		relay("r2", "2.2.2.2", false, now),
		relay("r3", "3.3.3.3", true, now),                            // draining → excluded
		relay("r4", "4.4.4.4", false, now.Add(-2*relayStaleTTL)),     // stale → excluded
		relay("r5", "", false, now),                                  // no funnel IP → excluded
	} {
		if err := st.UpsertRelay(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.CreateFunnelBinding(&FunnelBinding{Hostname: "app.acme.geneza.app", WorkspaceID: "ws1", NodeID: "n1", Target: "127.0.0.1:8080", Mode: "http"}, maxWorkspaceFunnels); err != nil {
		t.Fatal(err)
	}

	fake := newFakeRM()
	r := newFunnelDNSReconciler(st, map[string]webpki.RecordManager{"geneza.app": fake})
	reachable := map[string]bool{"1.1.1.1": true, "2.2.2.2": true}
	r.reachable = func(ip string) bool { return reachable[ip] }

	r.reconcile(context.Background())
	if got := fake.get("app.acme.geneza.app"); len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "2.2.2.2" {
		t.Fatalf("published A set = %v, want [1.1.1.1 2.2.2.2]", got)
	}

	// Drain r1 → the A set fails over to just r2.
	if err := st.UpsertRelay(relay("r1", "1.1.1.1", true, now)); err != nil {
		t.Fatal(err)
	}
	r.reconcile(context.Background())
	if got := fake.get("app.acme.geneza.app"); len(got) != 1 || got[0] != "2.2.2.2" {
		t.Fatalf("after drain, A set = %v, want [2.2.2.2]", got)
	}

	// An advertised funnel IP that fails the reachability probe is not published.
	if err := st.CreateFunnelBinding(&FunnelBinding{Hostname: "app.acme.geneza.app", WorkspaceID: "ws1", NodeID: "n1", Target: "127.0.0.1:8080", Mode: "http"}, maxWorkspaceFunnels); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertRelay(relay("r1", "1.1.1.1", false, now)); err != nil { // back healthy
		t.Fatal(err)
	}
	reachable["1.1.1.1"] = false // but now unreachable
	r.reconcile(context.Background())
	if got := fake.get("app.acme.geneza.app"); len(got) != 1 || got[0] != "2.2.2.2" {
		t.Fatalf("unreachable funnel IP must be excluded, got %v", got)
	}

	// Releasing the funnel withdraws the record.
	if err := st.DeleteFunnelBinding("app.acme.geneza.app", "ws1"); err != nil {
		t.Fatal(err)
	}
	r.reconcile(context.Background())
	if got := fake.get("app.acme.geneza.app"); got != nil {
		t.Fatalf("released funnel's A record should be withdrawn, got %v", got)
	}
}

func TestFunnelDNSNoHealthyRelaysKeepsLastGood(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	if err := st.UpsertRelay(relay("r1", "1.1.1.1", false, now)); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateFunnelBinding(&FunnelBinding{Hostname: "x.acme.geneza.app", WorkspaceID: "ws1"}, maxWorkspaceFunnels); err != nil {
		t.Fatal(err)
	}
	fake := newFakeRM()
	r := newFunnelDNSReconciler(st, map[string]webpki.RecordManager{"geneza.app": fake})
	r.reachable = func(string) bool { return true }
	r.reconcile(context.Background())
	if got := fake.get("x.acme.geneza.app"); len(got) != 1 {
		t.Fatalf("expected initial publish, got %v", got)
	}
	// All relays drain → reconcile must NOT blackhole (leave the last good set).
	if err := st.UpsertRelay(relay("r1", "1.1.1.1", true, now)); err != nil {
		t.Fatal(err)
	}
	r.reconcile(context.Background())
	if got := fake.get("x.acme.geneza.app"); len(got) != 1 {
		t.Fatalf("with no healthy relays the last good set must remain, got %v", got)
	}
}
