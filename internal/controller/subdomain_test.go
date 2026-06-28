package controller

import (
	"errors"
	"testing"
)

func mkRes(domain, label, ws string) *SubdomainReservation {
	return &SubdomainReservation{Domain: domain, Label: label, WorkspaceID: ws}
}

func TestReserveSubdomainUniqueness(t *testing.T) {
	st := testStore(t)
	if err := st.ReserveSubdomain(mkRes("example.app", "acme", "ws1"), 3); err != nil {
		t.Fatalf("ws1 reserve: %v", err)
	}
	// A different workspace cannot take the same (domain,label).
	if err := st.ReserveSubdomain(mkRes("example.app", "acme", "ws2"), 3); !errors.Is(err, errSubdomainTaken) {
		t.Fatalf("want errSubdomainTaken, got %v", err)
	}
	// The owner re-reserving its own is a no-op.
	if err := st.ReserveSubdomain(mkRes("example.app", "acme", "ws1"), 3); err != nil {
		t.Fatalf("idempotent re-reserve: %v", err)
	}
	// Same label on a different domain is independent.
	if err := st.ReserveSubdomain(mkRes("other.net", "acme", "ws2"), 3); err != nil {
		t.Fatalf("different domain: %v", err)
	}
	got, err := st.GetSubdomainReservation("example.app", "acme")
	if err != nil || got.WorkspaceID != "ws1" {
		t.Fatalf("get reservation: %+v err=%v", got, err)
	}
}

func TestReserveSubdomainCap(t *testing.T) {
	st := testStore(t)
	for _, l := range []string{"a", "b", "c"} {
		if err := st.ReserveSubdomain(mkRes("example.app", l, "ws1"), 3); err != nil {
			t.Fatalf("reserve %s: %v", l, err)
		}
	}
	if err := st.ReserveSubdomain(mkRes("example.app", "d", "ws1"), 3); !errors.Is(err, errSubdomainLimit) {
		t.Fatalf("4th reservation must hit the cap, got %v", err)
	}
	// Re-reserving an already-owned label past the cap is still fine (no new row).
	if err := st.ReserveSubdomain(mkRes("example.app", "a", "ws1"), 3); err != nil {
		t.Fatalf("re-reserve at cap: %v", err)
	}
	// A different workspace still has its own budget.
	if err := st.ReserveSubdomain(mkRes("example.app", "z", "ws2"), 3); err != nil {
		t.Fatalf("other workspace budget: %v", err)
	}
	subs, err := st.ListWorkspaceSubdomains("ws1")
	if err != nil || len(subs) != 3 {
		t.Fatalf("ws1 should hold 3, got %d (%v)", len(subs), err)
	}
}

func TestReleaseSubdomain(t *testing.T) {
	st := testStore(t)
	if err := st.ReserveSubdomain(mkRes("example.app", "acme", "ws1"), 3); err != nil {
		t.Fatal(err)
	}
	// A non-owner cannot release it.
	if err := st.ReleaseSubdomain("example.app", "acme", "ws2"); !errors.Is(err, errSubdomainTaken) {
		t.Fatalf("non-owner release must fail, got %v", err)
	}
	if err := st.ReleaseSubdomain("example.app", "acme", "ws1"); err != nil {
		t.Fatalf("owner release: %v", err)
	}
	if _, err := st.GetSubdomainReservation("example.app", "acme"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("released reservation should be gone, got %v", err)
	}
	// Releasing a missing one is a no-op.
	if err := st.ReleaseSubdomain("example.app", "acme", "ws1"); err != nil {
		t.Fatalf("release missing: %v", err)
	}
	// The freed label is now claimable by anyone.
	if err := st.ReserveSubdomain(mkRes("example.app", "acme", "ws2"), 3); err != nil {
		t.Fatalf("reclaim freed label: %v", err)
	}
}

func TestValidSubdomainLabel(t *testing.T) {
	ok := []string{"acme", "acme-prod", "a", "x1", "w-jbswy3dp"}
	bad := []string{"", "-acme", "acme-", "ACME", "a.b", "a_b", "café"}
	for _, l := range ok {
		if !validSubdomainLabel(l) {
			t.Errorf("%q should be valid", l)
		}
	}
	for _, l := range bad {
		if validSubdomainLabel(l) {
			t.Errorf("%q should be invalid", l)
		}
	}
}
