package controller

import (
	"testing"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

func TestManagedDNSZones(t *testing.T) {
	srv := newReplayServer(t)
	srv.cfg.ManagedDomain = ManagedDomainConfig{
		Domains: []ManagedDomainEntry{{Base: "geneza.app", DNSProvider: "cf"}},
	}
	recs := []*genezav1.DnsRecord{{Name: "web1", Ip: "100.64.0.5", Ttl: 15}}

	// No reservations yet → no managed zones.
	if z := srv.managedDNSZones(defaultWorkspace, recs); z != nil {
		t.Fatalf("no reservations should yield no zones, got %v", z)
	}

	if _, err := srv.reserveWorkspaceSubdomain(defaultWorkspace, "geneza.app", "acme", "test"); err != nil {
		t.Fatal(err)
	}

	z := srv.managedDNSZones(defaultWorkspace, recs)
	if len(z) != 1 || z[0].GetSuffix() != "acme.geneza.app" {
		t.Fatalf("want one zone acme.geneza.app, got %+v", z)
	}
	if len(z[0].GetRecords()) != 1 || z[0].GetRecords()[0].GetName() != "web1" {
		t.Fatalf("managed zone should carry the default overlay records, got %+v", z[0].GetRecords())
	}

	// No default records (node has no resolvable peers) → nothing to serve.
	if srv.managedDNSZones(defaultWorkspace, nil) != nil {
		t.Fatal("empty default records should yield no zones")
	}

	// Feature off → nothing.
	srv.cfg.ManagedDomain = ManagedDomainConfig{}
	if srv.managedDNSZones(defaultWorkspace, recs) != nil {
		t.Fatal("disabled managed domain should yield no zones")
	}
}
