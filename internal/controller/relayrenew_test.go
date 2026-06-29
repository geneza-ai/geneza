package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"geneza.io/internal/ca"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

func TestListRelaysSurfacesSerial(t *testing.T) {
	srv := newReplayServer(t)
	a := &adminAPIService{s: srv}
	if err := srv.store.UpsertRelay(&RelayRecord{
		RelayNode:    types.RelayNode{RegionID: "r1", RelayID: "relay-a", Addrs: []string{"1.2.3.4:7404"}},
		Version:      "1.0.0",
		LastSeenUnix: time.Now().Unix(),
		CertSerial:   "deadbeef",
	}); err != nil {
		t.Fatal(err)
	}
	resp, err := a.ListRelays(context.Background(), &genezav1.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetRelays()) != 1 {
		t.Fatalf("want 1 relay, got %d", len(resp.GetRelays()))
	}
	r := resp.GetRelays()[0]
	if r.GetRelayId() != "relay-a" || r.GetCertSerial() != "deadbeef" {
		t.Errorf("relay %q serial %q, want relay-a/deadbeef", r.GetRelayId(), r.GetCertSerial())
	}
}

func TestMaybeRenewRelayCert(t *testing.T) {
	s := newReplayServer(t)
	rr := &relayRegistryService{s: s}
	rec := &RelayRecord{RelayNode: types.RelayNode{RelayID: "relay-x"}}

	mkLeaf := func(ttl time.Duration) *x509.Certificate {
		leafPEM, _, err := s.ca.IssueServerKeypair(ca.Profile{
			Kind: ca.KindRelay, Name: "relay-x", TTL: ttl,
			DNSNames: []string{"relay.example.com"}, IPs: []net.IP{net.ParseIP("203.0.113.5")},
		})
		if err != nil {
			t.Fatal(err)
		}
		blk, _ := pem.Decode(leafPEM)
		c, _ := x509.ParseCertificate(blk.Bytes)
		return c
	}
	relayCtx := func(leaf *x509.Certificate) context.Context {
		return context.WithValue(context.Background(), peerInfoKey{},
			&peerInfo{identity: &ca.Identity{Kind: ca.KindRelay, Name: "relay-x"}, leaf: leaf})
	}

	nearExpiry := mkLeaf(30 * time.Second) // already past 2/3 of its short life
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := ca.MakeCSR(key, "relay-x")

	// No CSR -> no work.
	if c, roots := rr.maybeRenewRelayCert(relayCtx(nearExpiry), rec, nil); c != nil || roots != nil {
		t.Fatal("absent CSR must yield no cert")
	}

	// A node (non-relay) identity must never receive a relay renewal.
	nodeCtx := context.WithValue(context.Background(), peerInfoKey{},
		&peerInfo{identity: &ca.Identity{Kind: ca.KindNode, Name: "relay-x"}, leaf: nearExpiry})
	if c, _ := rr.maybeRenewRelayCert(nodeCtx, rec, csr); c != nil {
		t.Fatal("a non-relay identity must not be issued a relay cert")
	}

	// A cert that is NOT near expiry must be refused (no serial churn on every connect).
	if c, _ := rr.maybeRenewRelayCert(relayCtx(mkLeaf(2*365*24*time.Hour)), rec, csr); c != nil {
		t.Fatal("a fresh cert must not be renewed")
	}

	// Happy path.
	certPEM, roots := rr.maybeRenewRelayCert(relayCtx(nearExpiry), rec, csr)
	if certPEM == nil {
		t.Fatal("expected a renewed cert")
	}
	if string(roots) != string(s.ca.RootsPEM) {
		t.Error("CA roots should be returned for pinning")
	}
	rblk, _ := pem.Decode(certPEM)
	renewed, err := x509.ParseCertificate(rblk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := renewed.URIs[0].String(); got != "geneza://relay/relay-x" {
		t.Errorf("identity = %q, want geneza://relay/relay-x", got)
	}
	if len(renewed.DNSNames) == 0 || renewed.DNSNames[0] != "relay.example.com" {
		t.Errorf("SANs not preserved: %v", renewed.DNSNames)
	}
	if len(renewed.IPAddresses) == 0 || !renewed.IPAddresses[0].Equal(net.ParseIP("203.0.113.5")) {
		t.Errorf("IP SANs not preserved: %v", renewed.IPAddresses)
	}
	csrPub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	renewedPub, _ := x509.MarshalPKIXPublicKey(renewed.PublicKey)
	if string(csrPub) != string(renewedPub) {
		t.Error("renewed cert must bind the CSR's key")
	}
	// The relay record tracks the just-issued serial, so the fleet view / a revoke
	// targets the cert the relay now holds.
	if rec.CertSerial != serialHex(renewed) {
		t.Errorf("record serial = %q, want the renewed cert serial %q", rec.CertSerial, serialHex(renewed))
	}
}
