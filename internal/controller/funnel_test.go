package controller

import (
	"context"
	"errors"
	"testing"
	"time"
)

func enableManagedDomain(srv *Server) {
	srv.cfg.ManagedDomain = ManagedDomainConfig{
		Domains: []ManagedDomainEntry{{Base: "geneza.app", DNSProvider: "cf"}},
	}
}

func TestCreateFunnelValidation(t *testing.T) {
	srv := newReplayServer(t)
	enableManagedDomain(srv)
	ws := defaultWorkspace

	// A funnel hostname must be under a reservation the workspace owns.
	if _, err := srv.createFunnel(ws, "app.acme.geneza.app", "n1", "100.64.0.5:8080", "http", "t"); !errors.Is(err, errFunnelHost) {
		t.Fatalf("funnel before reservation: want errFunnelHost, got %v", err)
	}
	if _, err := srv.reserveWorkspaceSubdomain(ws, "geneza.app", "acme", "t"); err != nil {
		t.Fatal(err)
	}

	f, err := srv.createFunnel(ws, "app.acme.geneza.app", "n1", "100.64.0.5:8080", "", "t")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if f.Mode != "http" {
		t.Fatalf("default mode should be http, got %q", f.Mode)
	}

	// Bad target (no port) and unknown mode are rejected.
	if _, err := srv.createFunnel(ws, "x.acme.geneza.app", "n1", "noport", "http", "t"); err == nil {
		t.Fatal("target without port should fail")
	}
	if _, err := srv.createFunnel(ws, "y.acme.geneza.app", "n1", "1.2.3.4:5", "ftp", "t"); err == nil {
		t.Fatal("unknown mode should fail")
	}
	// A hostname under no reservation is rejected even if otherwise valid.
	if _, err := srv.createFunnel(ws, "evil.other.app", "n1", "1.2.3.4:5", "http", "t"); !errors.Is(err, errFunnelHost) {
		t.Fatalf("hostname outside reservations: want errFunnelHost, got %v", err)
	}

	// Cross-workspace uniqueness on the hostname.
	if err := srv.store.CreateFunnelBinding(&FunnelBinding{Hostname: "app.acme.geneza.app", WorkspaceID: "wsOther"}, maxWorkspaceFunnels); !errors.Is(err, errFunnelTaken) {
		t.Fatalf("cross-ws hostname claim: want errFunnelTaken, got %v", err)
	}

	// Delete removes it.
	if err := srv.deleteFunnel(ws, "app.acme.geneza.app", "t"); err != nil {
		t.Fatal(err)
	}
	if fs, _ := srv.store.ListWorkspaceFunnels(ws); len(fs) != 0 {
		t.Fatalf("funnel should be gone, got %v", fs)
	}
}

func TestManagerIssuesFunnelLeaf(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	iss := &fakeIssuer{notBefore: now, notAfter: now.Add(90 * 24 * time.Hour)}
	m, st := newTestManager(t, iss) // issuers keyed by "example.app"
	m.now = func() time.Time { return now }
	if err := st.ReserveSubdomain(&SubdomainReservation{Domain: "example.app", Label: "acme", WorkspaceID: "ws1"}, maxWorkspaceSubdomains); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateFunnelBinding(&FunnelBinding{Hostname: "app.acme.example.app", WorkspaceID: "ws1", NodeID: "n1", Target: "100.64.0.5:80", Mode: "http"}, maxWorkspaceFunnels); err != nil {
		t.Fatal(err)
	}

	if err := m.reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	// The reservation gets a wildcard; the funnel gets a narrow leaf.
	wc, err := st.GetManagedCert(reservationCertID("example.app", "acme"))
	if err != nil || wc.Kind != KindWorkspaceWildcard {
		t.Fatalf("wildcard: %+v err=%v", wc, err)
	}
	leaf, err := st.GetManagedCert(funnelCertID("app.acme.example.app"))
	if err != nil || leaf.Kind != KindFunnelLeaf {
		t.Fatalf("funnel leaf: %+v err=%v", leaf, err)
	}
	if len(leaf.Names) != 1 || leaf.Names[0] != "app.acme.example.app" {
		t.Fatalf("leaf must be narrow (one hostname), got %v", leaf.Names)
	}
	if iss.calls != 2 {
		t.Fatalf("want 2 issuances (wildcard + leaf), got %d", iss.calls)
	}

	// Releasing the funnel GCs the leaf (but not the wildcard).
	if err := st.DeleteFunnelBinding("app.acme.example.app", "ws1"); err != nil {
		t.Fatal(err)
	}
	if err := m.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetManagedCert(funnelCertID("app.acme.example.app")); !errors.Is(err, ErrNotFound) {
		t.Errorf("released funnel's leaf should be GC'd, got %v", err)
	}
	if _, err := st.GetManagedCert(reservationCertID("example.app", "acme")); err != nil {
		t.Errorf("the wildcard must survive a funnel release: %v", err)
	}
}

func TestAgentBundleExcludesFunnelLeaf(t *testing.T) {
	srv := newReplayServer(t)
	ws := defaultWorkspace
	_, pub := gwNodeKeypair(t)
	node := &NodeRecord{ID: "n1", WorkspaceID: ws, NoisePub: pub, Approved: true}
	if err := srv.store.PutNode(ws, node); err != nil {
		t.Fatal(err)
	}
	pem := []byte("-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nc\n-----END CERTIFICATE-----\n")
	wcRef := writeBlob(t, srv, "wc.pem", pem)
	leafRef := writeBlob(t, srv, "leaf.pem", pem)
	if err := srv.store.PutManagedCert(&ManagedCertRecord{ID: "ws-x", WorkspaceID: ws, Domain: "geneza.app", Label: "acme", Kind: KindWorkspaceWildcard, Ref: wcRef, Epoch: 1}); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.PutManagedCert(&ManagedCertRecord{ID: "fnl-x", WorkspaceID: ws, Domain: "geneza.app", Label: "app.acme", Kind: KindFunnelLeaf, Ref: leafRef, Epoch: 1}); err != nil {
		t.Fatal(err)
	}
	cb, err := srv.buildNodeCertBundle(ws, node)
	if err != nil {
		t.Fatal(err)
	}
	if len(cb.GetCerts()) != 1 || cb.GetCerts()[0].GetZone() != "acme.geneza.app" {
		t.Fatalf("agent bundle must contain only the wildcard, got %d certs %v", len(cb.GetCerts()), cb.GetCerts())
	}
}
