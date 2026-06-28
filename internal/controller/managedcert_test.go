package controller

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"geneza.io/internal/webpki"
)

func pemBytes(typ string, b []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b})
}

// fakeIssuer returns a deterministic cert and counts calls.
type fakeIssuer struct {
	calls               int
	notBefore, notAfter time.Time
	err                 error
}

func (f *fakeIssuer) Issue(_ context.Context, names []string) (*webpki.Cert, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &webpki.Cert{
		Names:     names,
		ChainPEM:  pemBytes("CERTIFICATE", []byte("leaf")),
		KeyPEM:    pemBytes("PRIVATE KEY", []byte("key")),
		NotBefore: f.notBefore,
		NotAfter:  f.notAfter,
	}, nil
}

func TestManagedWorkspaceToken(t *testing.T) {
	a := managedWorkspaceToken("acme")
	b := managedWorkspaceToken("other")
	if a == b {
		t.Fatal("distinct workspaces must get distinct tokens")
	}
	if a != managedWorkspaceToken("acme") {
		t.Fatal("token must be stable")
	}
	if !strings.HasPrefix(a, "w-") || !validSubdomainLabel(a) {
		t.Errorf("token %q must be a valid w- label", a)
	}
}

func TestReservationWildcardNames(t *testing.T) {
	r := &SubdomainReservation{Domain: "example.app", Label: "acme"}
	names := reservationWildcardNames(r)
	if len(names) != 2 || names[0] != "*.acme.example.app" || names[1] != "acme.example.app" {
		t.Fatalf("unexpected SANs %v", names)
	}
	if reservationCertID("example.app", "acme") != "sub-acme-example-app" {
		t.Errorf("certID = %q", reservationCertID("example.app", "acme"))
	}
}

func TestRenewDue(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	day := int64(86400)
	if !renewDue(nil, now) {
		t.Error("missing cert is due")
	}
	fresh := &ManagedCertRecord{NotBefore: now.Unix(), NotAfter: now.Unix() + 90*day}
	if renewDue(fresh, now) {
		t.Error("a just-issued 90d cert is not due")
	}
	expiring := &ManagedCertRecord{NotBefore: now.Unix() - 85*day, NotAfter: now.Unix() + 5*day}
	if !renewDue(expiring, now) {
		t.Error("a cert in its final third is due")
	}
	if !renewDue(&ManagedCertRecord{NotBefore: now.Unix(), NotAfter: now.Unix()}, now) {
		t.Error("zero-lifetime cert is due")
	}
}

func TestSplitBundlePEM(t *testing.T) {
	c := &webpki.Cert{
		ChainPEM: append(pemBytes("CERTIFICATE", []byte("leaf")), pemBytes("CERTIFICATE", []byte("issuer"))...),
		KeyPEM:   pemBytes("PRIVATE KEY", []byte("key")),
	}
	chain, key, err := splitBundlePEM(bundlePEM(c))
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if strings.Count(string(chain), "BEGIN CERTIFICATE") != 2 {
		t.Errorf("chain should hold both certs: %s", chain)
	}
	if !strings.Contains(string(key), "PRIVATE KEY") {
		t.Errorf("key missing: %s", key)
	}
	if _, _, err := splitBundlePEM(pemBytes("CERTIFICATE", []byte("only-cert"))); err == nil {
		t.Error("a bundle with no key must error")
	}
}

func newTestManager(t *testing.T, iss webpki.Issuer) (*managedCertManager, *bboltStore) {
	t.Helper()
	st := testStore(t)
	blobs := newLocalBlobStore(t.TempDir())
	m := newManagedCertManager(st, blobs, map[string]webpki.Issuer{"example.app": iss})
	return m, st
}

func reserve(t *testing.T, st *bboltStore, label, ws string) {
	t.Helper()
	if err := st.ReserveSubdomain(&SubdomainReservation{Domain: "example.app", Label: label, WorkspaceID: ws}, maxWorkspaceSubdomains); err != nil {
		t.Fatalf("reserve %s: %v", label, err)
	}
}

func readBlob(t *testing.T, m *managedCertManager, ref string) []byte {
	t.Helper()
	r, err := m.blobs.open(ref)
	if err != nil {
		t.Fatalf("open blob %q: %v", ref, err)
	}
	defer r.Close()
	b, _ := io.ReadAll(r)
	return b
}

func TestManagerIssueAndIdempotent(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	iss := &fakeIssuer{notBefore: now, notAfter: now.Add(90 * 24 * time.Hour)}
	m, st := newTestManager(t, iss)
	m.now = func() time.Time { return now }
	reserve(t, st, "acme", "ws1")

	if err := m.reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if iss.calls != 1 {
		t.Fatalf("want 1 issue, got %d", iss.calls)
	}
	rec, err := st.GetManagedCert(reservationCertID("example.app", "acme"))
	if err != nil {
		t.Fatalf("get cert: %v", err)
	}
	if rec.Epoch != 1 || rec.WorkspaceID != "ws1" || rec.Domain != "example.app" || rec.Label != "acme" {
		t.Fatalf("unexpected record %+v", rec)
	}
	if rec.Names[0] != "*.acme.example.app" {
		t.Errorf("names %v", rec.Names)
	}
	if _, _, err := splitBundlePEM(readBlob(t, m, rec.Ref)); err != nil {
		t.Errorf("stored bundle: %v", err)
	}

	if err := m.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if iss.calls != 1 {
		t.Errorf("a current cert must not be re-issued, calls=%d", iss.calls)
	}
}

func TestManagerRenews(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	iss := &fakeIssuer{notBefore: now, notAfter: now.Add(90 * 24 * time.Hour)}
	m, st := newTestManager(t, iss)
	m.now = func() time.Time { return now }
	reserve(t, st, "acme", "ws1")
	if err := m.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, _ := st.GetManagedCert(reservationCertID("example.app", "acme"))
	oldRef := first.Ref

	first.NotBefore = now.Unix() - 85*86400
	first.NotAfter = now.Unix() + 5*86400
	if err := st.PutManagedCert(first); err != nil {
		t.Fatal(err)
	}

	if err := m.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if iss.calls != 2 {
		t.Fatalf("expiring cert must renew, calls=%d", iss.calls)
	}
	second, _ := st.GetManagedCert(reservationCertID("example.app", "acme"))
	if second.Epoch != 2 || second.Ref == oldRef {
		t.Errorf("renewal must advance epoch + mint a fresh ref: %+v (old %s)", second, oldRef)
	}
	if _, err := m.blobs.open(oldRef); !errors.Is(err, ErrNotFound) {
		t.Errorf("old blob should be GC'd, open err = %v", err)
	}
}

func TestManagerGCsReleasedReservation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	iss := &fakeIssuer{notBefore: now, notAfter: now.Add(90 * 24 * time.Hour)}
	m, st := newTestManager(t, iss)
	m.now = func() time.Time { return now }
	reserve(t, st, "acme", "ws1")
	if err := m.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec, _ := st.GetManagedCert(reservationCertID("example.app", "acme"))
	ref := rec.Ref

	if err := st.ReleaseSubdomain("example.app", "acme", "ws1"); err != nil {
		t.Fatal(err)
	}
	if err := m.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetManagedCert(reservationCertID("example.app", "acme")); !errors.Is(err, ErrNotFound) {
		t.Errorf("released reservation's cert should be GC'd, got %v", err)
	}
	if _, err := m.blobs.open(ref); !errors.Is(err, ErrNotFound) {
		t.Errorf("released cert's blob should be removed, got %v", err)
	}
}

func TestManagerNoIssuerForDomain(t *testing.T) {
	m, st := newTestManager(t, &fakeIssuer{})
	if err := st.ReserveSubdomain(&SubdomainReservation{Domain: "unknown.net", Label: "x", WorkspaceID: "ws1"}, maxWorkspaceSubdomains); err != nil {
		t.Fatal(err)
	}
	if err := m.reconcile(context.Background()); err == nil {
		t.Error("a reservation on a domain with no issuer must surface an error")
	}
}

func TestManagerIssueErrorDoesNotPersist(t *testing.T) {
	iss := &fakeIssuer{err: errors.New("dns-01 failed")}
	m, st := newTestManager(t, iss)
	reserve(t, st, "acme", "ws1")
	if err := m.reconcile(context.Background()); err == nil {
		t.Error("reconcile should surface the issue error")
	}
	if _, err := st.GetManagedCert(reservationCertID("example.app", "acme")); !errors.Is(err, ErrNotFound) {
		t.Errorf("a failed issue must not persist a record, got %v", err)
	}
}
