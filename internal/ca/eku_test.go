package ca

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

// A relay cert must carry BOTH server- and client-auth EKUs: the relay is a TLS
// server for the rendezvous floor AND a TLS client when it heartbeats the
// controller registrar with the same cert. A server-only cert is rejected by the
// controller's client-cert verification. A controller cert stays server-only.
func TestServerCertEKUs(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "ekutest"); err != nil {
		t.Fatalf("Init: %v", err)
	}
	caInst, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	leafOf := func(kind, name string) *x509.Certificate {
		t.Helper()
		certPEM, _, err := caInst.IssueServerKeypair(Profile{Kind: kind, Name: name, TTL: time.Hour})
		if err != nil {
			t.Fatalf("issue %s: %v", kind, err)
		}
		blk, _ := pem.Decode(certPEM)
		if blk == nil {
			t.Fatalf("%s: no PEM block", kind)
		}
		leaf, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatalf("%s parse: %v", kind, err)
		}
		return leaf
	}

	has := func(ekus []x509.ExtKeyUsage, want x509.ExtKeyUsage) bool {
		for _, e := range ekus {
			if e == want {
				return true
			}
		}
		return false
	}

	relay := leafOf(KindRelay, "relay-eu")
	if !has(relay.ExtKeyUsage, x509.ExtKeyUsageServerAuth) || !has(relay.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		t.Fatalf("relay cert EKUs = %v, want both server+client auth", relay.ExtKeyUsage)
	}

	gw := leafOf(KindController, "gw")
	if !has(gw.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatalf("controller cert missing server-auth EKU: %v", gw.ExtKeyUsage)
	}
	if has(gw.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		t.Fatalf("controller cert should not carry client-auth EKU: %v", gw.ExtKeyUsage)
	}

	// The relay leaf must actually verify as a CLIENT cert against the roots —
	// exactly the check the controller's gRPC server performs on a heartbeat.
	pool, err := PoolFromPEM(caInst.RootsPEM)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	inter := x509.NewCertPool()
	inter.AppendCertsFromPEM(caInst.IssuingPEM)
	if _, err := relay.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("relay cert failed client-auth verify (the registrar bug): %v", err)
	}
}
