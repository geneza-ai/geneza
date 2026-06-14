package gateway

import (
	"context"
	"crypto/x509"
	"math/big"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"osie.cloud/geneza/internal/ca"
)

func ctxWithIdentity(roles []string, serial *big.Int) context.Context {
	pi := &peerInfo{
		identity: &ca.Identity{Kind: ca.KindUser, Name: "op", Roles: roles},
		leaf:     &x509.Certificate{SerialNumber: serial},
	}
	return context.WithValue(context.Background(), peerInfoKey{}, pi)
}

func TestStripReservedRoles(t *testing.T) {
	got := stripReservedRoles([]string{"admin", "platform-admin", "ws-user"})
	for _, r := range got {
		if r == rolePlatformAdmin {
			t.Fatalf("platform-admin must be stripped from policy-resolved roles, got %v", got)
		}
	}
	// admin (IdP-grantable) and other roles survive.
	var hasAdmin, hasUser bool
	for _, r := range got {
		if r == roleAdmin {
			hasAdmin = true
		}
		if r == "ws-user" {
			hasUser = true
		}
	}
	if !hasAdmin || !hasUser {
		t.Fatalf("non-reserved roles must survive, got %v", got)
	}
}

func TestRequirePlatformAdmin(t *testing.T) {
	// A plain admin (IdP-grantable) is rejected for hub mutations.
	if err := requirePlatformAdmin(ctxWithIdentity([]string{"admin"}, big.NewInt(1))); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("admin without platform-admin: want PermissionDenied, got %v", err)
	}
	// platform-admin (break-glass) is allowed.
	if err := requirePlatformAdmin(ctxWithIdentity([]string{"admin", "platform-admin"}, big.NewInt(1))); err != nil {
		t.Fatalf("platform-admin should be allowed: %v", err)
	}
	// No identity at all -> Unauthenticated.
	if err := requirePlatformAdmin(context.Background()); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no identity: want Unauthenticated, got %v", err)
	}
}

func TestCertRevocationStore(t *testing.T) {
	s, err := OpenStore(t.TempDir() + "/s.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.IsCertRevoked("deadbeef") {
		t.Fatal("nothing should be revoked initially")
	}
	if err := s.RevokeCert(&RevokedCert{Serial: "deadbeef", By: "op", Reason: "lost laptop"}); err != nil {
		t.Fatal(err)
	}
	if !s.IsCertRevoked("deadbeef") {
		t.Fatal("serial should be revoked after RevokeCert")
	}
	rs, _ := s.ListRevokedCerts()
	if len(rs) != 1 || rs[0].Serial != "deadbeef" || rs[0].Reason != "lost laptop" {
		t.Fatalf("list revoked: %+v", rs)
	}
}

func TestCheckNotRevoked(t *testing.T) {
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	serial := big.NewInt(0xABCD)
	ctx := ctxWithIdentity([]string{"node"}, serial)
	// Not revoked -> allowed.
	if err := srv.checkNotRevoked(ctx); err != nil {
		t.Fatalf("unrevoked cert should pass: %v", err)
	}
	// Revoke the serial -> denied on the next call.
	if err := srv.store.RevokeCert(&RevokedCert{Serial: serial.Text(16)}); err != nil {
		t.Fatal(err)
	}
	if err := srv.checkNotRevoked(ctx); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked cert: want PermissionDenied, got %v", err)
	}
	// An unauthenticated ctx (no peer cert) is never blocked by revocation.
	if err := srv.checkNotRevoked(context.Background()); err != nil {
		t.Fatalf("no-cert ctx should pass revocation check: %v", err)
	}
}
