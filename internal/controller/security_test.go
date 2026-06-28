package controller

import (
	"context"
	"crypto/x509"
	"math/big"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"geneza.io/internal/ca"
)

func ctxWithIdentity(roles []string, serial *big.Int) context.Context {
	pi := &peerInfo{
		identity: &ca.Identity{Kind: ca.KindUser, Name: "op", Roles: roles},
		leaf:     &x509.Certificate{SerialNumber: serial},
	}
	return context.WithValue(context.Background(), peerInfoKey{}, pi)
}

func TestStripReservedRoles(t *testing.T) {
	// BOTH cluster roles (admin, platform-admin) are stripped from any
	// login/policy/membership-resolved set — a login can never mint a cluster
	// credential. ws-admin (the workspace admin) and ordinary roles survive.
	got := stripReservedRoles([]string{"admin", "platform-admin", "ws-admin", "ws-member"})
	for _, r := range got {
		if r == rolePlatformAdmin || r == roleAdmin {
			t.Fatalf("reserved cluster role %q must be stripped from login-resolved roles, got %v", r, got)
		}
	}
	var hasWSAdmin, hasMember bool
	for _, r := range got {
		if r == roleWSAdmin {
			hasWSAdmin = true
		}
		if r == "ws-member" {
			hasMember = true
		}
	}
	if !hasWSAdmin || !hasMember {
		t.Fatalf("non-reserved roles must survive, got %v", got)
	}
}

// TestRoleMapRejectsReservedRoles asserts config load fails closed if a keystone
// role_map (or default_role) tries to grant a reserved cluster role.
func TestRoleMapRejectsReservedRoles(t *testing.T) {
	base := func() *Config {
		return &Config{
			DataDir: "/tmp/x", ClusterName: "t",
			Workspaces: []WorkspaceConfig{{ID: defaultWorkspace, Name: "d", PolicyFile: "p.yaml"}},
		}
	}
	for _, tc := range []struct {
		name string
		mut  func(*Config)
	}{
		{"role_map->admin", func(c *Config) {
			c.Clouds = map[string]CloudConfig{"k": {Kind: "openstack", KeystoneURL: "https://k/v3", RoleMap: map[string]string{"admin": roleAdmin}}}
		}},
		{"role_map->platform-admin", func(c *Config) {
			c.Clouds = map[string]CloudConfig{"k": {Kind: "openstack", KeystoneURL: "https://k/v3", RoleMap: map[string]string{"foo": rolePlatformAdmin}}}
		}},
		{"default_role->admin", func(c *Config) {
			c.Clouds = map[string]CloudConfig{"k": {Kind: "openstack", KeystoneURL: "https://k/v3", DefaultRole: roleAdmin}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mut(c)
			c.applyDefaults()
			if err := c.validate(); err == nil {
				t.Fatalf("%s: config load must fail closed, got nil error", tc.name)
			}
		})
	}
	// A legitimate ws-admin / ws-viewer mapping loads fine.
	c := base()
	c.Clouds = map[string]CloudConfig{"k": {Kind: "openstack", KeystoneURL: "https://k/v3", RoleMap: map[string]string{"admin": roleWSAdmin, "member": "ws-viewer"}, DefaultRole: "ws-viewer"}}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		t.Fatalf("legitimate role_map must load, got %v", err)
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
	// Revoke the serial -> denied on the next call. The store write goes straight
	// to the backend here, so evict the deny cache the way the admin RevokeCert RPC
	// does in production (a direct write that skips the eviction stays cached until
	// the TTL — that is the intended deny-cache behavior, exercised separately).
	if err := srv.store.RevokeCert(&RevokedCert{Serial: serial.Text(16)}); err != nil {
		t.Fatal(err)
	}
	srv.deny.invalidateRevoked(serial.Text(16))
	if err := srv.checkNotRevoked(ctx); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked cert: want PermissionDenied, got %v", err)
	}
	// An unauthenticated ctx (no peer cert) is never blocked by revocation.
	if err := srv.checkNotRevoked(context.Background()); err != nil {
		t.Fatalf("no-cert ctx should pass revocation check: %v", err)
	}
}
