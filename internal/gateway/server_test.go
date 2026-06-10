package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"osie.cloud/geneza/internal/ca"
	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
	"osie.cloud/geneza/internal/types"
)

func testServerConfig(t *testing.T) *Config {
	t.Helper()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(testPolicyDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		DataDir:     filepath.Join(dir, "data"),
		ClusterName: "test",
		RelayAddrs:  []string{"127.0.0.1:7403"},
		PolicyFile:  policyPath,
		LocalUsers: []LocalUser{
			{Username: "alice", PasswordBcrypt: string(hash), Groups: []string{"admins"}},
		},
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestServerLoginEnrollAndConfigReconcile(t *testing.T) {
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatalf("init: %v", err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// Local login issues a user cert carrying the policy-resolved roles.
	key, err := ca.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ca.MakeCSR(key, "alice")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.handleLogin(context.Background(), &genezav1.LoginRequest{
		Provider: "local", Username: "alice", Password: "hunter2", CsrPem: csr,
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if resp.User != "alice" || len(resp.Roles) != 1 || resp.Roles[0] != "ops" {
		t.Fatalf("login identity: %q %v", resp.User, resp.Roles)
	}
	if _, err := srv.handleLogin(context.Background(), &genezav1.LoginRequest{
		Provider: "local", Username: "alice", Password: "wrong", CsrPem: csr,
	}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("bad password: want Unauthenticated, got %v", err)
	}
	// A user with no role bindings gets no cert at all.
	hash, _ := bcrypt.GenerateFromPassword([]byte("x"), bcrypt.MinCost)
	srv.identity.local = append(srv.identity.local, LocalUser{Username: "norole", PasswordBcrypt: string(hash)})
	if _, err := srv.handleLogin(context.Background(), &genezav1.LoginRequest{
		Provider: "local", Username: "norole", Password: "x", CsrPem: csr,
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("roleless login: want PermissionDenied, got %v", err)
	}

	// Token enrollment issues a node cert and the signed cluster config.
	admin := &adminAPIService{s: srv}
	tok, err := admin.CreateJoinToken(context.Background(), &genezav1.CreateJoinTokenRequest{
		Labels: map[string]string{"env": "prod"},
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	enroll := &enrollmentService{s: srv}
	nodeKey, _ := ca.GenerateKey()
	nodeCSR, _ := ca.MakeCSR(nodeKey, "node")
	noise := make([]byte, 32)
	enResp, err := enroll.Enroll(context.Background(), &genezav1.EnrollRequest{
		Provider:       "token",
		Token:          tok.Token,
		CsrPem:         nodeCSR,
		NoiseStaticPub: noise,
		Labels:         map[string]string{"env": "dev", "rack": "r1"},
		Platform:       &genezav1.PlatformInfo{Hostname: "host1"},
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	node, err := srv.store.GetNode(enResp.NodeId)
	if err != nil {
		t.Fatal(err)
	}
	// Token labels override the agent's self-asserted ones.
	if node.Labels["env"] != "prod" || node.Labels["rack"] != "r1" || node.Name != "host1" {
		t.Fatalf("node record: %+v", node)
	}
	// The signed cluster config must verify against its own grant keys.
	signed, err := types.DecodeSigned(enResp.SignedClusterConfig)
	if err != nil {
		t.Fatal(err)
	}
	var cc types.ClusterConfig
	if err := json.Unmarshal(signed.Payload, &cc); err != nil {
		t.Fatal(err)
	}
	trusted, err := cc.TrustedKeys()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := types.VerifyClusterConfig(trusted, signed, 1); err != nil {
		t.Fatalf("cluster config verify: %v", err)
	}
	if cc.ConfigVersion != 1 {
		t.Fatalf("initial config version = %d, want 1", cc.ConfigVersion)
	}
	// Second use of the single-use token must fail.
	if _, err := enroll.Enroll(context.Background(), &genezav1.EnrollRequest{
		Provider: "token", Token: tok.Token, CsrPem: nodeCSR, NoiseStaticPub: noise,
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("token reuse: want PermissionDenied, got %v", err)
	}
	// The reserved OpenStack seam answers Unimplemented.
	if _, err := enroll.Enroll(context.Background(), &genezav1.EnrollRequest{
		Provider: "openstack-metadata",
	}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("openstack-metadata: want Unimplemented, got %v", err)
	}
	srv.Close()

	// Changing config-derived desired state (relay_addrs) bumps and re-signs
	// the cluster config on the next start.
	cfg.RelayAddrs = []string{"127.0.0.1:7403", "127.0.0.2:7403"}
	srv2, err := New(cfg)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	defer srv2.Close()
	v, signedBytes := srv2.clusterConfig()
	if v != 2 {
		t.Fatalf("config version after change = %d, want 2", v)
	}
	signed2, err := types.DecodeSigned(signedBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := types.VerifyClusterConfig(trusted, signed2, 1); err != nil {
		t.Fatalf("bumped config verify: %v", err)
	}
	// And an unchanged restart must NOT bump.
	srv2.Close()
	srv3, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv3.Close()
	if v, _ := srv3.clusterConfig(); v != 2 {
		t.Fatalf("stable restart bumped config to %d", v)
	}

	// Stable promotion gate: with canary nodes set and offline, promotion
	// must fail; with no canary ring it succeeds.
	admin3 := &adminAPIService{s: srv3}
	if _, err := admin3.SetDesiredVersion(context.Background(), &genezav1.SetDesiredVersionRequest{
		Ring: "canary", Version: "1.1.0", CanaryNodes: []string{enResp.NodeId},
	}); err != nil {
		t.Fatalf("set canary: %v", err)
	}
	_, err = admin3.SetDesiredVersion(context.Background(), &genezav1.SetDesiredVersionRequest{
		Ring: "stable", Version: "1.1.0",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("promotion with offline canary: want FailedPrecondition, got %v", err)
	}
}

func TestInitRefusesReinit(t *testing.T) {
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatal(err)
	}
	if err := InitDataDir(cfg); err == nil {
		t.Fatal("re-init must refuse")
	}
}
