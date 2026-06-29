package controller

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"geneza.io/internal/ca"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

func adminWSCtx() context.Context { return userCtx(defaultWorkspace, "adm", roleWSAdmin) }

func testServerConfig(t testing.TB) *Config {
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

	// Cert issuance (the device-grant redeem path) bakes the resolved roles into
	// the cert. alice's roles come from the policy binding admins -> ops.
	key, err := ca.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ca.MakeCSR(key, "alice")
	if err != nil {
		t.Fatal(err)
	}
	roles := srv.rolesForMember(defaultWorkspace, providerLocal, "alice", "alice", []string{"admins"})
	if len(roles) != 1 || roles[0] != "ops" {
		t.Fatalf("alice roles: %v", roles)
	}
	certPEM, _, err := srv.issueUserCert("device:"+providerLocal, "alice", "alice", defaultWorkspace, roles, csr, time.Hour)
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	blk, _ := pem.Decode(certPEM)
	crt, _ := x509.ParseCertificate(blk.Bytes)
	id, err := ca.PeerIdentity(crt)
	if err != nil || id.Name != "alice" || id.Workspace != defaultWorkspace || len(id.Roles) != 1 || id.Roles[0] != "ops" {
		t.Fatalf("issued cert identity: %+v err=%v", id, err)
	}
	// A user with no role bindings resolves to no roles (device approve denies).
	if r := srv.rolesForMember(defaultWorkspace, providerLocal, "norole", "norole", nil); len(r) != 0 {
		t.Fatalf("roleless user must resolve to no roles, got %v", r)
	}
	// Reserved cluster roles are never issued even if the caller requests them.
	rc, _, err := srv.issueUserCert("device:"+providerLocal, "x", "x", defaultWorkspace, []string{"ops", roleAdmin, rolePlatformAdmin}, csr, time.Hour)
	if err != nil {
		t.Fatalf("issue cert (reserved): %v", err)
	}
	blk2, _ := pem.Decode(rc)
	crt2, _ := x509.ParseCertificate(blk2.Bytes)
	id2, _ := ca.PeerIdentity(crt2)
	for _, rr := range id2.Roles {
		if reservedRoles[rr] {
			t.Fatalf("issued cert leaked a reserved role: %v", id2.Roles)
		}
	}

	// Token enrollment issues a node cert and the signed cluster config.
	admin := &workspaceAPIService{s: srv}
	tok, err := admin.CreateJoinToken(adminWSCtx(), &genezav1.CreateJoinTokenRequest{
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
	node, err := srv.store.GetNode(defaultWorkspace, enResp.NodeId)
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
	admin3 := &clusterAPIService{s: srv3}
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

// TestEnrollApprovalGate covers the zero-trust admission model: a token-enrolled
// node lands pending; ApproveNode flips it; and an --auto-approve token enrolls
// already-approved with the auto provenance recorded.
func TestEnrollApprovalGate(t *testing.T) {
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	admin := &workspaceAPIService{s: srv}
	enroll := &enrollmentService{s: srv}

	enrollWith := func(autoApprove bool) *NodeRecord {
		t.Helper()
		tok, err := admin.CreateJoinToken(adminWSCtx(), &genezav1.CreateJoinTokenRequest{
			Labels: map[string]string{"env": "prod"}, AutoApprove: autoApprove,
		})
		if err != nil {
			t.Fatal(err)
		}
		key, _ := ca.GenerateKey()
		csr, _ := ca.MakeCSR(key, "node")
		resp, err := enroll.Enroll(context.Background(), &genezav1.EnrollRequest{
			Provider: "token", Token: tok.Token, CsrPem: csr,
			NoiseStaticPub: make([]byte, 32),
			Platform:       &genezav1.PlatformInfo{Hostname: "h"},
		})
		if err != nil {
			t.Fatalf("enroll(auto=%v): %v", autoApprove, err)
		}
		n, err := srv.store.GetNode(defaultWorkspace, resp.NodeId)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Default: pending.
	pending := enrollWith(false)
	if pending.Approved {
		t.Fatal("token enrollment should land pending (Approved=false)")
	}
	// Approve flips it and records provenance.
	if _, err := admin.ApproveNode(adminWSCtx(), &genezav1.ApproveNodeRequest{Node: pending.ID, Approve: true}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	got, _ := srv.store.GetNode(defaultWorkspace, pending.ID)
	// ApprovedBy comes from the admin cert identity (empty in this unit ctx); the
	// real provenance is asserted via the auto-approve path below.
	if !got.Approved || got.ApprovedAtUnix == 0 {
		t.Fatalf("after approve: %+v", got)
	}
	// Re-quarantine clears it.
	if _, err := admin.ApproveNode(adminWSCtx(), &genezav1.ApproveNodeRequest{Node: pending.ID, Approve: false}); err != nil {
		t.Fatal(err)
	}
	if got, _ = srv.store.GetNode(defaultWorkspace, pending.ID); got.Approved {
		t.Fatal("deny should clear Approved")
	}

	// --auto-approve token: approved on enroll, provenance = auto:<provider>.
	auto := enrollWith(true)
	if !auto.Approved || auto.ApprovedBy != "auto:token" {
		t.Fatalf("auto-approve enroll: %+v", auto)
	}

	// Unknown node id -> NotFound.
	if _, err := admin.ApproveNode(adminWSCtx(), &genezav1.ApproveNodeRequest{Node: "n-doesnotexist", Approve: true}); status.Code(err) != codes.NotFound {
		t.Fatalf("approve unknown: want NotFound, got %v", err)
	}
}

// TestCrossWorkspaceIsolation is the flagship multi-tenancy property: a node in
// workspace B is structurally invisible to a workspace-A-scoped caller (NotFound,
// not "denied"), the broker refuses to reach it, and the node->workspace index
// (the unauthenticated update path) resolves correctly.
func TestCrossWorkspaceIsolation(t *testing.T) {
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if err := srv.ensureWorkspace("wsb", "B", defaultOverlayCIDR); err != nil {
		t.Fatal(err)
	}
	enroll := &enrollmentService{s: srv}
	enrollInto := func(ws, name string) *NodeRecord {
		t.Helper()
		tok, _ := types.NewToken()
		if err := srv.store.PutToken(tok, &TokenRecord{
			WorkspaceID: ws, ExpiresUnix: time.Now().Add(time.Hour).Unix(), MaxUses: 1, AutoApprove: true,
		}); err != nil {
			t.Fatal(err)
		}
		key, _ := ca.GenerateKey()
		csr, _ := ca.MakeCSR(key, "node")
		resp, err := enroll.Enroll(context.Background(), &genezav1.EnrollRequest{
			Provider: "token", Token: tok, CsrPem: csr, NoiseStaticPub: make([]byte, 32),
			Platform: &genezav1.PlatformInfo{Hostname: name},
		})
		if err != nil {
			t.Fatalf("enroll %s/%s: %v", ws, name, err)
		}
		n, _ := srv.store.GetNode(ws, resp.NodeId)
		return n
	}

	nA := enrollInto(defaultWorkspace, "alpha")
	nB := enrollInto("wsb", "bravo")

	// INV-CP2: a wsB node is invisible to a wsA-scoped read, and vice versa.
	if _, err := srv.store.GetNode(defaultWorkspace, nB.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wsA GetNode(nB) = %v, want ErrNotFound", err)
	}
	if _, err := srv.store.FindNode(defaultWorkspace, "bravo"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wsA FindNode(bravo) = %v, want ErrNotFound", err)
	}
	if got, _ := srv.store.ListNodes(defaultWorkspace); len(got) != 1 || got[0].ID != nA.ID {
		t.Fatalf("wsA ListNodes = %v, want only nA", got)
	}
	if got, _ := srv.store.ListNodes("wsb"); len(got) != 1 || got[0].ID != nB.ID {
		t.Fatalf("wsB ListNodes = %v, want only nB", got)
	}

	// INV-CP1 (unauth update path): the index resolves each node's workspace.
	if ws, _ := srv.store.WorkspaceForNode(nB.ID); ws != "wsb" {
		t.Fatalf("WorkspaceForNode(nB) = %q, want wsb", ws)
	}

	// INV-CP3: a wsA user cannot broker to nB (NotFound, structurally).
	identA := &ca.Identity{Kind: ca.KindUser, Workspace: defaultWorkspace, Name: "alice", Roles: []string{"ops"}}
	_, berr := srv.broker.CreateSession(context.Background(), identA, &genezav1.CreateSessionRequest{
		Node: nB.ID, Action: "shell", WantPty: true, ClientNoisePub: make([]byte, 32), ClientPath: "native",
	})
	if status.Code(berr) != codes.NotFound {
		t.Fatalf("wsA broker to nB = %v, want NotFound", berr)
	}
	// (Cross-tenant DNS isolation is now structural: networkDNS projects only
	// ListNodes(ws) into a node's pushed zone, and FindNode above already proves a
	// wsB node is invisible to a wsA read. DNS is resolved locally from the pushed
	// per-Network zone — no controller resolver to leak across tenants.)
}

// TestWorkspaceMembershipLogin proves the Phase-2 config-driven membership
// gate: a user lands in exactly the workspaces they belong to (open OR matched),
// an ambiguous login returns candidates (no cert), an explicit pick mints a cert
// scoped to that workspace, and a non-member workspace is refused.
func TestWorkspaceMembershipLogin(t *testing.T) {
	cfg := testServerConfig(t)
	// default (synthesized, open) + prod (group "admins") + secret (only "bob").
	// alice carries group "admins", so she is a member of {default, prod} but not
	// secret. All three share the one test policy file (binds ops→group admins).
	cfg.Workspaces = append(cfg.Workspaces,
		WorkspaceConfig{ID: "prod", PolicyFile: cfg.PolicyFile, OverlayCIDR: defaultOverlayCIDR, MemberGroups: []string{"admins"}},
		WorkspaceConfig{ID: "secret", PolicyFile: cfg.PolicyFile, OverlayCIDR: defaultOverlayCIDR, Members: []string{"bob"}},
	)
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	if err := InitDataDir(cfg); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// workspacesForUserStore: alice ∈ {default, prod}, never secret.
	cands := srv.workspacesForUserStore(providerLocal, "alice", "alice", []string{"admins"})
	if !contains(cands, "default") || !contains(cands, "prod") || contains(cands, "secret") {
		t.Fatalf("workspacesForUserStore(alice) = %v, want {default, prod}", cands)
	}

	// No workspace + ambiguous membership -> ambiguous (the SPA must pick).
	if ws, ambiguous, ok := resolveLoginWorkspace("", cands); ok || !ambiguous || ws != "" {
		t.Fatalf("ambiguous resolution: ws=%q ambiguous=%v ok=%v", ws, ambiguous, ok)
	}

	// Explicit member pick -> resolved; issuing a cert scopes it to that workspace.
	ws, ambiguous, ok := resolveLoginWorkspace("prod", cands)
	if !ok || ambiguous || ws != "prod" {
		t.Fatalf("pick prod: ws=%q ambiguous=%v ok=%v", ws, ambiguous, ok)
	}
	key, _ := ca.GenerateKey()
	csr, _ := ca.MakeCSR(key, "alice")
	roles := srv.rolesForMember(ws, providerLocal, "alice", "alice", []string{"admins"})
	certPEM, _, err := srv.issueUserCert("device:"+providerLocal, "alice", "alice", ws, roles, csr, time.Hour)
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	blk, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(blk.Bytes)
	id, err := ca.PeerIdentity(leaf)
	if err != nil || id.Workspace != "prod" {
		t.Fatalf("issued cert workspace = %q (err %v), want prod", id.Workspace, err)
	}

	// A workspace she is not a member of is refused by the resolver.
	if _, _, ok := resolveLoginWorkspace("secret", cands); ok {
		t.Fatal("login to non-member workspace 'secret' must be refused")
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
