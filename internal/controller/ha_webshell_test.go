package controller

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"geneza.io/internal/ca"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

// HA cross-controller web shell. Controllers are leaderless, but only the one
// holding an agent's control stream can push it a session offer — so a web shell
// opened against a non-owner controller must re-broker at the owner, exactly as
// the native CLI does. Before this existed the redirect fell through to
// DialSession and every such shell died with "controller returned no relay floor
// for this session" — an (N-1)/N failure rate under HA.
//
// The fake owner below is a real mTLS gRPC WorkspaceAPI server sharing this
// controller's CA, so the hop is exercised end to end: cert minting, TLS, the
// identity the owner actually observes.

// fakeOwner is a stand-in owning controller. It records the verified peer
// identity of whoever calls CreateSession and answers with a canned success.
type fakeOwner struct {
	genezav1.UnimplementedWorkspaceAPIServer
	mu    sync.Mutex
	seen  *ca.Identity
	calls int
}

func (f *fakeOwner) CreateSession(ctx context.Context, req *genezav1.CreateSessionRequest) (*genezav1.CreateSessionResponse, error) {
	// Mirror the real server: identity comes from the VERIFIED client cert.
	id, _, _ := identityFrom(ctx)
	f.mu.Lock()
	f.seen, f.calls = id, f.calls+1
	f.mu.Unlock()
	return &genezav1.CreateSessionResponse{
		SessionId: "s-owner", RelayAddr: "relay.example:7403",
		RelayFloor: []string{"relay.example:7403"}, RelayToken: "tok",
	}, nil
}

// startFakeOwner serves the stub over mTLS on loopback using srv's CA, and
// returns its address. The auth interceptor is the real one, so the identity the
// stub sees is derived the same way a live controller derives it.
func startFakeOwner(t *testing.T, srv *Server) (*fakeOwner, string) {
	t.Helper()
	certPEM, keyPEM, err := srv.ca.IssueServerKeypair(ca.Profile{
		Kind: ca.KindController, Name: "gw2", TTL: time.Hour,
		DNSNames: []string{"localhost"}, IPs: []net.IP{net.ParseIP("127.0.0.1")},
	})
	if err != nil {
		t.Fatalf("issue owner server cert: %v", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := ca.PoolFromPEM(srv.ca.RootsPEM)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	owner := &fakeOwner{}
	gs := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{pair},
			ClientCAs:    pool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS12,
		})),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			if pi := extractPeer(ctx); pi != nil {
				ctx = context.WithValue(ctx, peerInfoKey{}, pi)
			}
			return h(ctx, req)
		}),
	)
	genezav1.RegisterWorkspaceAPIServer(gs, owner)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	_, port, _ := net.SplitHostPort(lis.Addr().String())
	return owner, net.JoinHostPort("localhost", port)
}

// A web shell for a node owned by ANOTHER controller re-brokers at the owner,
// and the owner sees the console user's identity carrying the web path pin.
func TestWebShellFollowsCrossControllerRedirect(t *testing.T) {
	srv, api, _ := buildLaunchServer(t, EmbedConfig{})
	owner, addr := startFakeOwner(t, srv)

	seedLaunchNode(t, srv, defaultWorkspace, "n-remote", "i-remote", "proj-a", nil)
	// The node is homed on gw2, and gw2 is in the signed cluster set at its OWN
	// address — which is why per-controller advertised addresses matter: an LB
	// address here would route the redirect back to this controller.
	if _, err := srv.store.ClaimAgentAffinity("n-remote", "gw2", time.Now()); err != nil {
		t.Fatalf("claim affinity: %v", err)
	}
	srv.broker.clusterControllers = func() []types.ControllerEndpoint {
		return []types.ControllerEndpoint{{ControllerID: "gw2", Addrs: []string{addr}}}
	}

	u := &consoleUser{
		Name: "alice", Provider: providerKeystone, Subject: "ks-alice",
		Workspace: defaultWorkspace, Roles: []string{roleWSAdmin},
	}
	resp, closeConn, err := api.brokerWebSession(context.Background(), u, &genezav1.CreateSessionRequest{
		Node: "n-remote", Action: types.ActionShell, WantPty: true,
		ClientNoisePub: make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("cross-controller broker: %v", err)
	}
	if closeConn != nil {
		defer func() { _ = closeConn() }()
	}

	// The redirect was followed, not passed through.
	if resp.GetControllerRedirect() != nil {
		t.Fatalf("a redirect must be followed, not returned to the caller")
	}
	if resp.GetRelayToken() == "" || len(relayFloorOf(resp)) == 0 {
		t.Fatalf("re-brokered response carries no relay floor — this is the exact shape that used to fail with %q",
			"controller returned no relay floor for this session")
	}
	owner.mu.Lock()
	seen, calls := owner.seen, owner.calls
	owner.mu.Unlock()
	if calls != 1 {
		t.Fatalf("owner CreateSession calls = %d, want 1", calls)
	}
	if seen == nil {
		t.Fatalf("owner saw no verified identity")
	}
	// The owner authorizes the HUMAN, not the controller — so audit and policy
	// both name alice.
	if seen.Kind != ca.KindUser || seen.Name != "alice" || seen.Subject != "ks-alice" {
		t.Fatalf("owner saw the wrong principal: %+v", seen)
	}
	if seen.Workspace != defaultWorkspace {
		t.Fatalf("owner saw workspace %q", seen.Workspace)
	}
	// The load-bearing bit: without this pin the owner brokers the session as
	// NATIVE (the path is server-decided, never taken from req.client_path), and
	// a require_native rule would be bypassed by the web shell under HA.
	if seen.ClientPath != types.PathWeb {
		t.Fatalf("owner must observe the web path pin, got %q — require_native would be bypassed", seen.ClientPath)
	}
}

// relayFloorOf mirrors the client's floor accessor for the assertion above.
func relayFloorOf(resp *genezav1.CreateSessionResponse) []string {
	if f := resp.GetRelayFloor(); len(f) > 0 {
		return f
	}
	if a := resp.GetRelayAddr(); a != "" {
		return []string{a}
	}
	return nil
}

// A node owned by THIS controller must not take the redirect path at all.
func TestWebShellLocalNodeDoesNotRedirect(t *testing.T) {
	srv, api, _ := buildLaunchServer(t, EmbedConfig{})
	owner, addr := startFakeOwner(t, srv)
	seedLaunchNode(t, srv, defaultWorkspace, "n-local", "i-local", "proj-a", nil)
	srv.broker.clusterControllers = func() []types.ControllerEndpoint {
		return []types.ControllerEndpoint{{ControllerID: "gw2", Addrs: []string{addr}}}
	}
	// No affinity row => this controller owns it (or it is simply offline here).
	_, _, err := api.brokerWebSession(context.Background(), testConsoleUser(), &genezav1.CreateSessionRequest{
		Node: "n-local", Action: types.ActionShell, WantPty: true,
	})
	// The agent is not actually online in this harness, so the broker denies it
	// locally — the point is that it never reached the fake owner.
	if err == nil {
		t.Fatalf("expected a local broker error for an offline node")
	}
	owner.mu.Lock()
	calls := owner.calls
	owner.mu.Unlock()
	if calls != 0 {
		t.Fatalf("a locally-owned node must not be re-brokered elsewhere (owner saw %d calls)", calls)
	}
}

// Liveness must be cluster-wide: an agent homed on a peer controller is absent
// from THIS controller's in-memory registry, and reporting it offline would grey
// out a Console button that works.
func TestLaunchMintReportsOnlineForPeerHomedAgent(t *testing.T) {
	srv, api, fake := buildLaunchServer(t, EmbedConfig{})
	h := api.handler()
	fake.session = &fakeSession{caller: keystoneCaller("alice", "proj-a")}
	_, _ = mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	ws := launchWorkspace(t, srv, "proj-a")
	seedLaunchNode(t, srv, ws, "n-1", "i-1", "proj-a", nil)

	// Not in the local registry (this controller does not hold its stream).
	if srv.registry.Online("n-1") {
		t.Fatalf("precondition: node must not be locally homed")
	}
	if srv.nodeOnlineAnywhere("n-1") {
		t.Fatalf("with no presence row the node must read offline")
	}
	code, resp := mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	if code != 200 {
		t.Fatalf("mint: %d %v", code, resp)
	}
	if resp["online"] != false {
		t.Fatalf("no presence row => online must be false, got %v", resp["online"])
	}

	// A fresh presence row written by a PEER controller must flip it to online.
	if err := srv.store.PutAgentPresence(&AgentPresenceRecord{
		NodeID: "n-1", Healthy: true, LastSeenUnix: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if !srv.nodeOnlineAnywhere("n-1") {
		t.Fatalf("a peer-homed agent with a fresh heartbeat must read online")
	}
	code, resp = mintLaunch(t, h, `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	if code != 200 {
		t.Fatalf("mint: %d %v", code, resp)
	}
	if resp["online"] != true {
		t.Fatalf("peer-homed live node must be reported online, got %v", resp["online"])
	}

	// A stale row is not liveness — it must age back out.
	if err := srv.store.PutAgentPresence(&AgentPresenceRecord{
		NodeID: "n-1", Healthy: true,
		LastSeenUnix: time.Now().Add(-2 * canaryHeartbeatFresh).Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if srv.nodeOnlineAnywhere("n-1") {
		t.Fatalf("a stale presence row must not count as online")
	}
}

func testConsoleUser() *consoleUser {
	return &consoleUser{
		Name: "alice", Provider: providerKeystone, Subject: "ks-alice",
		Workspace: defaultWorkspace, Roles: []string{roleWSAdmin},
	}
}
