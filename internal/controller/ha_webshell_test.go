package controller

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"geneza.io/internal/ca"
	"geneza.io/internal/enrollcode"
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

// The console node list must judge liveness CLUSTER-WIDE, not from the local
// registry. An agent holds its control stream to exactly one controller, so a
// local-only check reported every agent homed on a sibling as offline: with
// several controllers behind one name the SAME node flipped between online and
// offline depending on which replica answered the request.
//
// The web-shell pre-flight shared that check, so it rejected shells with "node
// is offline" before brokerWebSession could follow the ControllerRedirect —
// silently defeating the redirect for (N-1)/N of requests.
func TestNodeSummariesJudgeLivenessClusterWide(t *testing.T) {
	srv, api, fake := buildLaunchServer(t, EmbedConfig{})
	fake.session = &fakeSession{caller: keystoneCaller("alice", "proj-a")}
	_, _ = mintLaunch(t, api.handler(), `{"token":"gAAAA-alice","instance_id":"i-1"}`)
	ws := launchWorkspace(t, srv, "proj-a")
	seedLaunchNode(t, srv, ws, "n-1", "i-1", "proj-a", nil)

	online := func() bool {
		t.Helper()
		sums, err := srv.nodeSummaries(ws)
		if err != nil {
			t.Fatalf("nodeSummaries: %v", err)
		}
		for _, s := range sums {
			if s.GetNodeId() == "n-1" {
				return s.GetOnline()
			}
		}
		t.Fatalf("node n-1 missing from summaries")
		return false
	}

	if srv.registry.Online("n-1") {
		t.Fatalf("precondition: node must not be locally homed")
	}
	if online() {
		t.Fatalf("no presence row anywhere => must read offline")
	}

	// A peer controller stamps the shared row on every heartbeat.
	if err := srv.store.PutAgentPresence(&AgentPresenceRecord{
		NodeID: "n-1", Healthy: true, LastSeenUnix: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if !online() {
		t.Fatalf("peer-homed agent with a fresh heartbeat must read ONLINE " +
			"(this is the regression: the console showed it offline)")
	}

	// Freshness still governs — a stale row is not liveness.
	if err := srv.store.PutAgentPresence(&AgentPresenceRecord{
		NodeID: "n-1", Healthy: true,
		LastSeenUnix: time.Now().Add(-2 * canaryHeartbeatFresh).Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if online() {
		t.Fatalf("a stale presence row must age back out to offline")
	}
}

// The console's token mint must hand back something install.sh will ACCEPT.
// It returned only the raw gz- token, which install.sh rejects with "unknown
// argument" — the encoded gzk_ code was reachable only through the CLI, so a
// console-only operator had no way to discover the right shape from the error.
func TestMintTokenReturnsAUsableEnrollCode(t *testing.T) {
	srv, api, _ := buildLaunchServer(t, EmbedConfig{})
	// A test binary embeds no release root, and skipping on that would make this
	// test silently vacuous — the pin is the whole point. Give it one.
	rootPub := filepath.Join(t.TempDir(), "root.pub")
	if err := os.WriteFile(rootPub, []byte(
		"-----BEGIN PUBLIC KEY-----\n"+
			"MCowBQYDK2VwAyEALaKgDFdpt/6Ka0BZkCY7qCa6TKUPNhS7CSEMUpQnXtw=\n"+
			"-----END PUBLIC KEY-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv.cfg.RootPubkeyFile = rootPub
	if srv.rootFingerprint() == "" {
		t.Fatalf("precondition: the server must now serve a root fingerprint")
	}
	// A fingerprint alone does not mean this controller serves /install.sh — the
	// one-liner is gated on install_dir too, so set it for the happy path.
	srv.cfg.InstallDir = t.TempDir()
	tok := mintConsoleSession(t, srv, defaultWorkspace, "admin", roleWSAdmin)

	r := httptest.NewRequest("POST", "/api/v1/tokens", strings.NewReader(`{"ttlSeconds":3600,"maxUses":1}`))
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("mint: %d %s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	raw, _ := body["token"].(string)
	if raw == "" {
		t.Fatalf("no token in response: %v", body)
	}
	code, _ := body["enrollCode"].(string)
	if !strings.HasPrefix(code, "gzk_") {
		t.Fatalf("enrollCode must be the encoded form install.sh takes, got %q", code)
	}
	cmd, _ := body["installCommand"].(string)
	if !strings.Contains(cmd, "install.sh") || !strings.Contains(cmd, code) {
		t.Fatalf("installCommand must be runnable and carry the code, got %q", cmd)
	}

	// It must decode back to THIS token plus the pinned root, or a node would
	// enrol against a root nobody verified.
	f, ok := enrollcode.Decode(code)
	if !ok {
		t.Fatalf("enrollCode does not decode: %q", code)
	}
	if f.Token != raw {
		t.Fatalf("code carries token %q, want %q", f.Token, raw)
	}
	if f.RootFP != srv.rootFingerprint() {
		t.Fatalf("code carries root fp %q, want %q", f.RootFP, srv.rootFingerprint())
	}
}

// rootFingerprint() is non-empty for every release build (it falls back to the
// compiled-in root), so it does NOT imply this controller serves an installer.
// With install_dir unset, /install.sh 404s — and behind a catch-all SPA route it
// answers with index.html and HTTP 200, i.e. HTML piped into `sudo sh`. The mint
// must therefore withhold the one-liner and hand back the code alone.
func TestMintTokenOmitsInstallCommandWithoutAnInstaller(t *testing.T) {
	srv, api, _ := buildLaunchServer(t, EmbedConfig{})
	rootPub := filepath.Join(t.TempDir(), "root.pub")
	if err := os.WriteFile(rootPub, []byte(
		"-----BEGIN PUBLIC KEY-----\n"+
			"MCowBQYDK2VwAyEALaKgDFdpt/6Ka0BZkCY7qCa6TKUPNhS7CSEMUpQnXtw=\n"+
			"-----END PUBLIC KEY-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv.cfg.RootPubkeyFile = rootPub
	srv.cfg.InstallDir = ""
	tok := mintConsoleSession(t, srv, defaultWorkspace, "admin", roleWSAdmin)

	r := httptest.NewRequest("POST", "/api/v1/tokens", strings.NewReader(`{"ttlSeconds":3600,"maxUses":1}`))
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("mint: %d %s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if cmd, ok := body["installCommand"]; ok {
		t.Fatalf("installCommand must be withheld when install_dir is unset, got %q", cmd)
	}
	if code, _ := body["enrollCode"].(string); !strings.HasPrefix(code, "gzk_") {
		t.Fatalf("the code itself must still be returned, got %q", code)
	}
}

// An unset console.external_url used to render "curl -fsSL /install.sh | sudo sh",
// a relative URL that cannot work. Fall back to the controller's own runtime base
// like `geneza node enroll` does, and never emit a host-less command.
func TestMintTokenNeverEmitsAHostlessInstallCommand(t *testing.T) {
	srv, api, _ := buildLaunchServer(t, EmbedConfig{})
	rootPub := filepath.Join(t.TempDir(), "root.pub")
	if err := os.WriteFile(rootPub, []byte(
		"-----BEGIN PUBLIC KEY-----\n"+
			"MCowBQYDK2VwAyEALaKgDFdpt/6Ka0BZkCY7qCa6TKUPNhS7CSEMUpQnXtw=\n"+
			"-----END PUBLIC KEY-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv.cfg.RootPubkeyFile = rootPub
	srv.cfg.InstallDir = t.TempDir()
	srv.cfg.Console.ExternalURL = ""
	tok := mintConsoleSession(t, srv, defaultWorkspace, "admin", roleWSAdmin)

	r := httptest.NewRequest("POST", "/api/v1/tokens", strings.NewReader(`{"ttlSeconds":3600,"maxUses":1}`))
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handler().ServeHTTP(w, r)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if cmd, _ := body["installCommand"].(string); strings.Contains(cmd, " /install.sh") {
		t.Fatalf("install command must carry a host, got %q", cmd)
	}
}

// The web-shell proxy may only rewrite the relay target to loopback when the
// relay is actually on this host. It used to do so unconditionally, which is
// fine on a single box and fatal everywhere else: with a separate relay layer
// (deploy/openstack, or any multi-region fleet) every web shell died on
//
//	tunnel: relay connect 127.0.0.1:7403: connect: connection refused
//
// which reads as "the relay is down" rather than "the controller dialled its own
// loopback instead of the relay".
func TestLocalRelayOverrideOnlyWhenColocated(t *testing.T) {
	for _, tc := range []struct {
		name     string
		relay    string
		dnsNames []string
		ips      []string
		want     string
	}{
		{"separate host by ip", "57.130.73.101:7403", []string{"gw1.example.com"}, []string{"57.130.64.9"}, ""},
		{"separate host by name", "relay1.example.com:7403", []string{"gw1.example.com"}, nil, ""},
		{"colocated by advertised name", "gw1.example.com:7403", []string{"gw1.example.com"}, nil, "127.0.0.1:7403"},
		{"colocated by advertised ip", "57.130.64.9:7403", nil, []string{"57.130.64.9"}, "127.0.0.1:7403"},
		{"already loopback", "127.0.0.1:7403", []string{"gw1.example.com"}, nil, "127.0.0.1:7403"},
		{"localhost", "localhost:7403", []string{"gw1.example.com"}, nil, "127.0.0.1:7403"},
		{"no relay configured", "", nil, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Advertise: Advertise{DNSNames: tc.dnsNames, IPs: tc.ips}}
			if tc.relay != "" {
				cfg.RelayAddrs = []string{tc.relay}
			}
			got := (&Server{cfg: cfg}).localRelayAddr()
			if got != tc.want {
				t.Fatalf("relay=%q advertise=%v/%v: got %q, want %q",
					tc.relay, tc.dnsNames, tc.ips, got, tc.want)
			}
		})
	}
}

// The console hands out `curl -fsSL <console-origin>/install.sh | sudo sh`, so the
// console listener must actually serve the installer. It used to fall through to
// the SPA catch-all, which answers ANY unknown path with index.html and HTTP 200 —
// so the one-liner piped HTML into `sudo sh` and every status-code check read
// healthy. Serve the real script, and 404 (never 200) when no installer is set up.
func TestConsoleListenerServesTheInstaller(t *testing.T) {
	srv, api, _ := buildLaunchServer(t, EmbedConfig{})
	h := api.handler()

	// With no install_dir the console must NOT answer 200 with the SPA.
	srv.cfg.InstallDir = ""
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/install.sh", nil))
	if w.Code == 200 {
		t.Fatalf("console served 200 for /install.sh with no installer — that is the SPA, i.e. HTML into sudo sh")
	}

	// With one configured it must serve the script itself, not the SPA.
	srv.cfg.InstallDir = t.TempDir()
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/install.sh", nil))
	if w.Code != 200 {
		t.Fatalf("install.sh: %d %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "shellscript") {
		t.Fatalf("content-type %q — the SPA would say text/html", ct)
	}
	if body := w.Body.String(); !strings.HasPrefix(body, "#!") {
		t.Fatalf("body is not a shell script: %.60q", body)
	}
}
