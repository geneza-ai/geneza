package controller

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"geneza.io/internal/ca"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/policy"
	"geneza.io/internal/types"
)

type fakeAgents struct {
	online   map[string]bool
	accepted bool
	reason   string
	err      error
	services map[string][]types.Service

	lastNode      string
	lastGrant     []byte
	lastAgentTurn *genezav1.TurnCreds
}

func (f *fakeAgents) Online(nodeID string) bool { return f.online[nodeID] }

func (f *fakeAgents) Services(nodeID string) ([]types.Service, bool) {
	s, ok := f.services[nodeID]
	return s, ok
}

func (f *fakeAgents) SendOffer(_ context.Context, nodeID, sessionID string, grant []byte, turn *genezav1.TurnCreds, _ time.Duration) (bool, string, error) {
	f.lastNode = nodeID
	f.lastGrant = grant
	f.lastAgentTurn = turn
	return f.accepted, f.reason, f.err
}

// fakeP2P records whether the broker set up the ICE path for a session.
type fakeP2P struct{ setupCalls int }

func (f *fakeP2P) setupSession(string, string, string, string, string, string) (clientTurn, agentTurn *genezav1.TurnCreds) {
	f.setupCalls++
	return &genezav1.TurnCreds{Controlling: true}, &genezav1.TurnCreds{Controlling: false}
}
func (f *fakeP2P) teardownSession(string)         {}
func (f *fakeP2P) armInitialLease(*SessionRecord) {}
func (f *fakeP2P) selectRelayCandidates(string, string, string) []types.RelayCandidate {
	return nil
}

const testPolicyDoc = `
roles:
  ops:
    allow:
      - actions: ["shell", "exec"]
        node_labels: {env: prod}
        max_session_ttl: 4h
      - service_kinds: ["subnet-route", "exit-node"]
        node_labels: {env: prod}
  watcher:
    allow:
      - actions: ["shell"]
        node_labels: {"*": "*"}
        allow_detach: false
  natonly:
    allow:
      - actions: ["shell"]
        node_labels: {"*": "*"}
        require_native: true
bindings:
  - role: natonly
    users: [nina]
  - role: ops
    users: [alice]
  - role: watcher
    users: [walter]
  - role: ops
    groups: [admins]
`

func testBroker(t *testing.T) (*Broker, *fakeAgents, Store, ed25519.PublicKey) {
	t.Helper()
	store := testStore(t)
	audit, err := openAudit(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.Close() })
	engine, err := policy.Parse([]byte(testPolicyDoc))
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, keyID, err := types.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	agents := &fakeAgents{online: map[string]bool{"n-aaaaaaaaaaaa": true}, accepted: true}
	ov := newOverlayAllocator()
	b := NewBroker(store, audit, agents,
		func(string) policy.Engine { return engine },
		func(string) *overlayAllocator { return ov },
		priv, keyID, []string{"10.70.70.10:7403"}, 2*time.Minute, 12*time.Hour)

	noise := make([]byte, 32)
	for i := range noise {
		noise[i] = 0xA0
	}
	if err := store.PutNode(defaultWorkspace, &NodeRecord{
		ID: "n-aaaaaaaaaaaa", Name: "web1",
		Labels:   map[string]string{"env": "prod"},
		NoisePub: noise,
		Approved: true, // admission gate is exercised separately (TestBrokerPendingNodeDenied)
	}); err != nil {
		t.Fatal(err)
	}
	return b, agents, store, pub
}

func clientNoise() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = 0xC1
	}
	return b
}

// A web session must NOT be offered ICE: the in-process web-shell proxy only uses
// the relay-TCP floor, so if the agent were handed TURN creds it would wait out its
// full ICE gather window for candidates the proxy never sends — a ~15s stall before
// the first prompt. A native session still gets ICE.
func TestBrokerWebSessionSkipsICE(t *testing.T) {
	b, agents, _, _ := testBroker(t)
	p2p := &fakeP2P{}
	b.SetSessionP2P(p2p)
	ident := &ca.Identity{Kind: ca.KindUser, Workspace: defaultWorkspace, Name: "alice", Roles: []string{"ops"}}
	req := func() *genezav1.CreateSessionRequest {
		return &genezav1.CreateSessionRequest{Node: "web1", Action: "shell", WantPty: true, ClientNoisePub: clientNoise()}
	}

	// Native: ICE offered — setupSession runs and the agent's offer carries TURN creds.
	if _, err := b.CreateSession(context.Background(), ident, req()); err != nil {
		t.Fatalf("native broker: %v", err)
	}
	if p2p.setupCalls != 1 || agents.lastAgentTurn == nil {
		t.Fatalf("native session must be offered ICE: setupCalls=%d agentTurn=%v", p2p.setupCalls, agents.lastAgentTurn)
	}

	// Web: ICE NOT offered — setupSession is skipped and the offer carries nil creds,
	// so the agent goes straight to the relay floor.
	agents.lastAgentTurn = &genezav1.TurnCreds{} // poison; the web offer must overwrite it with nil
	if _, err := b.CreateSessionWeb(context.Background(), ident, req()); err != nil {
		t.Fatalf("web broker: %v", err)
	}
	if p2p.setupCalls != 1 {
		t.Fatalf("web session must NOT set up ICE: setupCalls=%d (want 1)", p2p.setupCalls)
	}
	if agents.lastAgentTurn != nil {
		t.Fatalf("web session offer must carry nil agent TURN creds, got %+v", agents.lastAgentTurn)
	}
}

func TestBrokerPendingNodeDenied(t *testing.T) {
	b, _, store, _ := testBroker(t)
	// Quarantine the node (simulate a freshly-enrolled, not-yet-approved machine).
	if _, err := store.SetNodeApproval(defaultWorkspace, "n-aaaaaaaaaaaa", false, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	ident := &ca.Identity{Kind: ca.KindUser, Workspace: defaultWorkspace, Name: "alice", Roles: []string{"ops"}}
	req := &genezav1.CreateSessionRequest{
		Node: "web1", Action: "shell", WantPty: true,
		ClientNoisePub: clientNoise(), ClientPath: "native",
	}
	_, err := b.CreateSession(context.Background(), ident, req)
	if err == nil {
		t.Fatal("expected pending-approval denial, got success")
	}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", got)
	}
	// After approval the same request succeeds.
	if _, err := store.SetNodeApproval(defaultWorkspace, "n-aaaaaaaaaaaa", true, "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.CreateSession(context.Background(), ident, req); err != nil {
		t.Fatalf("after approval: %v", err)
	}
}

func TestBrokerGrantConstruction(t *testing.T) {
	b, agents, store, pub := testBroker(t)
	ident := &ca.Identity{Kind: ca.KindUser, Workspace: defaultWorkspace, Name: "alice", Roles: []string{"ops"}}
	resp, err := b.CreateSession(context.Background(), ident, &genezav1.CreateSessionRequest{
		Node:           "web1",
		Action:         "shell",
		WantPty:        true,
		ClientNoisePub: clientNoise(),
		ClientPath:     "native",
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if agents.lastNode != "n-aaaaaaaaaaaa" {
		t.Fatalf("offer went to %q", agents.lastNode)
	}
	signed, err := types.DecodeSigned(resp.SignedGrant)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := types.VerifyGrant(map[string]ed25519.PublicKey{types.KeyIDFor(pub): pub}, signed)
	if err != nil {
		t.Fatalf("grant does not verify: %v", err)
	}
	if grant.User != "alice" || grant.NodeID != "n-aaaaaaaaaaaa" || grant.Action != "shell" {
		t.Fatalf("grant fields wrong: %+v", grant)
	}
	if grant.RelayAddr != "10.70.70.10:7403" || resp.RelayAddr != grant.RelayAddr {
		t.Fatalf("relay addr wrong: %q / %q", grant.RelayAddr, resp.RelayAddr)
	}
	// With no live-fleet hook the floor falls back to the static relay_addrs config,
	// and RelayFloor carries that same set with RelayAddr as its first entry.
	if len(grant.RelayFloor) != 1 || grant.RelayFloor[0] != grant.RelayAddr {
		t.Fatalf("relay floor = %+v, want [%q]", grant.RelayFloor, grant.RelayAddr)
	}
	if len(resp.RelayFloor) != 1 || resp.RelayFloor[0] != resp.RelayAddr {
		t.Fatalf("resp relay floor = %+v, want [%q]", resp.RelayFloor, resp.RelayAddr)
	}
	if grant.RelayToken == "" || grant.RelayToken != resp.RelayToken {
		t.Fatalf("relay token mismatch")
	}
	if !grant.AllowPTY || grant.AllowDetach {
		t.Fatalf("pty/detach flags wrong: %+v", grant)
	}
	// Policy caps TTL at 4h, below the 12h default.
	if grant.MaxSessionTTL != 4*time.Hour {
		t.Fatalf("max session ttl = %s, want 4h", grant.MaxSessionTTL)
	}
	if got := grant.ExpiresAt.Sub(grant.IssuedAt); got != 2*time.Minute {
		t.Fatalf("grant window = %s, want 2m", got)
	}
	// Agent-side validation must accept what we signed.
	if err := grant.Validate("n-aaaaaaaaaaaa", grant.AgentNoisePub, time.Now()); err != nil {
		t.Fatalf("agent-side validate: %v", err)
	}
	// Session record persisted as pending.
	rec, err := store.GetSession(defaultWorkspace, resp.SessionId)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != SessionPending || rec.User != "alice" {
		t.Fatalf("session record: %+v", rec)
	}
}

func TestBrokerVPNGrant(t *testing.T) {
	b, agents, store, pub := testBroker(t)
	agents.services = map[string][]types.Service{
		"n-aaaaaaaaaaaa": {
			{Name: "lan", Kind: types.KindSubnet, NodeID: "n-aaaaaaaaaaaa", Addr: "192.168.99.0/24"},
			{Name: "exit", Kind: types.KindExitNode, NodeID: "n-aaaaaaaaaaaa"},
		},
	}
	ident := &ca.Identity{Kind: ca.KindUser, Workspace: defaultWorkspace, Name: "alice", Roles: []string{"ops"}}

	// Subnet route: action derived to vpn, route = service addr, overlay ip set.
	resp, err := b.CreateSession(context.Background(), ident, &genezav1.CreateSessionRequest{
		Node:           "web1",
		Action:         types.ActionVPN,
		Service:        "lan",
		ClientNoisePub: clientNoise(),
	})
	if err != nil {
		t.Fatalf("vpn CreateSession: %v", err)
	}
	signed, err := types.DecodeSigned(resp.SignedGrant)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := types.VerifyGrant(map[string]ed25519.PublicKey{types.KeyIDFor(pub): pub}, signed)
	if err != nil {
		t.Fatalf("vpn grant does not verify: %v", err)
	}
	if grant.Action != types.ActionVPN {
		t.Fatalf("action = %q, want vpn", grant.Action)
	}
	if len(grant.Routes) != 1 || grant.Routes[0] != "192.168.99.0/24" {
		t.Fatalf("routes = %v, want [192.168.99.0/24]", grant.Routes)
	}
	if grant.OverlayIP == "" {
		t.Fatal("vpn grant has no overlay ip")
	}
	if grant.Record {
		t.Fatal("vpn grant must not be recordable (no PTY)")
	}
	if err := grant.Validate("n-aaaaaaaaaaaa", grant.AgentNoisePub, time.Now()); err != nil {
		t.Fatalf("agent-side validate: %v", err)
	}
	rec, err := store.GetSession(defaultWorkspace, resp.SessionId)
	if err != nil {
		t.Fatal(err)
	}
	if rec.OverlayIP != grant.OverlayIP {
		t.Fatalf("session record overlay ip %q != grant %q", rec.OverlayIP, grant.OverlayIP)
	}

	// Exit node: route becomes the default route.
	resp2, err := b.CreateSession(context.Background(), ident, &genezav1.CreateSessionRequest{
		Node:           "web1",
		Action:         types.ActionVPN,
		Service:        "exit",
		ClientNoisePub: clientNoise(),
	})
	if err != nil {
		t.Fatalf("exit-node CreateSession: %v", err)
	}
	signed2, _ := types.DecodeSigned(resp2.SignedGrant)
	grant2, err := types.VerifyGrant(map[string]ed25519.PublicKey{types.KeyIDFor(pub): pub}, signed2)
	if err != nil {
		t.Fatalf("exit grant does not verify: %v", err)
	}
	if len(grant2.Routes) != 1 || grant2.Routes[0] != "0.0.0.0/0" {
		t.Fatalf("exit routes = %v, want [0.0.0.0/0]", grant2.Routes)
	}
	if grant2.OverlayIP == grant.OverlayIP {
		t.Fatal("two concurrent vpn sessions got the same overlay ip")
	}
}

func TestBrokerVPNServiceDenied(t *testing.T) {
	// walter (watcher) may shell anywhere but has no service_kinds rule.
	b, agents, _, _ := testBroker(t)
	agents.services = map[string][]types.Service{
		"n-aaaaaaaaaaaa": {{Name: "lan", Kind: types.KindSubnet, NodeID: "n-aaaaaaaaaaaa", Addr: "192.168.99.0/24"}},
	}
	ident := &ca.Identity{Kind: ca.KindUser, Workspace: defaultWorkspace, Name: "walter", Roles: []string{"watcher"}}
	_, err := b.CreateSession(context.Background(), ident, &genezav1.CreateSessionRequest{
		Node:           "web1",
		Action:         types.ActionVPN,
		Service:        "lan",
		ClientNoisePub: clientNoise(),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied for vpn without service rule, got %v", err)
	}
}

func TestBrokerWebPathPolicyGate(t *testing.T) {
	b, _, _, _ := testBroker(t)
	ident := &ca.Identity{Kind: ca.KindUser, Workspace: defaultWorkspace, Name: "nina", Roles: []string{"natonly"}}
	req := &genezav1.CreateSessionRequest{Node: "web1", Action: "shell", ClientNoisePub: clientNoise()}

	// Native client path is allowed by the require_native rule.
	if _, err := b.CreateSession(context.Background(), ident, req); err != nil {
		t.Fatalf("native shell should be allowed: %v", err)
	}
	// The browser shell proxy goes through CreateSessionWeb -> client_path=web,
	// which require_native must deny.
	if _, err := b.CreateSessionWeb(context.Background(), ident, req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("web shell must be denied by require_native, got %v", err)
	}
}

func TestBrokerPolicyDeny(t *testing.T) {
	b, _, _, _ := testBroker(t)
	// bob has no bindings at all.
	ident := &ca.Identity{Kind: ca.KindUser, Workspace: defaultWorkspace, Name: "bob", Roles: []string{"nobody"}}
	_, err := b.CreateSession(context.Background(), ident, &genezav1.CreateSessionRequest{
		Node:           "web1",
		Action:         "shell",
		ClientNoisePub: clientNoise(),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
}

func TestBrokerDetachDeniedStrict(t *testing.T) {
	b, _, _, _ := testBroker(t)
	// walter's only rule sets allow_detach: false.
	ident := &ca.Identity{Kind: ca.KindUser, Workspace: defaultWorkspace, Name: "walter", Roles: []string{"watcher"}}
	_, err := b.CreateSession(context.Background(), ident, &genezav1.CreateSessionRequest{
		Node:           "web1",
		Action:         "shell",
		WantDetachable: true,
		ClientNoisePub: clientNoise(),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied for detach request, got %v", err)
	}
}

func TestBrokerActionValidation(t *testing.T) {
	b, _, _, _ := testBroker(t)
	ident := &ca.Identity{Kind: ca.KindUser, Workspace: defaultWorkspace, Name: "alice", Roles: []string{"ops"}}
	cases := []*genezav1.CreateSessionRequest{
		{Node: "web1", Action: "exec", ClientNoisePub: clientNoise()},                           // exec without command
		{Node: "web1", Action: "forward", ClientNoisePub: clientNoise()},                        // forward without target
		{Node: "web1", Action: "forward", ForwardTarget: "nope", ClientNoisePub: clientNoise()}, // not host:port
		{Node: "web1", Action: "attach", ClientNoisePub: clientNoise()},                         // attach without id
		{Node: "web1", Action: "shell", ClientNoisePub: []byte("short")},                        // bad noise key
		{Node: "web1", Action: "dance", ClientNoisePub: clientNoise()},                          // unknown action
	}
	for i, req := range cases {
		if _, err := b.CreateSession(context.Background(), ident, req); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("case %d: want InvalidArgument, got %v", i, err)
		}
	}
}

func TestBrokerAgentRejection(t *testing.T) {
	b, agents, store, _ := testBroker(t)
	agents.accepted = false
	agents.reason = "session limit reached"
	ident := &ca.Identity{Kind: ca.KindUser, Workspace: defaultWorkspace, Name: "alice", Roles: []string{"ops"}}
	_, err := b.CreateSession(context.Background(), ident, &genezav1.CreateSessionRequest{
		Node:           "web1",
		Action:         "shell",
		ClientNoisePub: clientNoise(),
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable, got %v", err)
	}
	// The pending record must be closed out.
	sessions, err := store.ListSessions(defaultWorkspace)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].State != SessionEnded {
		t.Fatalf("rejected offer should end the session record: %+v", sessions)
	}
}

func TestBrokerAttachFlow(t *testing.T) {
	b, _, store, _ := testBroker(t)
	ident := &ca.Identity{Kind: ca.KindUser, Workspace: defaultWorkspace, Name: "alice", Roles: []string{"ops"}}
	// A detached prior session owned by alice with a known host session.
	if err := store.PutSession(defaultWorkspace, &SessionRecord{
		ID: "s-111111111111", User: "alice", NodeID: "n-aaaaaaaaaaaa", NodeName: "web1",
		Action: "shell", State: SessionDetached, HostSessionID: "h-42", Detachable: true,
	}); err != nil {
		t.Fatal(err)
	}
	resp, err := b.CreateSession(context.Background(), ident, &genezav1.CreateSessionRequest{
		Action:          "attach",
		AttachSessionId: "s-111111111111",
		ClientNoisePub:  clientNoise(),
	})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	signed, _ := types.DecodeSigned(resp.SignedGrant)
	var grant types.SessionGrant
	if err := json.Unmarshal(signed.Payload, &grant); err != nil {
		t.Fatal(err)
	}
	if grant.AttachID != "h-42" {
		t.Fatalf("grant.AttachID = %q, want h-42", grant.AttachID)
	}

	// Someone else's session: opaque denial.
	if err := store.PutSession(defaultWorkspace, &SessionRecord{
		ID: "s-222222222222", User: "mallory", NodeID: "n-aaaaaaaaaaaa",
		Action: "shell", State: SessionDetached, HostSessionID: "h-43",
	}); err != nil {
		t.Fatal(err)
	}
	_, err = b.CreateSession(context.Background(), ident, &genezav1.CreateSessionRequest{
		Action:          "attach",
		AttachSessionId: "s-222222222222",
		ClientNoisePub:  clientNoise(),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("foreign attach: want PermissionDenied, got %v", err)
	}

	// Ended sessions cannot be reattached.
	if err := store.UpdateSession(defaultWorkspace, "s-111111111111", func(r *SessionRecord) { r.State = SessionEnded }); err != nil {
		t.Fatal(err)
	}
	_, err = b.CreateSession(context.Background(), ident, &genezav1.CreateSessionRequest{
		Action:          "attach",
		AttachSessionId: "s-111111111111",
		ClientNoisePub:  clientNoise(),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ended attach: want PermissionDenied, got %v", err)
	}
}

// redirectFor only points a client at a controller PRESENT in the signed cluster set,
// never at the raw affinity row, and is inert without a signed fleet (single-node).
func TestBrokerRedirectFor(t *testing.T) {
	store := testStore(t)
	b := &Broker{store: store}
	now := time.Now()

	// No resolver wired (single-node): always nil.
	if got := b.redirectFor("n1"); got != nil {
		t.Fatalf("no resolver: want nil, got %v", got)
	}

	signed := []types.ControllerEndpoint{{ControllerID: "gw-B", Addrs: []string{"10.0.0.2:7401"}}}
	b.SetClusterRedirect("gw-A", func() []types.ControllerEndpoint { return signed })

	// Unowned node: nil.
	if got := b.redirectFor("n1"); got != nil {
		t.Fatalf("unowned: want nil, got %v", got)
	}

	// Owned by a peer present in the signed set: redirect to the SIGNED addrs.
	if _, err := store.ClaimAgentAffinity("n1", "gw-B", now); err != nil {
		t.Fatal(err)
	}
	red := b.redirectFor("n1")
	if red == nil || red.GetControllerId() != "gw-B" || len(red.GetAddrs()) != 1 || red.GetAddrs()[0] != "10.0.0.2:7401" {
		t.Fatalf("peer-owned: want redirect to gw-B signed addr, got %v", red)
	}

	// Owned by self (stale affinity, no live local stream): never self-redirect.
	if _, err := store.ClaimAgentAffinity("n2", "gw-A", now); err != nil {
		t.Fatal(err)
	}
	if got := b.redirectFor("n2"); got != nil {
		t.Fatalf("self-owned: want nil, got %v", got)
	}

	// Owned by a peer ABSENT from the signed set: fail closed (nil → caller denies).
	if _, err := store.ClaimAgentAffinity("n3", "gw-Z", now); err != nil {
		t.Fatal(err)
	}
	if got := b.redirectFor("n3"); got != nil {
		t.Fatalf("unsigned owner: want nil (fail closed), got %v", got)
	}
}
