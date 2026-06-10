package gateway

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"osie.cloud/geneza/internal/ca"
	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
	"osie.cloud/geneza/internal/policy"
	"osie.cloud/geneza/internal/types"
)

type fakeAgents struct {
	online   map[string]bool
	accepted bool
	reason   string
	err      error

	lastNode  string
	lastGrant []byte
}

func (f *fakeAgents) Online(nodeID string) bool { return f.online[nodeID] }

func (f *fakeAgents) SendOffer(_ context.Context, nodeID, sessionID string, grant []byte, _ time.Duration) (bool, string, error) {
	f.lastNode = nodeID
	f.lastGrant = grant
	return f.accepted, f.reason, f.err
}

const testPolicyDoc = `
roles:
  ops:
    allow:
      - actions: ["shell", "exec"]
        node_labels: {env: prod}
        max_session_ttl: 4h
  watcher:
    allow:
      - actions: ["shell"]
        node_labels: {"*": "*"}
        allow_detach: false
bindings:
  - role: ops
    users: [alice]
  - role: watcher
    users: [walter]
  - role: ops
    groups: [admins]
`

func testBroker(t *testing.T) (*Broker, *fakeAgents, *Store, ed25519.PublicKey) {
	t.Helper()
	store := testStore(t)
	audit, err := OpenAudit(filepath.Join(t.TempDir(), "audit.jsonl"))
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
	b := NewBroker(store, audit, agents, func() policy.Engine { return engine },
		priv, keyID, []string{"10.70.70.10:7403"}, 2*time.Minute, 12*time.Hour)

	noise := make([]byte, 32)
	for i := range noise {
		noise[i] = 0xA0
	}
	if err := store.PutNode(&NodeRecord{
		ID: "n-aaaaaaaaaaaa", Name: "web1",
		Labels:   map[string]string{"env": "prod"},
		NoisePub: noise,
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

func TestBrokerGrantConstruction(t *testing.T) {
	b, agents, store, pub := testBroker(t)
	ident := &ca.Identity{Kind: ca.KindUser, Name: "alice", Roles: []string{"ops"}}
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
	rec, err := store.GetSession(resp.SessionId)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != SessionPending || rec.User != "alice" {
		t.Fatalf("session record: %+v", rec)
	}
}

func TestBrokerPolicyDeny(t *testing.T) {
	b, _, _, _ := testBroker(t)
	// bob has no bindings at all.
	ident := &ca.Identity{Kind: ca.KindUser, Name: "bob", Roles: []string{"nobody"}}
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
	ident := &ca.Identity{Kind: ca.KindUser, Name: "walter", Roles: []string{"watcher"}}
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
	ident := &ca.Identity{Kind: ca.KindUser, Name: "alice", Roles: []string{"ops"}}
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
	ident := &ca.Identity{Kind: ca.KindUser, Name: "alice", Roles: []string{"ops"}}
	_, err := b.CreateSession(context.Background(), ident, &genezav1.CreateSessionRequest{
		Node:           "web1",
		Action:         "shell",
		ClientNoisePub: clientNoise(),
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable, got %v", err)
	}
	// The pending record must be closed out.
	sessions, err := store.ListSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].State != SessionEnded {
		t.Fatalf("rejected offer should end the session record: %+v", sessions)
	}
}

func TestBrokerAttachFlow(t *testing.T) {
	b, _, store, _ := testBroker(t)
	ident := &ca.Identity{Kind: ca.KindUser, Name: "alice", Roles: []string{"ops"}}
	// A detached prior session owned by alice with a known host session.
	if err := store.PutSession(&SessionRecord{
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
	if err := store.PutSession(&SessionRecord{
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
	if err := store.UpdateSession("s-111111111111", func(r *SessionRecord) { r.State = SessionEnded }); err != nil {
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
