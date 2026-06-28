package agentd

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"geneza.io/internal/types"
)

const testNodeID = "node-aaaa"

func testKeys(t *testing.T) (ed25519.PrivateKey, string, map[string]ed25519.PublicKey) {
	t.Helper()
	pub, priv, keyID, err := types.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return priv, keyID, map[string]ed25519.PublicKey{keyID: pub}
}

func testAgentNoisePub() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func testGrant(now time.Time) types.SessionGrant {
	client := make([]byte, 32)
	for i := range client {
		client[i] = byte(0x40 + i)
	}
	return types.SessionGrant{
		V:              1,
		ID:             "sess-1",
		User:           "alice",
		NodeID:         testNodeID,
		Action:         types.ActionShell,
		AllowPTY:       true,
		ClientNoisePub: client,
		AgentNoisePub:  testAgentNoisePub(),
		RelayAddr:      "relay.example:7403",
		RelayToken:     "gz-deadbeef",
		IssuedAt:       now.Add(-time.Second),
		ExpiresAt:      now.Add(2 * time.Minute),
	}
}

func signGrant(t *testing.T, priv ed25519.PrivateKey, keyID string, g types.SessionGrant) []byte {
	t.Helper()
	env, err := types.Sign(priv, keyID, "grant", g)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestEvaluateOfferAccepts(t *testing.T) {
	priv, keyID, trusted := testKeys(t)
	now := time.Now()
	raw := signGrant(t, priv, keyID, testGrant(now))

	got, err := EvaluateOffer(raw, trusted, nil, "", testNodeID, testAgentNoisePub(), types.AgentPolicy{}, now)
	if err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
	if got.ID != "sess-1" || got.User != "alice" {
		t.Fatalf("wrong grant parsed: %+v", got)
	}
}

func TestEvaluateOfferRejectsWrongNode(t *testing.T) {
	priv, keyID, trusted := testKeys(t)
	now := time.Now()
	g := testGrant(now)
	g.NodeID = "node-other"
	raw := signGrant(t, priv, keyID, g)

	if _, err := EvaluateOffer(raw, trusted, nil, "", testNodeID, testAgentNoisePub(), types.AgentPolicy{}, now); err == nil {
		t.Fatal("grant for another node must be rejected")
	}
}

func TestEvaluateOfferRejectsExpired(t *testing.T) {
	priv, keyID, trusted := testKeys(t)
	now := time.Now()
	g := testGrant(now)
	g.IssuedAt = now.Add(-10 * time.Minute)
	g.ExpiresAt = now.Add(-5 * time.Minute)
	raw := signGrant(t, priv, keyID, g)

	_, err := EvaluateOffer(raw, trusted, nil, "", testNodeID, testAgentNoisePub(), types.AgentPolicy{}, now)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired grant must be rejected, got %v", err)
	}
}

func TestEvaluateOfferRejectsUnknownKey(t *testing.T) {
	priv, keyID, _ := testKeys(t)
	_, _, otherTrusted := testKeys(t) // trusts a different key entirely
	now := time.Now()
	raw := signGrant(t, priv, keyID, testGrant(now))

	_, err := EvaluateOffer(raw, otherTrusted, nil, "", testNodeID, testAgentNoisePub(), types.AgentPolicy{}, now)
	if !errors.Is(err, types.ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}
}

func TestEvaluateOfferRejectsTamperedPayload(t *testing.T) {
	priv, keyID, trusted := testKeys(t)
	now := time.Now()
	env, err := types.Sign(priv, keyID, "grant", testGrant(now))
	if err != nil {
		t.Fatal(err)
	}
	// Flip a payload byte after signing.
	env.Payload[10] ^= 0xff
	raw, err := env.Encode()
	if err != nil {
		t.Fatal(err)
	}
	_, err = EvaluateOffer(raw, trusted, nil, "", testNodeID, testAgentNoisePub(), types.AgentPolicy{}, now)
	if !errors.Is(err, types.ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestEvaluateOfferRejectsDetachWhenForbidden(t *testing.T) {
	priv, keyID, trusted := testKeys(t)
	now := time.Now()
	g := testGrant(now)
	g.AllowDetach = true
	raw := signGrant(t, priv, keyID, g)

	// Local agent policy outranks the controller's grant: forbid_detach wins.
	_, err := EvaluateOffer(raw, trusted, nil, "", testNodeID, testAgentNoisePub(),
		types.AgentPolicy{ForbidDetach: true}, now)
	if err == nil || !strings.Contains(err.Error(), "detach") {
		t.Fatalf("detachable grant must be rejected under forbid_detach, got %v", err)
	}

	// Same grant without detach is fine under the same policy.
	g.AllowDetach = false
	raw = signGrant(t, priv, keyID, g)
	if _, err := EvaluateOffer(raw, trusted, nil, "", testNodeID, testAgentNoisePub(),
		types.AgentPolicy{ForbidDetach: true}, now); err != nil {
		t.Fatalf("non-detachable grant should pass forbid_detach policy, got %v", err)
	}
}

func TestEvaluateOfferRejectsNoiseKeyMismatch(t *testing.T) {
	priv, keyID, trusted := testKeys(t)
	now := time.Now()
	raw := signGrant(t, priv, keyID, testGrant(now))

	wrongPub := make([]byte, 32) // all zeros != testAgentNoisePub
	if _, err := EvaluateOffer(raw, trusted, nil, "", testNodeID, wrongPub, types.AgentPolicy{}, now); err == nil {
		t.Fatal("grant bound to a different agent noise key must be rejected")
	}
}

func TestEvaluateOfferRejectsGarbage(t *testing.T) {
	_, _, trusted := testKeys(t)
	if _, err := EvaluateOffer([]byte("not json"), trusted, nil, "", testNodeID, testAgentNoisePub(), types.AgentPolicy{}, time.Now()); err == nil {
		t.Fatal("garbage envelope must be rejected")
	}
}

// Scoped-grant floor: the agent rejects a grant whose workspace is not its own
// enrolled workspace, even when the signature is valid (a compromised/failed-over
// controller must not plant a cross-workspace grant on a node).
func TestEvaluateOfferRejectsWrongWorkspace(t *testing.T) {
	priv, keyID, trusted := testKeys(t)
	now := time.Now()
	g := testGrant(now)
	g.WorkspaceID = "ws-b"
	raw := signGrant(t, priv, keyID, g)
	if _, err := EvaluateOffer(raw, trusted, nil, "ws-a", testNodeID, testAgentNoisePub(), types.AgentPolicy{}, now); err == nil {
		t.Fatal("expected rejection of a grant for a different workspace")
	}
}

func TestEvaluateOfferAcceptsMatchingWorkspace(t *testing.T) {
	priv, keyID, trusted := testKeys(t)
	now := time.Now()
	g := testGrant(now)
	g.WorkspaceID = "ws-a"
	raw := signGrant(t, priv, keyID, g)
	if _, err := EvaluateOffer(raw, trusted, nil, "ws-a", testNodeID, testAgentNoisePub(), types.AgentPolicy{}, now); err != nil {
		t.Fatalf("grant for the agent's own workspace must be accepted: %v", err)
	}
}

// A signing key scoped to a set of workspaces cannot sign a grant for a workspace
// outside that scope, regardless of the agent's own workspace.
func TestEvaluateOfferRejectsKeyOutOfScope(t *testing.T) {
	priv, keyID, trusted := testKeys(t)
	now := time.Now()
	g := testGrant(now)
	g.WorkspaceID = "ws-b"
	raw := signGrant(t, priv, keyID, g)
	scopes := map[string][]string{keyID: {"ws-a"}} // key may only sign for ws-a
	if _, err := EvaluateOffer(raw, trusted, scopes, "", testNodeID, testAgentNoisePub(), types.AgentPolicy{}, now); err == nil {
		t.Fatal("expected rejection: key is not scoped for ws-b")
	}
	// In-scope is accepted.
	scopes[keyID] = []string{"ws-b"}
	if _, err := EvaluateOffer(raw, trusted, scopes, "", testNodeID, testAgentNoisePub(), types.AgentPolicy{}, now); err != nil {
		t.Fatalf("in-scope grant must be accepted: %v", err)
	}
}
