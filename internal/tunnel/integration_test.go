package tunnel_test

import (
	"crypto/ed25519"
	"encoding/json"
	"net"
	"testing"
	"time"

	"geneza.io/internal/defaults"
	"geneza.io/internal/tunnel"
	"geneza.io/internal/types"
)

// Exercises the real client/agent data-path contract end to end over an
// in-memory pipe: controller signs a grant, client embeds it in the Noise IK
// handshake, agent verifies signature + node binding + that the tunnel's
// remote static key equals the grant's ClientNoisePub, then app bytes flow
// E2E. A relay would only ever see these ciphertext frames.
func TestSignedGrantOverTunnel(t *testing.T) {
	gwPub, gwPriv, keyID, err := types.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	trusted := map[string]ed25519.PublicKey{keyID: gwPub}

	clientKey, err := tunnel.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	agentKey, err := tunnel.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	const nodeID = "n-abc123"
	now := time.Now()
	grant := &types.SessionGrant{
		V: 1, ID: "s-0001", User: "alice", NodeID: nodeID,
		Action: types.ActionShell, AllowPTY: true,
		ClientNoisePub: clientKey.Public, AgentNoisePub: agentKey.Public,
		RelayAddr: "relay:7403", RelayToken: "gz-deadbeef",
		IssuedAt: now, ExpiresAt: now.Add(defaults.GrantTTL),
	}
	signed, err := types.Sign(gwPriv, keyID, defaults.ContextGrant, grant)
	if err != nil {
		t.Fatal(err)
	}
	grantBytes, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	type result struct {
		err  error
		seen []byte
	}
	agentDone := make(chan result, 1)
	go func() {
		conn, err := tunnel.Server(c2, agentKey, grant.ID, func(remoteStatic, payload []byte) ([]byte, error) {
			s, err := types.DecodeSigned(payload)
			if err != nil {
				return nil, err
			}
			g, err := types.VerifyGrant(trusted, s)
			if err != nil {
				return nil, err
			}
			if err := g.Validate(nodeID, agentKey.Public, time.Now()); err != nil {
				return nil, err
			}
			if string(remoteStatic) != string(g.ClientNoisePub) {
				return nil, errMismatch
			}
			return json.Marshal(map[string]any{"ok": true, "node": nodeID})
		})
		if err != nil {
			agentDone <- result{err: err}
			return
		}
		buf := make([]byte, 5)
		_, err = conn.Read(buf)
		agentDone <- result{err: err, seen: buf}
	}()

	conn, accept, err := tunnel.Client(c1, clientKey, agentKey.Public, grant.ID, grantBytes)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	var acc map[string]any
	if err := json.Unmarshal(accept, &acc); err != nil {
		t.Fatalf("accept payload: %v", err)
	}
	if acc["ok"] != true {
		t.Fatalf("agent did not accept: %v", acc)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	r := <-agentDone
	if r.err != nil {
		t.Fatalf("agent side: %v", r.err)
	}
	if string(r.seen) != "hello" {
		t.Fatalf("agent read %q, want hello", r.seen)
	}
}

// A grant signed by an untrusted key must be rejected before any app data.
func TestUntrustedGrantRejected(t *testing.T) {
	_, attackerPriv, attackerID, _ := types.GenerateSigningKey()
	realPub, _, realID, _ := types.GenerateSigningKey()
	trusted := map[string]ed25519.PublicKey{realID: realPub}

	clientKey, _ := tunnel.GenerateKeypair()
	agentKey, _ := tunnel.GenerateKeypair()
	now := time.Now()
	grant := &types.SessionGrant{
		V: 1, ID: "s-x", User: "mallory", NodeID: "n-abc123", Action: types.ActionShell,
		ClientNoisePub: clientKey.Public, AgentNoisePub: agentKey.Public,
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	signed, _ := types.Sign(attackerPriv, attackerID, defaults.ContextGrant, grant)
	grantBytes, _ := signed.Encode()

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		// Mirror the real agent: close the relay conn when a grant is
		// rejected, so the initiator's wait for msg2 unblocks with EOF
		// instead of hanging (Server never writes msg2 on rejection).
		defer c2.Close()
		_, _ = tunnel.Server(c2, agentKey, grant.ID, func(_, payload []byte) ([]byte, error) {
			s, err := types.DecodeSigned(payload)
			if err != nil {
				return nil, err
			}
			if _, err := types.VerifyGrant(trusted, s); err != nil {
				return nil, err
			}
			return []byte("{}"), nil
		})
	}()
	if _, _, err := tunnel.Client(c1, clientKey, agentKey.Public, grant.ID, grantBytes); err == nil {
		t.Fatal("expected handshake failure for untrusted grant")
	}
}

var errMismatch = &mismatchError{}

type mismatchError struct{}

func (*mismatchError) Error() string { return "client noise key mismatch" }
