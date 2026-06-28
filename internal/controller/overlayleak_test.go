package controller

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"geneza.io/internal/ca"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

// TestBrokerVPNRejectReleasesOverlayIP guards against leaking a per-session
// overlay address when the agent rejects a VPN offer. The broker allocates a
// client overlay IP (100.64.0.128..254 = 127 per workspace) before offering the
// session; if a rejected offer never releases it, the pool is exhausted after
// 127 rejects and every later VPN request fails closed — a permanent,
// restart-only denial of the VPN service for the whole workspace.
func TestBrokerVPNRejectReleasesOverlayIP(t *testing.T) {
	b, agents, _, _ := testBroker(t)
	agents.services = map[string][]types.Service{
		"n-aaaaaaaaaaaa": {{Name: "lan", Kind: types.KindSubnet, NodeID: "n-aaaaaaaaaaaa", Addr: "192.168.99.0/24"}},
	}
	agents.accepted = false // every offer is rejected at the agent

	ident := &ca.Identity{Kind: ca.KindUser, Workspace: defaultWorkspace, Name: "alice", Roles: []string{"ops"}}
	req := &genezav1.CreateSessionRequest{
		Node: "web1", Action: types.ActionVPN, Service: "lan", ClientNoisePub: clientNoise(),
	}

	// Drive well past the 127-address pool. Each rejected request must hand its
	// overlay IP back, so none of these should ever fail with ResourceExhausted.
	const attempts = 127 + 10
	for i := 0; i < attempts; i++ {
		_, err := b.CreateSession(context.Background(), ident, req)
		if err == nil {
			t.Fatalf("attempt %d: expected the agent reject, got success", i)
		}
		if status.Code(err) == codes.ResourceExhausted {
			t.Fatalf("overlay pool exhausted after %d rejected VPN sessions (%v): "+
				"a rejected offer leaks its overlay IP", i, err)
		}
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("attempt %d: want Unavailable (agent rejected), got %v: %v", i, status.Code(err), err)
		}
	}
}
