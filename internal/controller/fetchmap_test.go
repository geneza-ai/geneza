package controller

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"geneza.io/internal/ca"
	genezav1 "geneza.io/internal/pb/geneza/v1"
)

func nodeIdentityCtx(ws, name string) context.Context {
	pi := &peerInfo{identity: &ca.Identity{Kind: ca.KindNode, Workspace: ws, Name: name}}
	return context.WithValue(context.Background(), peerInfoKey{}, pi)
}

// FetchClusterConfig serves the signed map to an enrolled node only when it is
// behind, returns an empty payload to a current/ahead caller (so a steady-state
// probe is a cheap 304), and refuses an unenrolled or anonymous caller.
func TestFetchClusterConfig(t *testing.T) {
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.store.PutNode(defaultWorkspace, &NodeRecord{ID: "n1", Name: "alpha", Approved: true}); err != nil {
		t.Fatal(err)
	}
	signed := []byte("signed-cluster-map-bytes")
	srv.setClusterConfig(5, signed)

	n := &nodeControlService{s: srv}
	ctx := nodeIdentityCtx(defaultWorkspace, "n1")

	// Behind -> the signed map.
	resp, err := n.FetchClusterConfig(ctx, &genezav1.MapRequest{HaveVersion: 3})
	if err != nil {
		t.Fatalf("behind: %v", err)
	}
	if string(resp.GetClusterConfig()) != string(signed) {
		t.Fatalf("behind: got %q want %q", resp.GetClusterConfig(), signed)
	}

	// Current -> empty (no payload re-sent).
	resp, err = n.FetchClusterConfig(ctx, &genezav1.MapRequest{HaveVersion: 5})
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	if len(resp.GetClusterConfig()) != 0 {
		t.Fatalf("current: want empty, got %d bytes", len(resp.GetClusterConfig()))
	}

	// Ahead (somehow holds a newer version) -> empty, never a rollback.
	resp, err = n.FetchClusterConfig(ctx, &genezav1.MapRequest{HaveVersion: 9})
	if err != nil {
		t.Fatalf("ahead: %v", err)
	}
	if len(resp.GetClusterConfig()) != 0 {
		t.Fatalf("ahead: want empty, got %d bytes", len(resp.GetClusterConfig()))
	}

	// Unenrolled node (valid node cert, no record) -> PermissionDenied: a
	// deprovisioned node cannot keep pulling the map.
	if _, err := n.FetchClusterConfig(nodeIdentityCtx(defaultWorkspace, "ghost"), &genezav1.MapRequest{HaveVersion: 0}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unenrolled: want PermissionDenied, got %v", err)
	}

	// No verified identity -> Unauthenticated.
	if _, err := n.FetchClusterConfig(context.Background(), &genezav1.MapRequest{HaveVersion: 0}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no identity: want Unauthenticated, got %v", err)
	}
}
