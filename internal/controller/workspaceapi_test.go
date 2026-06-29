package controller

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// TestWorkspaceEnrollAuthz pins the fix for "geneza node enroll -> admin role
// required": CreateJoinToken now lives on the WorkspaceAPI, so a ws-admin enrolls
// machines into their OWN workspace, a plain ws-member is refused, and the reserved
// cluster admin still passes (holds it everywhere). The token binds to the caller's
// workspace.
func TestWorkspaceEnrollAuthz(t *testing.T) {
	srv := newReplayServer(t)
	w := &workspaceAPIService{s: srv}

	// ws-admin: allowed.
	resp, err := w.CreateJoinToken(userCtx(defaultWorkspace, "adm", roleWSAdmin), &genezav1.CreateJoinTokenRequest{})
	if err != nil {
		t.Fatalf("ws-admin enroll should succeed, got %v", err)
	}
	if resp.GetToken() == "" {
		t.Fatal("no token returned")
	}

	// ws-member: refused (this is the bug — used to be a cluster-admin gate).
	if _, err := w.CreateJoinToken(userCtx(defaultWorkspace, "bob", roleWSMember), &genezav1.CreateJoinTokenRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ws-member enroll must be PermissionDenied, got %v", err)
	}

	// reserved cluster admin: allowed (satisfies the workspace gate everywhere).
	if _, err := w.CreateJoinToken(userCtx(defaultWorkspace, "root", roleAdmin), &genezav1.CreateJoinTokenRequest{}); err != nil {
		t.Fatalf("cluster admin enroll should succeed, got %v", err)
	}
}
