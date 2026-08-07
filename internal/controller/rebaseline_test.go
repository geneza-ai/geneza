package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Reuses userCtx from recording_replay_test.go — one identity-context helper for
// the package, so a change to how callers are authenticated shows up everywhere.
func wsAdminCtx(ws, name string) context.Context  { return userCtx(ws, name, roleWSAdmin) }
func wsViewerCtx(ws, name string) context.Context { return userCtx(ws, name, "ws-viewer") }

// A node whose agent was updated OUT OF BAND drifts from its pinned baseline and
// is quarantined as binary_tamper. Re-approval cannot fix that — the baseline is
// deliberately preserved across it — so the node re-quarantines on its next beat,
// forever, while the approve button appears to have worked. Rebaseline is the
// only exit; this proves it is one, and that the sharp edges are guarded.
func TestRebaselineResolvesADriftQuarantineThatApprovalCannot(t *testing.T) {
	srv := newReplayServer(t)
	const ws, nodeID = defaultWorkspace, "n-rebase"
	old := sha256.Sum256([]byte("the binary the admin originally approved"))
	cur := sha256.Sum256([]byte("the binary the admin installed by hand"))

	if err := srv.store.PutNode(ws, &NodeRecord{
		WorkspaceID: ws, ID: nodeID, Name: "node-rebase", Approved: true,
		ApprovedBinaryHash: old[:], LastBinaryHash: cur[:],
	}); err != nil {
		t.Fatal(err)
	}
	api := &workspaceAPIService{s: srv}
	ctx := wsAdminCtx(ws, "alice")

	// A reason is mandatory: this accepts a binary the controller never published.
	if _, err := api.RebaselineNode(ctx, &genezav1.RebaselineNodeRequest{Node: nodeID}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a bare rebaseline must be refused, got %v", err)
	}

	// The blessed hash is the node's OWN measurement, so an admin acting on a
	// stale view cannot bless a binary that changed underneath them.
	stale := sha256.Sum256([]byte("what the console showed a minute ago"))
	_, err := api.RebaselineNode(ctx, &genezav1.RebaselineNodeRequest{
		Node: nodeID, Reason: "verified by hand", ExpectHash: hex.EncodeToString(stale[:]),
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a mismatched expect_hash must be refused, got %v", err)
	}

	resp, err := api.RebaselineNode(ctx, &genezav1.RebaselineNodeRequest{
		Node: nodeID, Reason: "rebuilt from source, checksum verified out of band",
	})
	if err != nil {
		t.Fatalf("rebaseline: %v", err)
	}
	if resp.GetBinaryHash() != hex.EncodeToString(cur[:]) {
		t.Fatalf("blessed %s, want the node's current measurement %s",
			resp.GetBinaryHash(), hex.EncodeToString(cur[:]))
	}

	// The load-bearing assertion: the SAME measurement that used to quarantine
	// must now be steady state. Without the re-pin this drifts again immediately.
	srv.evaluateBinaryDrift(ws, nodeID, cur[:])
	after, err := srv.store.GetNode(ws, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if !after.Approved {
		t.Fatal("the node re-quarantined on the very next beat: the baseline did not move")
	}
	if hex.EncodeToString(after.ApprovedBinaryHash) != hex.EncodeToString(cur[:]) {
		t.Fatalf("baseline = %x, want %x", after.ApprovedBinaryHash, cur[:])
	}
}

// Blessing an unpublished binary must not read as a routine approval when someone
// reviews the trail months later, so it carries its own event type and the hash
// it replaced.
func TestRebaselineIsAuditedUnderItsOwnType(t *testing.T) {
	srv := newReplayServer(t)
	const ws, nodeID = defaultWorkspace, "n-audit"
	old := sha256.Sum256([]byte("old"))
	cur := sha256.Sum256([]byte("new"))
	if err := srv.store.PutNode(ws, &NodeRecord{
		WorkspaceID: ws, ID: nodeID, Name: "node-audit", Approved: true,
		ApprovedBinaryHash: old[:], LastBinaryHash: cur[:],
	}); err != nil {
		t.Fatal(err)
	}
	api := &workspaceAPIService{s: srv}
	if _, err := api.RebaselineNode(wsAdminCtx(ws, "alice"), &genezav1.RebaselineNodeRequest{
		Node: nodeID, Reason: "supply-chain review ticket OPS-4412",
	}); err != nil {
		t.Fatal(err)
	}
	page, err := srv.audit.QueryPage(AuditQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range page.Lines {
		line := string(r)
		if strings.Contains(line, "node_rebaselined") {
			found = true
			for _, want := range []string{
				hex.EncodeToString(cur[:]), // what was blessed
				hex.EncodeToString(old[:]), // what it replaced
				"OPS-4412",                 // why
			} {
				if !strings.Contains(line, want) {
					t.Errorf("audit record is missing %q: %s", want, line)
				}
			}
		}
	}
	if !found {
		t.Fatal("no node_rebaselined record: an unpublished binary was blessed with no distinct trail")
	}
}

// A node that has never reported a measurement has nothing to bless. Silently
// pinning an empty hash would disable drift detection for that node entirely.
func TestRebaselineRefusesANodeWithNoMeasurement(t *testing.T) {
	srv := newReplayServer(t)
	const ws, nodeID = defaultWorkspace, "n-fresh"
	if err := srv.store.PutNode(ws, &NodeRecord{
		WorkspaceID: ws, ID: nodeID, Name: "node-fresh", Approved: true,
	}); err != nil {
		t.Fatal(err)
	}
	api := &workspaceAPIService{s: srv}
	_, err := api.RebaselineNode(wsAdminCtx(ws, "alice"), &genezav1.RebaselineNodeRequest{
		Node: nodeID, Reason: "nothing to bless",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition for an unmeasured node, got %v", err)
	}
}

// Rebaseline moves the admission gate, so it must be gated like the other
// admission mutations rather than on plain membership.
func TestRebaselineRequiresWSAdmin(t *testing.T) {
	srv := newReplayServer(t)
	const ws, nodeID = defaultWorkspace, "n-authz"
	cur := sha256.Sum256([]byte("x"))
	if err := srv.store.PutNode(ws, &NodeRecord{
		WorkspaceID: ws, ID: nodeID, Name: "node-authz", Approved: true, LastBinaryHash: cur[:],
	}); err != nil {
		t.Fatal(err)
	}
	api := &workspaceAPIService{s: srv}
	_, err := api.RebaselineNode(wsViewerCtx(ws, "mallory"), &genezav1.RebaselineNodeRequest{
		Node: nodeID, Reason: "let me in",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a non-admin must not bless a binary, got %v", err)
	}
}
