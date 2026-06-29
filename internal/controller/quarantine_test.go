package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"geneza.io/internal/ca"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

func driftHash(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

func putApprovedNode(t *testing.T, srv *Server, ws, id string, plat PlatformRecord) {
	t.Helper()
	if err := srv.store.PutNode(ws, &NodeRecord{
		WorkspaceID: ws, ID: id, Name: id,
		Approved: true, ApprovedBy: "test", ApprovedAtUnix: time.Now().Unix(),
		Platform: plat,
	}); err != nil {
		t.Fatalf("put node: %v", err)
	}
}

// A swapped agent binary (a hash the controller never published) quarantines the node
// and tears down its live sessions; re-approval clears the quarantine but PRESERVES
// the blessed baseline, so a still-tampered node re-quarantines and cannot launder
// itself trusted by an admin click alone.
func TestBinaryDriftQuarantinesAndReapprove(t *testing.T) {
	srv := newContinuousAuthzServer(t)
	const ws, node, sid = "ws-1", "node-drift", "sess-drift"
	putApprovedNode(t, srv, ws, node, PlatformRecord{OS: "linux", Arch: "amd64"})
	putActiveSession(t, srv, ws, node, sid)
	good, bad := driftHash("good-binary"), driftHash("tampered-binary")

	// First measurement after approval pins the baseline — no drift.
	srv.evaluateBinaryDrift(ws, node, good)
	if n, _ := srv.store.GetNode(ws, node); !n.Approved {
		t.Fatal("baseline pin must not quarantine an approved node")
	}
	if _, err := srv.store.GetQuarantine(ws, node); err == nil {
		t.Fatal("no quarantine expected after the first (baseline) measurement")
	}

	// A different, unpublished hash is tamper.
	srv.evaluateBinaryDrift(ws, node, bad)
	if n, _ := srv.store.GetNode(ws, node); n.Approved {
		t.Fatal("binary tamper must quarantine (Approved=false)")
	}
	q, err := srv.store.GetQuarantine(ws, node)
	if err != nil || q.Reason != "binary_tamper" {
		t.Fatalf("expected binary_tamper quarantine, got %+v err=%v", q, err)
	}
	if s, _ := srv.store.GetSession(ws, sid); s.State != SessionRevoked {
		t.Fatalf("quarantine must revoke live sessions, state=%v", s.State)
	}
	if _, ok := lastAudit(t, srv, "node_quarantined"); !ok {
		t.Fatal("quarantine must be audited")
	}

	// Re-approval clears the quarantine but keeps the baseline.
	if _, err := srv.store.SetNodeApproval(ws, node, true, "admin", time.Now()); err != nil {
		t.Fatalf("reapprove: %v", err)
	}
	if _, err := srv.store.GetQuarantine(ws, node); err == nil {
		t.Fatal("re-approval must clear the quarantine record")
	}
	// Still running the tampered binary → re-quarantines on the next beat.
	srv.evaluateBinaryDrift(ws, node, bad)
	if n, _ := srv.store.GetNode(ws, node); n.Approved {
		t.Fatal("a still-tampered node must re-quarantine after re-approval (no laundering)")
	}
}

// publishAgentRelease records a published geneza-agent release manifest by its hash
// and publish time (the CreatedAt drives the anti-rollback floor).
func publishAgentRelease(t *testing.T, srv *Server, version string, binHash []byte, createdUnix int64) {
	t.Helper()
	m := types.Manifest{
		Product: "geneza-agent", OS: "linux", Arch: "amd64", Version: version,
		SHA256: hex.EncodeToString(binHash), CreatedAt: time.Unix(createdUnix, 0).UTC(),
	}
	payload, _ := json.Marshal(&m)
	env := types.Signed{Payload: payload}
	raw, _ := env.Encode()
	if err := srv.store.PutManifest(ManifestKey("geneza-agent", "linux", "amd64", version), raw); err != nil {
		t.Fatalf("put manifest: %v", err)
	}
}

func mustNode(t *testing.T, srv *Server, ws, id string) *NodeRecord {
	t.Helper()
	n, err := srv.store.GetNode(ws, id)
	if err != nil {
		t.Fatalf("get node %s: %v", id, err)
	}
	return n
}

// faultyStore wraps a real Store and injects errors on the drift-path methods, to
// prove the controller fails CLOSED (never leaves a drifted/quarantined node usable)
// when the store errors. Every other method delegates to the embedded Store.
type faultyStore struct {
	Store
	failFindQuarantine bool
	failQuarantineNode bool
}

func (f *faultyStore) FindQuarantineByHostUUID(ws, uuid string) (*QuarantineRecord, error) {
	if f.failFindQuarantine {
		return nil, fmt.Errorf("store unreachable")
	}
	return f.Store.FindQuarantineByHostUUID(ws, uuid)
}

func (f *faultyStore) QuarantineNode(ws, nodeID, reason, by string, detail map[string]string) (*NodeRecord, error) {
	if f.failQuarantineNode {
		return nil, fmt.Errorf("store unreachable")
	}
	return f.Store.QuarantineNode(ws, nodeID, reason, by, detail)
}

// A binary change whose hash matches ANY release the controller published is a
// sanctioned update: it re-pins the baseline silently, never quarantines — even when
// the operator manually pins a node to a published version that is NOT the rollout
// ring's stable/canary and is not what the node was enrolled reporting.
func TestSanctionedUpdateRepinsNoQuarantine(t *testing.T) {
	srv := newContinuousAuthzServer(t)
	const ws, node = "ws-1", "node-upd"
	// Node enrolled reporting v1; rollout ring is unset. A manual operator update
	// moves it to a published v9 that is neither stable, canary, nor its enrolled
	// version — the authoritative hash check must still recognize it as trusted.
	putApprovedNode(t, srv, ws, node, PlatformRecord{OS: "linux", Arch: "amd64", AgentVersion: "v1"})
	good, manual := driftHash("v1-binary"), driftHash("v9-manual-but-published")
	publishAgentRelease(t, srv, "v9", manual, 9000)

	srv.evaluateBinaryDrift(ws, node, good)   // pin baseline = v1
	srv.evaluateBinaryDrift(ws, node, manual) // changed to a published-but-non-ring release
	n, _ := srv.store.GetNode(ws, node)
	if !n.Approved {
		t.Fatal("a manual update to a published release must NOT quarantine")
	}
	if !bytes.Equal(n.ApprovedBinaryHash, manual) {
		t.Fatal("baseline must re-pin to the updated release hash")
	}
	if _, err := srv.store.GetQuarantine(ws, node); err == nil {
		t.Fatal("no quarantine for a sanctioned update")
	}
}

// The manual "Quarantine" button funnels through the same central entrypoint as the
// auto-detectors: it denies the node, writes the cause, and tears down live sessions.
func TestManualQuarantineCentralEntrypoint(t *testing.T) {
	srv := newContinuousAuthzServer(t)
	const ws, node, sid = "ws-1", "node-man", "sess-man"
	putApprovedNode(t, srv, ws, node, PlatformRecord{OS: "linux", Arch: "amd64"})
	putActiveSession(t, srv, ws, node, sid)

	if err := srv.quarantineNode(ws, node, "manual", "admin@acme", map[string]string{"name": node}); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if n, _ := srv.store.GetNode(ws, node); n.Approved {
		t.Fatal("manual quarantine must set Approved=false")
	}
	q, err := srv.store.GetQuarantine(ws, node)
	if err != nil || q.Reason != "manual" || q.QuarantinedBy != "admin@acme" {
		t.Fatalf("manual quarantine record wrong: %+v err=%v", q, err)
	}
	if s, _ := srv.store.GetSession(ws, sid); s.State != SessionRevoked {
		t.Fatal("manual quarantine must revoke live sessions")
	}
}

// A quarantine pins the host's stable hardware id so a wipe-and-re-enroll of the
// same host (a fresh node id) is found by host evidence and held for admin review.
func TestQuarantineFoundByHostUUID(t *testing.T) {
	srv := newContinuousAuthzServer(t)
	const ws, node = "ws-1", "node-host"
	putApprovedNode(t, srv, ws, node, PlatformRecord{OS: "linux", Arch: "amd64", HostUUID: "uuid-XYZ"})

	if err := srv.quarantineNode(ws, node, "identity_clone", "system", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	q, err := srv.store.FindQuarantineByHostUUID(ws, "uuid-XYZ")
	if err != nil || q.NodeID != node {
		t.Fatalf("host-uuid lookup must find the quarantine, got %+v err=%v", q, err)
	}
	if _, err := srv.store.FindQuarantineByHostUUID(ws, "other-uuid"); err == nil {
		t.Fatal("an unrelated host uuid must not match")
	}
}

// A malformed (non-32-byte) self-measurement must NOT pin the baseline and must NOT
// quarantine a healthy node — it is dropped, and a later valid hash pins cleanly.
func TestShortBinaryHashRejected(t *testing.T) {
	srv := newContinuousAuthzServer(t)
	const ws, node = "ws-1", "node-short"
	putApprovedNode(t, srv, ws, node, PlatformRecord{OS: "linux", Arch: "amd64"})

	srv.evaluateBinaryDrift(ws, node, []byte{1, 2, 3}) // too short
	n := mustNode(t, srv, ws, node)
	if len(n.ApprovedBinaryHash) != 0 {
		t.Fatal("a short hash must not pin the baseline")
	}
	if !n.Approved {
		t.Fatal("a short hash must not quarantine a healthy node")
	}
	good := driftHash("good")
	srv.evaluateBinaryDrift(ws, node, good)
	if !bytes.Equal(mustNode(t, srv, ws, node).ApprovedBinaryHash, good) {
		t.Fatal("a valid 32-byte hash should pin cleanly after a rejected short one")
	}
}

// A downgrade to an OLDER published release (a known-vulnerable signed build) is
// quarantined; a forward update to a newer published release is accepted.
func TestDowngradeToOldPublishedReleaseQuarantines(t *testing.T) {
	srv := newContinuousAuthzServer(t)
	const ws, node = "ws-1", "node-dg"
	putApprovedNode(t, srv, ws, node, PlatformRecord{OS: "linux", Arch: "amd64"})
	v1, v2 := driftHash("v1-bin"), driftHash("v2-bin")
	publishAgentRelease(t, srv, "v1", v1, 1000)
	publishAgentRelease(t, srv, "v2", v2, 2000)

	srv.evaluateBinaryDrift(ws, node, v1) // first-pin v1 → floor = 1000
	if got := mustNode(t, srv, ws, node).ApprovedBinaryCreatedUnix; got != 1000 {
		t.Fatalf("first-pin floor = %d, want 1000", got)
	}
	srv.evaluateBinaryDrift(ws, node, v2) // forward update → accepted, floor advances
	if n := mustNode(t, srv, ws, node); !n.Approved || n.ApprovedBinaryCreatedUnix != 2000 {
		t.Fatalf("forward update should be accepted and advance the floor: %+v", n)
	}
	srv.evaluateBinaryDrift(ws, node, v1) // rollback to older published release → downgrade
	if mustNode(t, srv, ws, node).Approved {
		t.Fatal("a downgrade to an older published release must quarantine")
	}
	if q, err := srv.store.GetQuarantine(ws, node); err != nil || q.Reason != "binary_downgrade" {
		t.Fatalf("expected binary_downgrade quarantine, got %+v err=%v", q, err)
	}
}

// A stale, in-flight drift measurement must not clobber a FRESH admin re-approval —
// the admin acted on newer information; the next fresh beat re-decides.
func TestStaleDriftDoesNotClobberReapproval(t *testing.T) {
	srv := newContinuousAuthzServer(t)
	const ws, node = "ws-1", "node-toctou"
	putApprovedNode(t, srv, ws, node, PlatformRecord{OS: "linux", Arch: "amd64"})
	good, bad := driftHash("good"), driftHash("bad")
	srv.evaluateBinaryDrift(ws, node, good) // pin
	srv.evaluateBinaryDrift(ws, node, bad)  // quarantine (tamper)
	if mustNode(t, srv, ws, node).Approved {
		t.Fatal("precondition: node should be quarantined")
	}
	// Admin re-approves (stamped now).
	if err := srv.approveNodeWithReason(ws, mustNode(t, srv, ws, node), true, "investigated, cleared", "admin"); err != nil {
		t.Fatalf("reapprove: %v", err)
	}
	// A stale beat whose measurement predates the re-approval tries to quarantine.
	stale := time.Now().Unix() - 5
	srv.driftQuarantine(ws, node, "binary_tamper", stale, map[string]string{"measured_hash": hex.EncodeToString(bad)})
	if !mustNode(t, srv, ws, node).Approved {
		t.Fatal("a stale drift beat clobbered a fresh admin re-approval")
	}
}

// If the quarantine cause-row write fails, the node must still be DENIED via the
// admission gate (fail closed) rather than left approved and operational.
func TestQuarantineWriteFailureFailsClosed(t *testing.T) {
	srv := newContinuousAuthzServer(t)
	const ws, node = "ws-1", "node-d2"
	putApprovedNode(t, srv, ws, node, PlatformRecord{OS: "linux", Arch: "amd64"})
	good, bad := driftHash("good"), driftHash("bad")
	srv.evaluateBinaryDrift(ws, node, good) // pin (real store)
	srv.store = &faultyStore{Store: srv.store, failQuarantineNode: true}
	srv.evaluateBinaryDrift(ws, node, bad) // drift → QuarantineNode fails → defensive deny
	if mustNode(t, srv, ws, node).Approved {
		t.Fatal("a failed quarantine write must still deny the node (fail closed)")
	}
}

// A deny through the shared admission entrypoint (used by BOTH gRPC and console)
// writes the quarantine cause-row WITH host evidence and revokes sessions; a
// re-approval of a quarantined node requires a recorded reason.
func TestApproveNodeWithReasonParity(t *testing.T) {
	srv := newContinuousAuthzServer(t)
	const ws, node, sid = "ws-1", "node-d6", "sess-d6"
	putApprovedNode(t, srv, ws, node, PlatformRecord{OS: "linux", Arch: "amd64", HostUUID: "uuid-d6"})
	putActiveSession(t, srv, ws, node, sid)

	if err := srv.approveNodeWithReason(ws, mustNode(t, srv, ws, node), false, "suspected compromise", "console:bob"); err != nil {
		t.Fatalf("deny: %v", err)
	}
	q, err := srv.store.GetQuarantine(ws, node)
	if err != nil || q.Reason != "suspected compromise" || q.HostUUID != "uuid-d6" {
		t.Fatalf("console deny must write a cause-row with host evidence: %+v err=%v", q, err)
	}
	if s, _ := srv.store.GetSession(ws, sid); s.State != SessionRevoked {
		t.Fatal("console deny must revoke live sessions immediately")
	}
	if err := srv.approveNodeWithReason(ws, mustNode(t, srv, ws, node), true, "", "console:bob"); !errors.Is(err, errReasonRequired) {
		t.Fatalf("re-approval of a quarantined node without a reason must be rejected, got %v", err)
	}
	if err := srv.approveNodeWithReason(ws, mustNode(t, srv, ws, node), true, "cleared after review", "console:bob"); err != nil {
		t.Fatalf("re-approval with reason: %v", err)
	}
	if _, err := srv.store.GetQuarantine(ws, node); err == nil {
		t.Fatal("re-approval must clear the quarantine record")
	}
}

// When the re-enroll quarantine lookup ERRORS (store blip), a host requesting
// auto-approve must land PENDING, not be auto-approved (fail closed).
func TestEnrollQuarantineLookupFailsClosed(t *testing.T) {
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.store = &faultyStore{Store: srv.store, failFindQuarantine: true}
	admin := &workspaceAPIService{s: srv}
	enroll := &enrollmentService{s: srv}

	tok, err := admin.CreateJoinToken(adminWSCtx(), &genezav1.CreateJoinTokenRequest{AutoApprove: true})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ca.GenerateKey()
	csr, _ := ca.MakeCSR(key, "node")
	resp, err := enroll.Enroll(context.Background(), &genezav1.EnrollRequest{
		Provider: "token", Token: tok.Token, CsrPem: csr,
		NoiseStaticPub: make([]byte, 32),
		Platform:       &genezav1.PlatformInfo{Hostname: "h", HostUuid: "uuid-blip"},
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	n := mustNode(t, srv, defaultWorkspace, resp.NodeId)
	if n.Approved {
		t.Fatal("an auto-approve enroll whose quarantine lookup errored must land PENDING (fail closed)")
	}
}

// The clone-detection snapshot must be race-free under a concurrently-updating
// displaced handle. Run under -race; the assertion is simply that no torn read or
// data race occurs while both sides run.
func TestCloneSnapshotRaceFree(t *testing.T) {
	h := &agentHandle{nodeID: "n", waiters: map[string]chan *genezav1.SessionOfferAck{}}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 5000; i++ {
			h.setObservedIP("10.0.0.1")
			h.updateInfo(func(in *AgentInfo) { in.LastSeen = time.Now() })
		}
		close(done)
	}()
	for i := 0; i < 5000; i++ {
		ip, ls := h.cloneSnapshot()
		_ = ip
		_ = ls
	}
	<-done
}
