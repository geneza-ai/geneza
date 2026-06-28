package controller

import (
	"testing"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// drainNoticeOf returns the DrainNotice carried by a captured DiscoMsg, or nil.
func drainNoticeOf(d *genezav1.DiscoMsg) *genezav1.DrainNotice { return d.GetDrainNotice() }

// When a relay is marked draining, the controller pushes a DrainNotice carrying that
// relay's id to every live session over the already-open signaling channel — the
// agent over its disco path and the client over its SessionSignal stream. The
// endpoints self-filter by the relay they are actually on; the controller broadcasts.
func TestNotifyRelayDrainingPushesNotice(t *testing.T) {
	srv := newContinuousAuthzServer(t)
	const ws, node, sid = "ws-1", "node-A", "sess-A"

	// One live session: its agent holds a control stream, and a client SessionSignal
	// entry is registered (so both ends are reachable for the push).
	putActiveSession(t, srv, ws, node, sid)
	dc := &discoCapture{}
	srv.registry.Register(node, dc, &genezav1.AgentHello{})
	srv.sessionSignals.register(sid, ws, node, true, "alice", "subj-alice", "oidc")

	srv.notifyRelayDraining("relay-DRAIN", "10.0.0.5:7403")

	// Agent end: a session-keyed DrainNotice DiscoMsg for the draining relay.
	var agentNotice *genezav1.DrainNotice
	for _, d := range dc.discos() {
		if dn := drainNoticeOf(d); dn != nil {
			if d.GetSessionId() != sid {
				t.Fatalf("drain notice not session-keyed: %q", d.GetSessionId())
			}
			agentNotice = dn
		}
	}
	if agentNotice == nil {
		t.Fatal("no DrainNotice pushed to the agent")
	}
	if agentNotice.GetDrainingRelayId() != "relay-DRAIN" {
		t.Fatalf("agent notice relay id = %q, want relay-DRAIN", agentNotice.GetDrainingRelayId())
	}

	// Client end: a ControllerSignal carrying the same DrainNotice, delivered to the
	// session's SessionSignal buffer.
	e := srv.sessionSignals.get(sid)
	select {
	case gsig := <-e.toClient:
		if dn := gsig.GetDrainNotice(); dn == nil || dn.GetDrainingRelayId() != "relay-DRAIN" {
			t.Fatalf("client ControllerSignal drain notice = %v, want relay-DRAIN", dn)
		}
	default:
		t.Fatal("no DrainNotice delivered to the client SessionSignal stream")
	}
}

// A drain notice is pushed only for LIVE sessions, and never carries an empty relay
// id (which an endpoint could not filter on). A non-live (ended) session gets none.
func TestNotifyRelayDrainingSkipsNonLiveAndEmpty(t *testing.T) {
	srv := newContinuousAuthzServer(t)
	const ws, node = "ws-1", "node-B"

	// An ENDED session must not be notified.
	if err := srv.store.PutSession(ws, &SessionRecord{
		ID: "sess-ended", NodeID: node, User: "alice", Action: "shell", State: SessionEnded,
	}); err != nil {
		t.Fatalf("put session: %v", err)
	}
	dc := &discoCapture{}
	srv.registry.Register(node, dc, &genezav1.AgentHello{})

	srv.notifyRelayDraining("relay-DRAIN", "10.0.0.5:7403")
	for _, d := range dc.discos() {
		if d.GetDrainNotice() != nil {
			t.Fatal("an ended session must not receive a drain notice")
		}
	}

	// An empty relay id is a no-op (nothing to filter on).
	putActiveSession(t, srv, ws, node, "sess-live")
	srv.notifyRelayDraining("", "")
	for _, d := range dc.discos() {
		if d.GetDrainNotice() != nil {
			t.Fatal("an empty draining relay id must push nothing")
		}
	}
}
