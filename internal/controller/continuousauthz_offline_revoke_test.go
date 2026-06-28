package controller

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// captureSender is a fake agent control stream: it records pushed SessionRevoke
// ids and can be flipped to fail Send (a transient stream error).
type captureSender struct {
	mu      sync.Mutex
	revokes []string
	failAll bool
}

func (c *captureSender) Send(m *genezav1.ControllerMsg) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failAll {
		return errSendFail
	}
	if r := m.GetSessionRevoke(); r != nil {
		c.revokes = append(c.revokes, r.GetSessionId())
	}
	return nil
}

func (c *captureSender) got() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.revokes...)
}

type sendErr struct{}

func (sendErr) Error() string { return "send failed" }

var errSendFail = sendErr{}

func newContinuousAuthzServer(t *testing.T) *Server {
	t.Helper()
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatalf("init: %v", err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func putActiveSession(t *testing.T, srv *Server, ws, node, id string) {
	t.Helper()
	if err := srv.store.PutSession(ws, &SessionRecord{
		ID: id, NodeID: node, User: "alice", Action: "shell",
		State: SessionActive, StartedUnix: time.Now().Unix(),
	}); err != nil {
		t.Fatalf("put session: %v", err)
	}
}

// lastAudit returns the detail map of the most recent audit event of a type, and
// whether any exists.
func lastAudit(t *testing.T, srv *Server, typ string) (map[string]string, bool) {
	t.Helper()
	lines, ok, err := srv.audit.Query(0, typ, "", 100)
	if err != nil || !ok {
		t.Fatalf("audit query %s: ok=%v err=%v", typ, ok, err)
	}
	if len(lines) == 0 {
		return nil, false
	}
	var ev AuditEvent
	if err := json.Unmarshal(lines[len(lines)-1], &ev); err != nil {
		t.Fatalf("unmarshal audit: %v", err)
	}
	return ev.Detail, true
}

// ackRevoke drives the real agent->controller path: a "revoked" SessionEvent the
// agent emits after tearing the session down (its delivery confirmation).
func ackRevoke(srv *Server, ws, node, id string) {
	nc := &nodeControlService{s: srv}
	nc.handleSessionEvent(ws, node, &genezav1.SessionEvent{SessionId: id, Event: "revoked", Detail: "policy denied"})
}

// A session revoked while its agent is OFFLINE must NOT be silently lost —
// it stays owed (RevokeDelivered=false), is redelivered when the agent
// reconnects, and is only marked delivered when the AGENT acks (a "revoked"
// event), never on a bare Send. The session-host outlives the agent stream so
// the PTY is not actually gone until that ack lands.
func TestRevokeOfflineThenReattachAndAck(t *testing.T) {
	srv := newContinuousAuthzServer(t)
	const ws, node, sid = "ws-1", "node-A", "sess-A"
	putActiveSession(t, srv, ws, node, sid)

	// Agent offline: no handle registered.
	rec, _ := srv.store.GetSession(ws, sid)
	if err := srv.revokeSession(rec, "policy denied"); err != nil {
		t.Fatalf("revokeSession: %v", err)
	}
	got, _ := srv.store.GetSession(ws, sid)
	if got.State != SessionRevoked {
		t.Fatalf("state = %q, want revoked", got.State)
	}
	if got.RevokeDelivered {
		t.Fatal("revoke marked delivered before any agent ack — offline revoke would be silently lost")
	}
	if got.RevokeReason != "policy denied" {
		t.Fatalf("reason not persisted: %q", got.RevokeReason)
	}
	if d, ok := lastAudit(t, srv, "session_revoked"); !ok || d["pushed"] != "false" {
		t.Fatalf("offline revoke must audit pushed=false, got ok=%v detail=%v", ok, d)
	}

	// Agent reconnects → owed teardown is re-pushed (but not yet confirmed).
	cs := &captureSender{}
	srv.registry.Register(node, cs, &genezav1.AgentHello{})
	srv.redeliverPendingRevokes(node)
	if g := cs.got(); len(g) != 1 || g[0] != sid {
		t.Fatalf("reattach did not re-push revoke: %v", g)
	}
	if mid, _ := srv.store.GetSession(ws, sid); mid.RevokeDelivered {
		t.Fatal("marked delivered on re-push alone — must await agent ack")
	}

	// Agent acks (it killed the host session) → now confirmed.
	ackRevoke(srv, ws, node, sid)
	after, _ := srv.store.GetSession(ws, sid)
	if !after.RevokeDelivered {
		t.Fatal("revoke not confirmed after agent ack")
	}
	if _, ok := lastAudit(t, srv, "session_revoke_confirmed"); !ok {
		t.Fatal("confirmation not audited")
	}
}

// Online: the revoke is pushed immediately (audited pushed=true) but delivery is
// confirmed only by the agent ack — a bare Send is never trusted as delivery.
func TestOnlinePushIsNotDeliveryUntilAck(t *testing.T) {
	srv := newContinuousAuthzServer(t)
	const ws, node, sid = "ws-1", "node-B", "sess-B"
	putActiveSession(t, srv, ws, node, sid)

	cs := &captureSender{}
	srv.registry.Register(node, cs, &genezav1.AgentHello{})

	rec, _ := srv.store.GetSession(ws, sid)
	if err := srv.revokeSession(rec, "kicked"); err != nil {
		t.Fatalf("revokeSession: %v", err)
	}
	if g := cs.got(); len(g) != 1 || g[0] != sid {
		t.Fatalf("online revoke not pushed: %v", g)
	}
	if d, _ := lastAudit(t, srv, "session_revoked"); d["pushed"] != "true" {
		t.Fatalf("online revoke must audit pushed=true, got %v", d)
	}
	if got, _ := srv.store.GetSession(ws, sid); got.RevokeDelivered {
		t.Fatal("Send treated as delivery without an agent ack — dying-stream false positive")
	}

	ackRevoke(srv, ws, node, sid)
	if got, _ := srv.store.GetSession(ws, sid); !got.RevokeDelivered {
		t.Fatal("not confirmed after ack")
	}
}

// The sweep re-pushes an owed (unconfirmed) revoke every tick while the node is
// online, until the agent acks — so a push lost to a dying stream is retried.
func TestSweepRePushesUntilAck(t *testing.T) {
	srv := newContinuousAuthzServer(t)
	const ws, node, sid = "ws-1", "node-C", "sess-C"
	putActiveSession(t, srv, ws, node, sid)

	cs := &captureSender{}
	srv.registry.Register(node, cs, &genezav1.AgentHello{})

	rec, _ := srv.store.GetSession(ws, sid)
	if err := srv.revokeSession(rec, "policy denied"); err != nil {
		t.Fatalf("revokeSession: %v", err)
	}
	srv.reauthSweep() // unconfirmed + online → re-push
	if g := cs.got(); len(g) != 2 {
		t.Fatalf("sweep should re-push owed revoke: pushes=%v", g)
	}

	// Once the agent acks, the sweep stops re-pushing.
	ackRevoke(srv, ws, node, sid)
	srv.reauthSweep()
	if g := cs.got(); len(g) != 2 {
		t.Fatalf("sweep re-pushed a confirmed revoke: pushes=%v", g)
	}
}

// An offline node is NOT re-pushed by the sweep (no live stream); reconnect is
// what redelivers — so the sweep does not churn on a permanently-gone node.
func TestSweepSkipsOfflineNode(t *testing.T) {
	srv := newContinuousAuthzServer(t)
	const ws, node, sid = "ws-1", "node-D", "sess-D"
	putActiveSession(t, srv, ws, node, sid)

	rec, _ := srv.store.GetSession(ws, sid)
	if err := srv.revokeSession(rec, "policy denied"); err != nil {
		t.Fatalf("revokeSession: %v", err)
	}
	srv.reauthSweep() // node offline → no panic, no push, stays owed
	if got, _ := srv.store.GetSession(ws, sid); got.RevokeDelivered {
		t.Fatal("offline node revoke wrongly marked delivered")
	}
}
