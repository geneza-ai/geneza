package controller

import (
	"sync"
	"testing"
	"time"

	"geneza.io/internal/ca"
	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// discoCapture is a fake agent control stream that records pushed DiscoMsgs.
type discoCapture struct {
	mu   sync.Mutex
	msgs []*genezav1.DiscoMsg
}

func (d *discoCapture) Send(m *genezav1.ControllerMsg) error {
	if disco := m.GetDisco(); disco != nil {
		d.mu.Lock()
		d.msgs = append(d.msgs, disco)
		d.mu.Unlock()
	}
	return nil
}

func (d *discoCapture) discos() []*genezav1.DiscoMsg {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]*genezav1.DiscoMsg(nil), d.msgs...)
}

// The controller forwards session-scoped ICE signaling ONLY between the two
// principals named in the brokered grant, keyed by session_id — a different
// principal, a different workspace, or a foreign node must all be rejected.
func TestSessionSignalForwarding(t *testing.T) {
	srv := newContinuousAuthzServer(t)
	const ws, node, sid = "ws-1", "node-X", "sess-X"
	srv.sessionSignals.register(sid, ws, node, true, "alice", "subj-alice", "oidc")
	e := srv.sessionSignals.get(sid)
	if e == nil {
		t.Fatal("entry not registered")
	}

	// Principal check (authorizes).
	creator := &ca.Identity{Workspace: ws, Name: "alice", Subject: "subj-alice", Provider: "oidc"}
	if !e.authorizes(creator) {
		t.Fatal("the grant's creator must be authorized")
	}
	if e.authorizes(&ca.Identity{Workspace: ws, Name: "bob", Subject: "subj-bob", Provider: "oidc"}) {
		t.Fatal("a different principal must be rejected")
	}
	if e.authorizes(&ca.Identity{Workspace: "other-ws", Name: "alice", Subject: "subj-alice", Provider: "oidc"}) {
		t.Fatal("a cross-workspace caller must be rejected")
	}
	// Fail-closed: a subject-LESS caller must NOT match a subject-bearing login
	// creator via the mutable username (no name fallback for keyable creators).
	if e.authorizes(&ca.Identity{Workspace: ws, Name: "alice", Subject: "", Provider: "breakglass"}) {
		t.Fatal("an empty-subject caller matched a subject-bearing creator via name")
	}
	if e.authorizes(&ca.Identity{Workspace: ws, Name: "alice", Subject: "subj-alice", Provider: "local"}) {
		t.Fatal("a matching subject under a DIFFERENT provider must be rejected")
	}

	// client -> agent: creds + each candidate become session-keyed DiscoMsgs.
	dc := &discoCapture{}
	srv.registry.Register(node, dc, &genezav1.AgentHello{})
	srv.forwardClientSignalToAgent(e, sid, &genezav1.ClientSignal{
		SessionId:  sid,
		IceCreds:   &genezav1.IceCreds{Ufrag: "c-uf", Pwd: "c-pw"},
		Candidates: []string{"cand-1", "cand-2"},
	})
	got := dc.discos()
	if len(got) != 3 {
		t.Fatalf("want 1 creds + 2 candidate DiscoMsgs, got %d", len(got))
	}
	for _, d := range got {
		if d.GetSessionId() != sid {
			t.Fatalf("forwarded DiscoMsg not session-keyed: %q", d.GetSessionId())
		}
		if d.GetVni() != 0 {
			t.Fatal("session signaling must use vni=0 (not the overlay path)")
		}
	}
	if c := got[0].GetIceCreds(); c == nil || c.GetUfrag() != "c-uf" {
		t.Fatalf("first DiscoMsg must carry the client creds, got %v", got[0].GetBody())
	}

	// agent -> client: delivered to the SessionSignal buffer with the client role.
	srv.forwardAgentSignalToClient(ws, node, sid, &genezav1.DiscoMsg{
		SessionId: sid,
		Body:      &genezav1.DiscoMsg_IceCreds{IceCreds: &genezav1.IceCreds{Ufrag: "a-uf", Pwd: "a-pw"}},
	})
	select {
	case gsig := <-e.toClient:
		if gsig.GetIceCreds().GetUfrag() != "a-uf" {
			t.Fatalf("agent creds not delivered, got %v", gsig.GetIceCreds())
		}
		if !gsig.GetControlling() {
			t.Fatal("the client's controller-assigned ICE role must be propagated")
		}
	default:
		t.Fatal("agent signal was not delivered to the client")
	}

	// Anti-forgery: a DIFFERENT node must not inject signaling into this session.
	srv.forwardAgentSignalToClient(ws, "node-evil", sid, &genezav1.DiscoMsg{
		SessionId: sid,
		Body:      &genezav1.DiscoMsg_IceCreds{IceCreds: &genezav1.IceCreds{Ufrag: "evil"}},
	})
	select {
	case <-e.toClient:
		t.Fatal("a foreign node injected session signaling (cross-session signaling isolation breach)")
	default:
	}

	// A second client cannot attach to the same session's signaling.
	if !e.attach() {
		t.Fatal("first attach should succeed")
	}
	if e.attach() {
		t.Fatal("a second concurrent client must be refused")
	}
	e.detach()
	if !e.attach() {
		t.Fatal("attach should succeed again after detach")
	}

	// Teardown closes done (an attached stream returns) and removes the entry.
	srv.sessionSignals.unregister(sid)
	select {
	case <-e.done:
	default:
		t.Fatal("unregister must close the entry's done channel")
	}
	if srv.sessionSignals.get(sid) != nil {
		t.Fatal("entry must be gone after unregister")
	}
}

// An entry past its TTL is reaped on access and by the sweep, with its done
// closed so any attached stream returns.
func TestSessionSignalEntryExpiry(t *testing.T) {
	srv := newContinuousAuthzServer(t)
	const ws, node, sid = "ws-1", "node-Y", "sess-Y"
	srv.sessionSignals.register(sid, ws, node, true, "alice", "subj-alice", "oidc")
	e := srv.sessionSignals.get(sid)
	if e == nil {
		t.Fatal("entry should be live right after register")
	}
	// Force expiry.
	srv.sessionSignals.mu.Lock()
	e.expiry = time.Now().Add(-time.Second)
	srv.sessionSignals.mu.Unlock()

	if srv.sessionSignals.get(sid) != nil {
		t.Fatal("get must treat an expired entry as absent (and reap it)")
	}
	select {
	case <-e.done:
	default:
		t.Fatal("reaping an expired entry must close its done channel")
	}
}
