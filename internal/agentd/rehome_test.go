package agentd

import (
	"io"
	"log/slog"
	"testing"
	"time"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

func rehomeTestWorker() *Worker {
	return &Worker{
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		events: make(chan *genezav1.AgentMsg, 64),
	}
}

func (w *Worker) drainEvents(id string) []*genezav1.SessionEvent {
	var out []*genezav1.SessionEvent
	for {
		select {
		case m := <-w.events:
			if ev := m.GetSessionEvent(); ev != nil && ev.GetSessionId() == id {
				out = append(out, ev)
			}
		default:
			return out
		}
	}
}

func TestIsTransportLossDetail(t *testing.T) {
	loss := []string{"tunnel closed", "session host stream lost", "client disconnected", "ssh handshake: eof"}
	for _, d := range loss {
		if !isTransportLossDetail(d) {
			t.Fatalf("%q should be a transport loss", d)
		}
	}
	notLoss := []string{"", "exec command mismatch", "max session ttl", "vpn: no routes"}
	for _, d := range notLoss {
		if isTransportLossDetail(d) {
			t.Fatalf("%q must not be treated as a transport loss", d)
		}
	}
}

// TestTerminalEventRehomeArbitration is the heart of the teardown-vs-rehome
// arbitration: a transport-loss terminal is SUPPRESSED (re-home wins) while a
// re-home is viable, but emitted (teardown wins) once it is not — and a non-loss
// terminal (a clean exit, a revoke) always emits regardless.
func TestTerminalEventRehomeArbitration(t *testing.T) {
	w := rehomeTestWorker()

	// 1. Transport loss while re-home is viable -> suppressed, transportLost set.
	viable := &terminalEvent{w: w, sessionID: "s1", rehomePending: func() bool { return true }}
	viable.emit("ended", "tunnel closed", "h1", -1)
	if viable.emitted {
		t.Fatal("a transport loss must be suppressed while re-home is viable")
	}
	if !viable.transportLost {
		t.Fatal("transportLost must be set so the loop re-homes")
	}
	if evs := w.drainEvents("s1"); len(evs) != 0 {
		t.Fatalf("no event must be emitted on a suppressed loss, got %v", evs)
	}

	// 2. Transport loss when re-home is NOT viable (lease starved / budget spent) ->
	//    emitted as a genuine teardown.
	dead := &terminalEvent{w: w, sessionID: "s2", rehomePending: func() bool { return false }}
	dead.emit("ended", "tunnel closed", "h2", -1)
	if !dead.emitted {
		t.Fatal("a transport loss with no viable re-home must emit a terminal")
	}
	if evs := w.drainEvents("s2"); len(evs) != 1 || evs[0].GetEvent() != "ended" {
		t.Fatalf("want one ended event, got %v", evs)
	}

	// 3. A genuine end (a clean exit) ALWAYS emits, even mid-re-home-window: a
	//    non-transport-loss detail is never a re-home.
	exited := &terminalEvent{w: w, sessionID: "s3", rehomePending: func() bool { return true }}
	exited.emit("ended", "", "h3", 0)
	if !exited.emitted || exited.transportLost {
		t.Fatal("a clean exit must emit (teardown), never be treated as a re-home")
	}
	if evs := w.drainEvents("s3"); len(evs) != 1 {
		t.Fatalf("want one ended event for the clean exit, got %v", evs)
	}
}

// A proactive drain notice triggers a re-home ONLY for a session currently on the
// draining relay; a session on a DIFFERENT relay ignores it (no bystander migration).
func TestDrainNoticeHitsSession(t *testing.T) {
	// Match by id (session p2p endpoint knows its relay id).
	if !drainNoticeHitsSession(drainNotice{relayID: "relay-A"}, "relay-A", "") {
		t.Fatal("a session ON the draining relay (by id) must re-home")
	}
	// Match by addr (relay-TCP-floor endpoint knows only its relay addr).
	if !drainNoticeHitsSession(drainNotice{relayAddr: "1.2.3.4:7403"}, "", "1.2.3.4:7403") {
		t.Fatal("a session ON the draining relay (by addr) must re-home")
	}
	// No match: different relay.
	if drainNoticeHitsSession(drainNotice{relayID: "relay-A", relayAddr: "1.2.3.4:7403"}, "relay-B", "9.9.9.9:7403") {
		t.Fatal("a session on a DIFFERENT relay must NOT re-home")
	}
	// No match: empty notice fields or empty current relay.
	if drainNoticeHitsSession(drainNotice{}, "relay-A", "1.2.3.4:7403") {
		t.Fatal("an empty notice must never match")
	}
	if drainNoticeHitsSession(drainNotice{relayID: "relay-A"}, "", "") {
		t.Fatal("a session with no current relay must never match")
	}
}

// A controller DrainNotice routed over the agent's disco path fires the session's drain
// trigger (the per-session handler the re-home loop registers), even for a relay-TCP
// session with NO ICE signaler — the wire the proactive hint rides.
func TestHandleDiscoRoutesDrainNotice(t *testing.T) {
	w := rehomeTestWorker()
	const sid = "sess-D"
	gotID, gotAddr := make(chan string, 1), make(chan string, 1)
	w.registerDrainTrigger(sid, func(relayID, relayAddr string) {
		gotID <- relayID
		gotAddr <- relayAddr
	})
	defer w.unregisterDrainTrigger(sid)

	// No ICE signaler is registered (a relay-TCP session): the notice must STILL route.
	w.handleDisco(&genezav1.DiscoMsg{
		SessionId: sid,
		Body: &genezav1.DiscoMsg_DrainNotice{DrainNotice: &genezav1.DrainNotice{
			SessionId: sid, DrainingRelayId: "relay-A", DrainingRelayAddr: "1.2.3.4:7403",
		}},
	})
	select {
	case id := <-gotID:
		if id != "relay-A" || <-gotAddr != "1.2.3.4:7403" {
			t.Fatalf("drain trigger got id=%q, want relay-A / 1.2.3.4:7403", id)
		}
	case <-time.After(time.Second):
		t.Fatal("drain notice did not fire the session drain trigger")
	}

	// A notice for an UNregistered session is a harmless no-op (it does not panic).
	w.fireDrainTrigger("unknown-session", "relay-A", "1.2.3.4:7403")
}

// TestLeaseFreshArbiter proves the continuous-authz lease is the re-home arbiter:
// a fresh lease permits re-home; an expired one (a revoked / starved session) does
// not, so a relay can neither extend a revoked session nor block its teardown.
func TestLeaseFreshArbiter(t *testing.T) {
	w := rehomeTestWorker()
	g := testGrant(time.Now())
	w.registerLive(g.ID, func() {}, &g, "relayed")
	defer w.unregisterLive(g.ID)

	// Fresh lease (deadline in the future) -> re-homeable.
	w.armLeaseTimer(g.ID, time.Now().Add(time.Minute).UnixMilli())
	if !w.leaseFresh(g.ID) {
		t.Fatal("a session with a future lease deadline must be re-homeable")
	}
	// Expired lease -> NOT re-homeable (teardown is authoritative).
	w.liveMu.Lock()
	ls := w.live[g.ID]
	w.liveMu.Unlock()
	ls.mu.Lock()
	ls.leaseDeadline = time.Now().Add(-time.Second)
	ls.mu.Unlock()
	if w.leaseFresh(g.ID) {
		t.Fatal("a starved/revoked lease must NOT be re-homeable")
	}
	// An unknown session is never re-homeable.
	if w.leaseFresh("nope") {
		t.Fatal("an unknown session must not be re-homeable")
	}
}

// TestRelayInUse proves a grant's current relay (excluded from the next re-home) is
// read from the floor head + first candidate.
func TestRelayInUse(t *testing.T) {
	g := &types.SessionGrant{
		RelayAddr:       "scalar:7403",
		RelayFloor:      []string{"r1:7403", "r2:7403"},
		RelayCandidates: []types.RelayCandidate{{RelayID: "relay-1"}},
	}
	id, addr := relayInUse(g)
	if addr != "r1:7403" || id != "relay-1" {
		t.Fatalf("relayInUse = %q,%q want r1:7403,relay-1", id, addr)
	}
	// Falls back to the scalar addr when no floor.
	if _, addr := relayInUse(&types.SessionGrant{RelayAddr: "scalar:7403"}); addr != "scalar:7403" {
		t.Fatalf("scalar fallback addr = %q", addr)
	}
}

// TestRefreshLiveGrant proves a re-home swaps the enforcement grant + path without
// disturbing the lease epoch (continuous-authz continues across the migration).
func TestRefreshLiveGrant(t *testing.T) {
	w := rehomeTestWorker()
	g := testGrant(time.Now())
	w.registerLive(g.ID, func() {}, &g, "relayed")
	defer w.unregisterLive(g.ID)
	w.armLeaseTimer(g.ID, time.Now().Add(time.Minute).UnixMilli())

	w.liveMu.Lock()
	w.live[g.ID].mu.Lock()
	w.live[g.ID].epoch = 7
	w.live[g.ID].mu.Unlock()
	w.liveMu.Unlock()

	ng := testGrant(time.Now())
	ng.RelayAddr = "newrelay:7403"
	w.refreshLiveGrant(g.ID, &ng, "direct")

	w.liveMu.Lock()
	ls := w.live[g.ID]
	w.liveMu.Unlock()
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.grant.RelayAddr != "newrelay:7403" || ls.pathClass != "direct" {
		t.Fatalf("grant/path not refreshed: %+v %q", ls.grant.RelayAddr, ls.pathClass)
	}
	if ls.epoch != 7 {
		t.Fatalf("re-home must NOT reset the enforcement epoch: epoch=%d", ls.epoch)
	}
}
