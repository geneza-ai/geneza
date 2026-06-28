package agentd

import (
	"context"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"time"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

// rehome.go is the agent side of IN-SESSION relay re-home. When the relay a LIVE
// session is using drains or dies, the session migrates to a surviving relay under
// the SAME session id, rather than being torn down. A detachable shell re-attaches
// its persisted host PTY seamlessly; other actions reconnect-fast (the transport
// rebuilds, the action re-runs). A genuine session end — a revoke, a lease
// starvation, an explicit detach, a clean exit — still tears down: the lease is the
// arbiter, never the relay.

const (
	// maxRehomeAttempts bounds a single re-home burst so a genuinely-dead peer or an
	// exhausted fleet eventually tears the session down instead of looping forever.
	maxRehomeAttempts = 6
	// rehomeBackoffHi caps the full-jitter backoff between attempts, mirroring the
	// relay registrar's de-correlation of a fleet re-homing onto a survivor at once.
	rehomeBackoffHi = 8 * time.Second
	// rehomeWait bounds how long the agent waits for the controller's fresh grant after
	// it requests a re-home; past it the attempt is spent (backoff, then retry).
	rehomeWait = 20 * time.Second
)

// serveWithRehome serves the session over its current transport and, when the
// transport drops while the session is still authorized (lease fresh) and budget
// remains, re-homes it onto a surviving relay under the same session id. It owns the
// raw transport's lifecycle across every generation. The first transport is passed
// in already established; subsequent generations are rebuilt from a fresh
// controller-issued grant.
func (w *Worker) serveWithRehome(ctx context.Context, grant *types.SessionGrant, sig *sessionSignaler, raw, tconn net.Conn, log *slog.Logger) {
	attempts := 0
	appliedEpoch := int64(0)
	deadRelayID, deadRelayAddr := relayInUse(grant)

	// Proactive drain: the controller pushes a drain notice naming a relay it is draining;
	// when that is the relay THIS session is currently on, drop the transport at once so
	// the session migrates onto a survivor immediately — rather than waiting for the
	// draining relay to force-close the splice at its deadline. The handler is registered
	// for the whole session (every generation) and reads the CURRENT generation's relay +
	// transport-canceller under genMu; it rides the SAME path a real transport loss takes,
	// so the recovery is whatever the session already uses (agent in-session re-home for a
	// p2p session, client reattach for a detachable relay-TCP shell). The lease still gates
	// whether the resulting drop re-homes or ends.
	var (
		genMu      sync.Mutex
		curGcancel context.CancelFunc
	)
	w.registerDrainTrigger(grant.ID, func(relayID, relayAddr string) {
		genMu.Lock()
		hit := drainNoticeHitsSession(drainNotice{relayID: relayID, relayAddr: relayAddr}, deadRelayID, deadRelayAddr)
		cancel := curGcancel
		genMu.Unlock()
		if hit && cancel != nil {
			log.Info("relay draining; dropping transport to migrate session", "relay", relayID, "addr", relayAddr)
			cancel() // closes the current transport -> the session's recovery takes over
		}
	})
	defer w.unregisterDrainTrigger(grant.ID)

	for {
		end := &terminalEvent{w: w, sessionID: grant.ID}
		// Re-home is viable only while the session is still authorized: the lease is
		// the single arbiter, so a relay can neither prevent teardown (the lease timer
		// fires independently) nor extend a revoked session (the controller re-issue
		// refuses a lapsed/ended record). A re-home that is in flight also caps the
		// burst, so a flapping relay cannot spin the loop without bound.
		end.rehomePending = func() bool {
			return ctx.Err() == nil && attempts < maxRehomeAttempts && w.leaseFresh(grant.ID)
		}

		// Tear the current transport when the surrounding session context ends
		// (worker shutdown / explicit revoke), unblocking the SSH/VPN serve.
		gctx, gcancel := context.WithCancel(ctx)
		go func() { <-gctx.Done(); _ = tconn.Close() }()
		// Publish this generation's relay + canceller so the drain trigger acts on the
		// transport actually in use right now.
		genMu.Lock()
		curGcancel = gcancel
		genMu.Unlock()

		if grant.Action == types.ActionVPN {
			w.serveVPN(gctx, tconn, grant, log, end)
		} else {
			w.serveSSH(gctx, tconn, grant, log, end)
		}
		gcancel()
		_ = raw.Close()

		// A re-home was suppressed (a transport loss with the lease still fresh): try
		// to migrate. Anything else — a clean exit, an intentional detach, a revoke, a
		// lease starvation — is terminal and already emitted (or will be by the defer).
		if !end.transportLost {
			if !end.emitted {
				end.emit("ended", "tunnel closed", "", 0)
			}
			return
		}
		// A detachable shell whose re-home exhausts is left DETACHED, not ended: its
		// host PTY survives for a later manual reattach.
		exhaustedEvent := "ended"
		if grant.AllowDetach {
			exhaustedEvent = "detached"
		}

		// Bounded full-jitter backoff so a drained relay does not stampede every
		// session it carried onto the one survivor at the same instant.
		attempts++
		backoff := time.Duration(1<<uint(min(attempts, 3))) * time.Second
		if backoff > rehomeBackoffHi {
			backoff = rehomeBackoffHi
		}
		select {
		case <-ctx.Done():
			w.emitEvent(&genezav1.SessionEvent{SessionId: grant.ID, Event: "ended", Detail: "session closed"})
			return
		case <-time.After(time.Duration(rand.Int63n(int64(backoff) + 1))):
		}
		if ctx.Err() != nil || !w.leaseFresh(grant.ID) {
			w.emitEvent(&genezav1.SessionEvent{SessionId: grant.ID, Event: exhaustedEvent, Detail: "relay path lost"})
			return
		}

		log.Warn("relay path lost; re-homing session", "attempt", attempts, "dead_relay", deadRelayID)
		next, nextTurn, ok := w.requestRehome(ctx, grant.ID, sig, deadRelayID, deadRelayAddr, appliedEpoch, log)
		if !ok {
			if attempts >= maxRehomeAttempts {
				w.emitEvent(&genezav1.SessionEvent{SessionId: grant.ID, Event: exhaustedEvent, Detail: "re-home exhausted"})
				return
			}
			continue // budget left: another transport-loss generation may carry it
		}
		appliedEpoch = next.epoch

		nraw, ntconn, path, err := w.establishTunnel(ctx, next.grant, nextTurn, sig, log)
		if err != nil {
			log.Warn("re-home transport failed", "attempt", attempts, "err", err)
			if attempts >= maxRehomeAttempts {
				w.emitEvent(&genezav1.SessionEvent{SessionId: grant.ID, Event: exhaustedEvent, Detail: "re-home transport: " + err.Error()})
				return
			}
			continue
		}
		// The migrated transport is live: swap it in, refresh the enforcement state's
		// grant (the scope is unchanged but the relay coordinates are new), reset the
		// attempt budget, and serve the next generation.
		raw, tconn = nraw, ntconn
		grant = next.grant
		genMu.Lock()
		deadRelayID, deadRelayAddr = relayInUse(grant)
		genMu.Unlock()
		w.refreshLiveGrant(grant.ID, grant, path)
		attempts = 0
		w.emitEvent(&genezav1.SessionEvent{SessionId: grant.ID, Event: "established", PathClass: path, Detail: "re-homed"})
		log.Info("session re-homed", "path", path)
	}
}

// drainNoticeHitsSession reports whether a controller drain notice applies to a session
// currently using (currentRelayID, currentRelayAddr): it matches when the drained relay
// is the one in use, by id (a session p2p endpoint) OR by TCP rendezvous addr (a
// relay-TCP-floor endpoint, which knows its relay only by addr). A notice for any other
// relay — or one whose fields are both empty / unknown to this session — is ignored, so
// the proactive re-home migrates ONLY the sessions actually on the draining relay.
func drainNoticeHitsSession(dn drainNotice, currentRelayID, currentRelayAddr string) bool {
	if dn.relayID != "" && currentRelayID != "" && dn.relayID == currentRelayID {
		return true
	}
	if dn.relayAddr != "" && currentRelayAddr != "" && dn.relayAddr == currentRelayAddr {
		return true
	}
	return false
}

// rehomeGrant is a verified, re-issued grant ready to rebuild the transport on.
type rehomeGrant struct {
	epoch int64
	grant *types.SessionGrant
}

// requestRehome asks the controller to re-issue this session onto a surviving relay
// and waits for the fresh grant, which it re-EvaluateOffers (a re-home is never a
// "trust the controller" shortcut: the scoped-grant floor, node + noise-key binding,
// and policy ceiling all re-run). It returns the verified grant and this end's TURN
// creds, or ok=false on timeout / a declined or invalid re-issue.
func (w *Worker) requestRehome(ctx context.Context, sessionID string, sig *sessionSignaler, deadRelayID, deadRelayAddr string, appliedEpoch int64, log *slog.Logger) (rehomeGrant, *genezav1.TurnCreds, bool) {
	if sig == nil {
		return rehomeGrant{}, nil, false // relay-only session with no signaling channel
	}
	// Drain any stale re-home the loop has not consumed, so the wait below observes
	// only the response to THIS request.
	select {
	case <-sig.rehome:
	default:
	}
	w.enqueue(&genezav1.AgentMsg{Msg: &genezav1.AgentMsg_Disco{Disco: &genezav1.DiscoMsg{
		SessionId: sessionID, Vni: 0,
		Body: &genezav1.DiscoMsg_RehomeRequest{RehomeRequest: &genezav1.RehomeRequest{
			SessionId: sessionID, DeadRelayId: deadRelayID, DeadRelayAddr: deadRelayAddr,
			AppliedEpoch: appliedEpoch,
		}},
	}}})

	wait, cancel := context.WithTimeout(ctx, rehomeWait)
	defer cancel()
	for {
		select {
		case <-wait.Done():
			return rehomeGrant{}, nil, false
		case r := <-sig.rehome:
			if r.GetEpoch() <= appliedEpoch {
				continue // a duplicate or out-of-order push; keep waiting for the fresh one
			}
			grant, err := w.evaluateRehome(sessionID, r)
			if err != nil {
				log.Warn("re-home grant rejected", "session", sessionID, "err", err)
				return rehomeGrant{}, nil, false
			}
			return rehomeGrant{epoch: r.GetEpoch(), grant: grant}, r.GetTurn(), true
		}
	}
}

// evaluateRehome runs the full agent-side authorization gate on a re-issued grant —
// the same gate the initial offer faces — and asserts it is for THIS session id.
func (w *Worker) evaluateRehome(sessionID string, r *genezav1.SessionRehome) (*types.SessionGrant, error) {
	grant, err := EvaluateOffer(r.GetSignedGrant(), w.trustedKeys(), w.keyScopes(), w.st.Workspace(),
		w.st.NodeID, w.st.Noise.Public, w.agentPolicy(), time.Now())
	if err != nil {
		return nil, err
	}
	if grant.ID != sessionID {
		return nil, errRehomeSessionMismatch
	}
	return grant, nil
}

var errRehomeSessionMismatch = sessionError("re-home grant is for a different session")

type sessionError string

func (e sessionError) Error() string { return string(e) }

// relayInUse names the relay a grant's session is using, so a subsequent re-home
// excludes it. It is the floor's first entry (the relay the rendezvous prefers) and
// the first candidate's id; empty when no relay info is present (host-only tests).
func relayInUse(grant *types.SessionGrant) (relayID, relayAddr string) {
	if len(grant.RelayFloor) > 0 {
		relayAddr = grant.RelayFloor[0]
	} else {
		relayAddr = grant.RelayAddr
	}
	if len(grant.RelayCandidates) > 0 {
		relayID = grant.RelayCandidates[0].RelayID
	}
	return relayID, relayAddr
}

// leaseFresh reports whether the session's continuous-authz lease is still within
// its deadline — the arbiter that distinguishes a re-homeable transport loss from a
// genuine end (a starved or revoked session is never re-homed).
func (w *Worker) leaseFresh(id string) bool {
	w.liveMu.Lock()
	ls := w.live[id]
	w.liveMu.Unlock()
	if ls == nil {
		return false
	}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	// A zero deadline is the initial grace before the first lease lands; treat it as
	// fresh so a relay that dies in the first seconds still re-homes.
	return ls.leaseDeadline.IsZero() || time.Now().Before(ls.leaseDeadline)
}

// refreshLiveGrant swaps the enforcement state's grant + path class for a re-homed
// session without disturbing its lease/epoch/caps — the session id, lease chain, and
// continuous-authz continue uninterrupted across the relay migration.
func (w *Worker) refreshLiveGrant(id string, grant *types.SessionGrant, path string) {
	w.liveMu.Lock()
	defer w.liveMu.Unlock()
	if ls := w.live[id]; ls != nil {
		ls.grant = grant
		ls.pathClass = path
		ls.clientNoisePub = grant.ClientNoisePub
	}
}

