package controller

import (
	"context"
	"log/slog"
	"strings"
	"time"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

// Deny-path doorbell channels. A payload is a version int or a small key — never
// data; the receiver always re-reads the authoritative row (see docs/ha.md).
const (
	chanConfig  = "geneza_config"
	chanSuspend = "geneza_suspend"
	chanLift    = "geneza_lift"
	chanRevoke  = "geneza_revoke"
)

// Per-controller agent-push doorbell ops. A push for an agent held by another controller
// rings that controller's own channel; the owner re-derives the current config (netcfg/
// modcfg) or re-signs a fresh-epoch teardown (revoke) and delivers it on its local
// stream. A lost ring is backstopped by the owner's sweep (revoke) or the agent's
// reconnect reconcile (netcfg/modcfg), so these rings are an unacknowledged best
// effort, never authoritative.
const (
	opNetcfg = "netcfg"
	opModcfg = "modcfg"
	opRevoke = "revoke"
)

// gwChannel is the doorbell channel a controller LISTENs on its own behalf. Channel
// uniqueness is not load-bearing: a receiver re-checks ownership before acting, so a
// stray ring is dropped, not mis-delivered. The owning controller's id keeps it ≤ the
// 63-byte Postgres channel limit (enforced in config validation).
func gwChannel(controllerID string) string { return "geneza_gw_" + controllerID }

const gwNotifyTimeout = 5 * time.Second

// principalSep joins (workspace, provider, subject) into a doorbell payload; the
// unit separator cannot appear in those identity fields.
const principalSep = "\x1f"

func encPrincipal(ws, provider, subject string) string {
	return ws + principalSep + provider + principalSep + subject
}

func decPrincipal(s string) (ws, provider, subject string) {
	p := strings.SplitN(s, principalSep, 3)
	for len(p) < 3 {
		p = append(p, "")
	}
	return p[0], p[1], p[2]
}

// encDoorbell / decDoorbell frame an agent-push ring as op + the key fields the
// owner needs to re-derive: workspace, node, and (for a revoke) the session id plus
// the reason. The config itself is never carried — the owner re-reads it — so the
// payload is bounded and identity-free.
func encDoorbell(op, ws, nodeID, sessionID, reason string) string {
	return op + principalSep + ws + principalSep + nodeID + principalSep + sessionID + principalSep + reason
}

func decDoorbell(s string) (op, ws, nodeID, sessionID, reason string) {
	p := strings.SplitN(s, principalSep, 5)
	for len(p) < 5 {
		p = append(p, "")
	}
	return p[0], p[1], p[2], p[3], p[4]
}

// pgrouter is the shared-SQL-store stream router. It delivers to agents/clients
// locally, exactly like the inproc router, and drives the deny-path doorbells
// through a pluggable realtimeBus: Postgres pushes them over LISTEN/NOTIFY, MySQL
// polls the authoritative rows. Each strong write rings its doorbell in-band (a
// no-op on MySQL), and the bus re-reads or evicts on delivery. The doorbell is an
// optimization over the short-TTL deny cache — a lost ring only delays a re-read by
// at most the TTL.
type pgrouter struct {
	reg       *Registry
	sig       *sessionSignalBroker
	signRec   signRevokeRec
	signID    signRevokeID
	onSuspend func(ws, provider, subject string)
	onNetcfg  func(ws, nodeID string) // owner-side re-derive + push of a node's networks
	onModcfg  func(ws, nodeID string) // owner-side re-derive + push of a node's modules
	deny      *denyCache
	onConfig  func() // re-read + adopt the stored cluster config (a follower apply)

	controllerID  string
	ownChannel string // gwChannel(controllerID), precomputed

	// doorbells carries agent-push rings off the bus delivery path to a worker, so a
	// slow agent stream cannot head-of-line-block the deny/suspend/revoke doorbells.
	// A full queue drops the ring (the owner sweep / reconnect reconcile re-drives),
	// keeping it best-effort.
	doorbells  chan string
	workerDone chan struct{}

	store  *sqlStore
	bus    realtimeBus
	cancel context.CancelFunc
	done   chan struct{}
}

const doorbellQueue = 256

func newPGRouter(store *sqlStore, controllerID string, reg *Registry, sig *sessionSignalBroker,
	signRec signRevokeRec, signID signRevokeID, onSuspend func(ws, provider, subject string),
	deny *denyCache, onConfig func(), onNetcfg, onModcfg func(ws, nodeID string), dsn string) (*pgrouter, error) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &pgrouter{
		reg: reg, sig: sig, signRec: signRec, signID: signID, onSuspend: onSuspend,
		onNetcfg: onNetcfg, onModcfg: onModcfg, deny: deny, onConfig: onConfig,
		controllerID: controllerID, ownChannel: gwChannel(controllerID),
		doorbells: make(chan string, doorbellQueue), workerDone: make(chan struct{}),
		store: store, cancel: cancel, done: make(chan struct{}),
	}
	bus, err := newRealtimeBus(ctx, store, dsn, r)
	if err != nil {
		cancel()
		return nil, err
	}
	r.bus = bus
	store.bus = bus
	go r.serveDoorbells(ctx)
	return r, nil
}

// newRealtimeBus builds the bus the active engine backs: Postgres LISTEN/NOTIFY, or
// the MySQL poll loop. dsn is needed only for the Postgres bus's dedicated pool.
func newRealtimeBus(ctx context.Context, store *sqlStore, dsn string, h busHandler) (realtimeBus, error) {
	if store.dialect.name() == "postgres" {
		return newPGBus(ctx, dsn, h)
	}
	return newPollBus(store, h), nil
}

// --- busHandler ---

func (r *pgrouter) denyChannels() []string {
	return []string{chanConfig, chanSuspend, chanLift, chanRevoke, r.ownChannel}
}

func (r *pgrouter) onResync() {
	r.deny.flush()
	r.onConfig()
}

func (r *pgrouter) flushDeny()       { r.deny.flush() }
func (r *pgrouter) onConfigChanged() { r.onConfig() }

// onDoorbell reacts to a doorbell. For deny channels it drops the cached verdict so
// the next RPC re-reads the primary; for config it re-reads + adopts; for this
// controller's own channel it re-derives the agent push the ringing controller owes us.
func (r *pgrouter) onDoorbell(channel, payload string) {
	if channel == r.ownChannel {
		select {
		case r.doorbells <- payload:
		default:
			// Queue full (a backlog of slow agents): drop the ring. The owner sweep
			// (revoke) and the agent's reconnect reconcile (netcfg/modcfg) re-drive it.
			slog.Warn("agent-push doorbell dropped (worker busy)", "payload-bytes", len(payload))
		}
		return
	}
	switch channel {
	case chanRevoke:
		r.deny.invalidateRevoked(payload)
	case chanSuspend:
		ws, p, sub := decPrincipal(payload)
		r.onSuspend(ws, p, sub) // evicts the cache AND tears down locally-held streams
	case chanLift:
		ws, p, sub := decPrincipal(payload)
		r.deny.invalidateSuspension(ws, p, sub)
	case chanConfig:
		r.onConfig()
	}
}

// serveDoorbells drains agent-push rings serially, off the bus delivery path. The
// re-derive it runs (a store read plus a possibly-blocking stream send to the local
// agent) must never stall the deny-path doorbells.
func (r *pgrouter) serveDoorbells(ctx context.Context) {
	defer close(r.workerDone)
	for {
		select {
		case <-ctx.Done():
			return
		case payload := <-r.doorbells:
			r.handleAgentDoorbell(payload)
		}
	}
}

func (r *pgrouter) Close() {
	r.cancel()
	if r.bus != nil {
		r.bus.Close()
	}
	<-r.workerDone
}

// owns reports whether THIS controller currently holds nodeID's live stream at the
// directory's current epoch; owner is the controller the directory names (or "").
func (r *pgrouter) owns(nodeID string) (local bool, owner string) {
	gw, epoch, ok := r.store.AgentAffinity(nodeID)
	if !ok {
		return false, ""
	}
	if gw == r.controllerID && r.reg.Online(nodeID) {
		if h := r.reg.handle(nodeID); h != nil && h.affinityEpoch() == epoch {
			return true, gw
		}
	}
	return false, gw
}

// currentEpochMatches re-reads the directory at delivery time so a superseded owner
// that still has a stale handle does not act on a ring meant for the new owner.
func (r *pgrouter) currentEpochMatches(nodeID string) bool {
	gw, epoch, ok := r.store.AgentAffinity(nodeID)
	if !ok || gw != r.controllerID {
		return false
	}
	h := r.reg.handle(nodeID)
	return h != nil && h.affinityEpoch() == epoch
}

// notifyGW rings another controller's own channel through the bus. The ring is
// best-effort: a blip (or a bus with no push, i.e. MySQL) drops it and the
// sweep / reconnect reconcile re-drives, so it must never block the caller. The
// error is returned so a caller that audits delivery (the revoke path) can report
// "owed" honestly rather than claiming a push that never left.
func (r *pgrouter) notifyGW(controllerID, op, ws, nodeID, sessionID, reason string) error {
	ctx, cancel := context.WithTimeout(context.Background(), gwNotifyTimeout)
	defer cancel()
	if err := r.bus.crossControllerNotify(ctx, gwChannel(controllerID), encDoorbell(op, ws, nodeID, sessionID, reason)); err != nil {
		slog.Warn("agent-push doorbell not rung", "op", op, "owner", controllerID, "node", nodeID, "err", err)
		return err
	}
	return nil
}

// RouteNetcfg / RouteModcfg hand a config re-push to the controller that owns the
// agent's stream when this controller does not. The caller (pushNodeNetworks /
// pushNodeModules) reaches here only after finding no local handle, so a directory
// entry naming a peer is the cross-controller case; an unowned or self-owned-but-gone
// node is left to its reconnect reconcile.
func (r *pgrouter) RouteNetcfg(ws, nodeID string) { r.routeReread(opNetcfg, ws, nodeID) }
func (r *pgrouter) RouteModcfg(ws, nodeID string) { r.routeReread(opModcfg, ws, nodeID) }

func (r *pgrouter) routeReread(op, ws, nodeID string) {
	gw, _, ok := r.store.AgentAffinity(nodeID)
	if !ok || gw == r.controllerID {
		return // unowned/offline or stale-self: reconnect reconcile re-derives
	}
	_ = r.notifyGW(gw, op, ws, nodeID, "", "") // best-effort; reconnect reconcile backstops
}

// handleAgentDoorbell runs on the owning controller: it re-derives the owed push from
// the authoritative store and delivers it on the local stream. The epoch re-check
// drops a ring for a node that has since re-homed elsewhere (the new owner's
// reconnect reconcile, or the sweep for a revoke, covers it).
func (r *pgrouter) handleAgentDoorbell(payload string) {
	op, ws, nodeID, sessionID, reason := decDoorbell(payload)
	if !r.currentEpochMatches(nodeID) {
		return
	}
	switch op {
	case opNetcfg:
		r.onNetcfg(ws, nodeID)
	case opModcfg:
		r.onModcfg(ws, nodeID)
	case opRevoke:
		rev, err := r.signID(nodeID, sessionID, reason)
		if err != nil {
			slog.Error("routed revoke sign failed", "node", nodeID, "session", sessionID, "err", err)
			return
		}
		_ = r.reg.SendRevoke(nodeID, rev)
		// Cut the client end too if its signaling stream is held here — which it is
		// once the broker redirects a client to the agent's owning controller. The client
		// trusts the controller channel, so the owner's fresh-epoch revoke closes its end
		// at once instead of waiting out the fail-closed lease. A no-op if the client
		// attached elsewhere (then its own lease starves it).
		r.sig.deliverControl(sessionID, &genezav1.ControllerEnforcement{
			Msg: &genezav1.ControllerEnforcement_SessionRevoke{SessionRevoke: rev}})
	}
}

// --- delivery: local for the agent's controller; cross-controller agent pushes ring the
// owner's channel (RouteNetcfg/RouteModcfg and the remote SendRevoke branch). The
// synchronous session paths (SendOffer/SendDisco) cannot re-read a transient grant
// or ICE candidate from a ring, so a non-local agent there is owed/denied until the
// broker redirects the client to the owning controller ---

func (r *pgrouter) SendOffer(ctx context.Context, nodeID, sessionID string, g []byte, turn *genezav1.TurnCreds, timeout time.Duration) (bool, string, error) {
	return r.reg.SendOffer(ctx, nodeID, sessionID, g, turn, timeout)
}

func (r *pgrouter) SendRevoke(rec *SessionRecord, reason string) (bool, *genezav1.SessionRevoke, error) {
	if local, owner := r.owns(rec.NodeID); local {
		rev, err := r.signRec(rec, reason)
		if err != nil {
			return false, nil, err
		}
		return r.reg.SendRevoke(rec.NodeID, rev) == nil, rev, nil
	} else if owner == "" || owner == r.controllerID {
		return false, nil, nil // owed; the owner's sweep re-drives once the agent reattaches
	} else {
		// Ring the owner, which signs with its epoch and delivers. rev is nil here —
		// only the owning controller's epoch is valid for the agent. Report delivered from
		// whether the ring actually left: the session row already records the owed
		// revoke, so a failed ring is re-driven by the owner's sweep, and the audit
		// must read "owed" rather than a push that never happened.
		err := r.notifyGW(owner, opRevoke, rec.WorkspaceID, rec.NodeID, rec.ID, reason)
		return err == nil, nil, nil
	}
}

func (r *pgrouter) BridgeToAgent(nodeID, sessionID string, d *genezav1.DiscoMsg) (bool, error) {
	return r.reg.SendDisco(nodeID, d) == nil, nil
}

// PublishSuspend is a no-op: SuspendPrincipal already rang geneza_suspend inside
// its own transaction (Postgres) or is covered by the poll-bus deny flush (MySQL),
// so the fanout is in-band rather than a separate publish.
func (r *pgrouter) PublishSuspend(ws, provider, subject string) {}
func (r *pgrouter) OnAgentClaimed(nodeID string, epoch int64)   {}
func (r *pgrouter) OnAgentReleased(nodeID string, epoch int64)  {}

func (r *pgrouter) Online(nodeID string) bool { return r.reg.Online(nodeID) }
func (r *pgrouter) Services(nodeID string) ([]types.Service, bool) {
	return r.reg.Services(nodeID)
}
