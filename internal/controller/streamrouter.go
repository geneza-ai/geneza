package controller

import (
	"context"
	"fmt"
	"time"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

// streamRouter resolves a node or session to the controller that holds its live
// control stream and delivers a message there. The single-node default,
// inprocRouter, always delivers through the local Registry — a pure pass-through
// with no external dependency. The multi-controller pgRouter takes a push for a
// local agent directly and rings the owning controller over a Postgres NOTIFY channel
// for a remote one.
//
// The broker holds a streamRouter as its AgentDirectory, so a session brokered on
// one controller reaches an agent connected to another. Delivery results are
// reported as a plain "did a live stream take the send" boolean — never as
// "the agent confirmed"; only the agent's own ack confirms an enforcement push.
type streamRouter interface {
	// SendOffer pushes a signed grant to the agent and waits for its ack. turn
	// carries the per-session TURN coordinates (nil when session p2p is off); it
	// must survive a cross-controller hop so a remotely-held agent still gets its ICE
	// credentials.
	SendOffer(ctx context.Context, nodeID, sessionID string, signedGrant []byte,
		turn *genezav1.TurnCreds, timeout time.Duration) (accepted bool, reason string, err error)

	// SendRevoke tells the controller owning the session's agent to cut it. On the
	// local path it signs a fresh-epoch revoke and returns it so the caller can
	// also push it to the client end; on the remote path the owning controller signs
	// (its epoch view wins) and rev is nil. delivered reports only that a live
	// stream took the send — never that the agent confirmed.
	SendRevoke(rec *SessionRecord, reason string) (delivered bool, rev *genezav1.SessionRevoke, err error)

	// RouteNetcfg / RouteModcfg hand a config re-push to the controller that owns the
	// agent's stream when this controller does not hold it. They carry only the node
	// key — the owner re-derives the current config from the store and stamps it with
	// its own per-connection version — so a membership change applied on any controller
	// reaches an agent connected to another. No-ops on the single-node router, where
	// every agent is local. The caller invokes these only after finding no local
	// handle, so they never duplicate a local push.
	RouteNetcfg(ws, nodeID string)
	RouteModcfg(ws, nodeID string)

	// BridgeToAgent forwards a client-originated session signal (ICE) to the agent's
	// local control stream — the broker redirect co-locates the client and agent on
	// the owning controller, so this is always a local hand-off. It carries opaque ICE
	// bytes only; the relay never sees session payload.
	BridgeToAgent(nodeID, sessionID string, d *genezav1.DiscoMsg) (delivered bool, err error)

	// PublishSuspend fans a principal suspension out to every controller so one
	// holding the principal's live stream tears it down without waiting a sweep
	// tick. A no-op on the single-node router.
	PublishSuspend(ws, provider, subject string)

	// OnAgentClaimed / OnAgentReleased bracket the lifetime of an agent's control
	// stream on THIS controller: the pg router (un)tracks the node so a push raised on
	// another controller can be routed back to it. No-ops on the single-node router.
	OnAgentClaimed(nodeID string, epoch int64)
	OnAgentReleased(nodeID string, epoch int64)

	Online(nodeID string) bool
	Services(nodeID string) ([]types.Service, bool)

	// Close tears down any background resources (a bus connection, a dedicated
	// LISTEN connection). A no-op on the single-node router.
	Close()
}

// signRevokeRec signs a fresh-epoch revoke from a record the caller already holds
// (the local path, no store reload). signRevokeID loads the session by node+id
// and signs it (the remote-owner path, where the agent's node record is
// resident). The epoch authority stays on the Server in both.
type signRevokeRec func(rec *SessionRecord, reason string) (*genezav1.SessionRevoke, error)
type signRevokeID func(nodeID, sessionID, reason string) (*genezav1.SessionRevoke, error)

// newRouter builds the stream router the config selects. The single-node default
// is the inproc pass-through; router=pg builds the Postgres NOTIFY-backed router.
func (s *Server) newRouter(cfg *Config, store Store) (streamRouter, error) {
	if cfg.Router == "pg" {
		sqlSt, ok := store.(*sqlStore)
		if !ok {
			return nil, fmt.Errorf("router=pg requires a shared SQL store")
		}
		return newPGRouter(sqlSt, s.controllerID, s.registry, s.sessionSignals, s.signRevokeRec,
			s.signRevokeForRouter, s.onSuspendFanout, s.deny, s.applyClusterConfigFromStore,
			s.pushNodeNetworks, s.pushNodeModules, sqlSt.dsn)
	}
	return newInprocRouter(s.registry, s.signRevokeRec), nil
}

// inprocRouter is the single-node default: every method delegates to the local
// Registry / session-signal broker with the same semantics the controller has always
// had. No bus is dialed and no affinity directory is consulted — there is exactly
// one controller, so the local handle is always the owner.
type inprocRouter struct {
	reg     *Registry
	signRec signRevokeRec
}

func newInprocRouter(reg *Registry, signRec signRevokeRec) *inprocRouter {
	return &inprocRouter{reg: reg, signRec: signRec}
}

func (r *inprocRouter) SendOffer(ctx context.Context, nodeID, sessionID string, g []byte,
	turn *genezav1.TurnCreds, timeout time.Duration) (bool, string, error) {
	return r.reg.SendOffer(ctx, nodeID, sessionID, g, turn, timeout) // turn passes through verbatim
}

func (r *inprocRouter) SendRevoke(rec *SessionRecord, reason string) (bool, *genezav1.SessionRevoke, error) {
	rev, err := r.signRec(rec, reason)
	if err != nil {
		return false, nil, err
	}
	return r.reg.SendRevoke(rec.NodeID, rev) == nil, rev, nil // not-connected -> delivered=false (owed)
}

func (r *inprocRouter) BridgeToAgent(nodeID, sessionID string, d *genezav1.DiscoMsg) (bool, error) {
	return r.reg.SendDisco(nodeID, d) == nil, nil
}
func (r *inprocRouter) RouteNetcfg(ws, nodeID string)               {} // single-node: every agent is local
func (r *inprocRouter) RouteModcfg(ws, nodeID string)               {}
func (r *inprocRouter) PublishSuspend(ws, provider, subject string) {}
func (r *inprocRouter) Close()                                      {}
func (r *inprocRouter) OnAgentClaimed(nodeID string, epoch int64)   {}
func (r *inprocRouter) OnAgentReleased(nodeID string, epoch int64)  {}
func (r *inprocRouter) Online(nodeID string) bool                   { return r.reg.Online(nodeID) }
func (r *inprocRouter) Services(nodeID string) ([]types.Service, bool) {
	return r.reg.Services(nodeID)
}
