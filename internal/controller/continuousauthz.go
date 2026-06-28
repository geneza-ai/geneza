package controller

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/policy"
)

// errReasonRequired is returned by approveNodeWithReason when re-approving a node
// that is under an active drift quarantine without a recorded reason. Callers map it
// to InvalidArgument / 400.
var errReasonRequired = errors.New("a reason is required to re-approve a quarantined node")

// Continuous authorization: re-evaluate every in-flight session against the
// CURRENT policy on a tick, and revoke (tear down over the control channel) any
// that are no longer permitted. This turns Geneza from per-session zero trust
// into continuous zero trust — a policy tightening, a time-window closing, or
// an explicit admin revoke takes effect on live sessions within one interval,
// not at TTL expiry. (Role/group membership is re-evaluated against current
// policy bindings using the roles captured at login; live IdP-group revocation
// is bounded by the short cert TTL.)

const defaultReauthInterval = 15 * time.Second

// leaderRetryInterval is how often a follower re-attempts the leader lock, so it
// promotes within one interval of the current leader's connection dropping.
func (s *Server) runContinuousAuthz(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = defaultReauthInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	slog.Info("continuous authorization active", "interval", interval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.reauthSweep()
		}
	}
}

// reauthSweep re-evaluates active/detached sessions and revokes the denied ones.
func (s *Server) reauthSweep() {
	now := time.Now().Unix()
	// Global janitorial GC of expired ephemerals. Every controller runs it: each is an
	// idempotent `DELETE ... WHERE expired`, so two controllers sharing one store delete
	// the same dead rows and the second simply deletes nothing — no leader needed.
	if n, err := s.store.SweepExpiredAuthSessions(now); err != nil {
		slog.Warn("reauth sweep: expire auth sessions", "err", err)
	} else if n > 0 {
		slog.Debug("reauth sweep: expired auth sessions", "count", n)
	}
	if n, err := s.store.SweepExpiredDeviceGrants(now); err != nil {
		slog.Warn("reauth sweep: expire device grants", "err", err)
	} else if n > 0 {
		slog.Debug("reauth sweep: expired device grants", "count", n)
	}
	if n, err := s.store.SweepExpiredHandoffs(now); err != nil {
		slog.Warn("reauth sweep: expire handoffs", "err", err)
	} else if n > 0 {
		slog.Debug("reauth sweep: expired handoffs", "count", n)
	}
	// Drop relays that stopped heartbeating so the next map rebuild removes them.
	if n, err := s.store.ExpireStaleRelays(relayStaleTTL); err != nil {
		slog.Warn("reauth sweep: expire relays", "err", err)
	} else if n > 0 {
		slog.Debug("reauth sweep: expired relays", "count", n)
	}
	// Drop controllers that stopped self-heartbeating so the discovery set shrinks.
	if n, err := s.store.ExpireStaleControllers(controllerStaleTTL); err != nil {
		slog.Warn("reauth sweep: expire controllers", "err", err)
	} else if n > 0 {
		slog.Debug("reauth sweep: expired controllers", "count", n)
	}
	s.sessionSignals.sweepExpired() // per-controller in-memory signaling GC
	sessions, err := s.store.ListAllSessions()
	if err != nil {
		slog.Warn("reauth sweep: list sessions", "err", err)
		return
	}
	// Prefetch the node set once for the whole sweep so re-authorizing M live
	// sessions costs a single ListAllNodes, not one GetNode per session. Falls back
	// to per-session store reads if the bulk read fails (the sweep still runs).
	lookup := s.storeNodeLookup
	if all, lerr := s.store.ListAllNodes(); lerr == nil {
		idx := make(map[string]*NodeRecord, len(all))
		for _, n := range all {
			idx[n.WorkspaceID+"\x00"+n.ID] = n
		}
		lookup = func(ws, id string) (*NodeRecord, bool) { n, ok := idx[ws+"\x00"+id]; return n, ok }
	}
	for _, rec := range sessions {
		switch rec.State {
		case SessionActive, SessionDetached:
			// Re-evaluate every live session on every controller. The decision reads the
			// global-strong store, so a deny written anywhere is enforced within a
			// tick; enforcement pushes route to the controller holding the agent (revoke)
			// or no-op locally (the direct lease push only lands where the agent is),
			// and the client lease refresh lands wherever the client is attached. A
			// detached session whose agent is offline still has its deny persisted so
			// the teardown is owed and redelivered on reconnect.
			s.driveLiveSessionWith(rec, lookup)
		case SessionRevoked:
			// A revoke whose push never reached the agent (it was offline, or the
			// gRPC send buffered into a stream that was already dying) is still owed
			// until the agent acknowledges it. Re-push while the node is online; an
			// offline node is caught instead when it reconnects (see
			// redeliverPendingRevokes). Without this, a marked-revoked session could
			// keep running on the node — the controller would believe it was cut.
			if !rec.RevokeDelivered && s.registry.Online(rec.NodeID) {
				s.rePushRevoke(rec)
			}
		}
	}
}

// driveLiveSession applies the current authorization decision to one live session:
// revoke on a deny, a signed read-only downgrade delta on a read-only tighten, else
// a lease refresh. Used by BOTH the sweep and the agent-reconnect re-push so the
// agent's caps converge to the host's authoritative state immediately on reconnect,
// not a sweep interval later (no stale agent-allows-while-host-blocks window). The
// read-only delta is pushed for ANY session type (the caps it carries —
// allow_input=false, allow_sftp_write=false — apply per action), not just PTYs.
func (s *Server) driveLiveSession(rec *SessionRecord) {
	s.driveLiveSessionWith(rec, s.storeNodeLookup)
}

// nodeLookup resolves a node for re-authorization. The single-session path reads
// the store; the sweep passes a prefetched index so re-authorizing M live sessions
// costs one ListAllNodes, not one GetNode per session (M round-trips per tick).
type nodeLookup func(ws, id string) (*NodeRecord, bool)

func (s *Server) storeNodeLookup(ws, id string) (*NodeRecord, bool) {
	n, err := s.store.GetNode(ws, id)
	return n, err == nil
}

func (s *Server) driveLiveSessionWith(rec *SessionRecord, getNode nodeLookup) {
	d := s.reauthorizeWith(rec, getNode)
	switch {
	case !d.Allow:
		if err := s.revokeSession(rec, "continuous-authz: "+d.Reason); err != nil {
			slog.Warn("reauth revoke failed", "session", rec.ID, "err", err)
		}
	case d.ReadOnly:
		s.pushReadOnlyDelta(rec)
	default:
		s.refreshLease(rec) // allowed, no tighten: converge-on-state lease
	}
}

// reauthorize re-runs the policy decision for a live session against the current
// policy, returning the full Decision (Allow + ReadOnly) so the sweep can pick
// revoke vs downgrade-delta vs lease-refresh.
func (s *Server) reauthorize(rec *SessionRecord) policy.Decision {
	return s.reauthorizeWith(rec, s.storeNodeLookup)
}

func (s *Server) reauthorizeWith(rec *SessionRecord, getNode nodeLookup) policy.Decision {
	// Authorization gate: a suspended principal's live sessions are torn
	// down every sweep tick, even while their cert/token stays valid.
	if s.store.IsSuspended(rec.WorkspaceID, rec.Provider, rec.Subject) {
		return policy.Decision{Allow: false, Reason: "principal suspended"}
	}
	// Continuous-presence gate: a presence-required session whose
	// heartbeat has gone stale (no verified beat for > presence.ttl) is denied —
	// which stops the lease refresh, so the agent's fail-closed lease starves and
	// the conduit dies even if SendRevoke is lost. Applies to Active AND Detached
	// (a detached presence session has no client to beat, so it stales by design).
	if ttl := s.cfg.Presence.TTL.D(); ttl > 0 && rec.RequirePresence {
		if time.Now().Unix()-rec.LastPresenceUnix > int64(ttl.Seconds()) {
			return policy.Decision{Allow: false, Reason: "presence expired"}
		}
	}
	var labels map[string]string
	if node, ok := getNode(rec.WorkspaceID, rec.NodeID); ok {
		// Admission gate is continuous too: if the node's approval was revoked
		// (quarantined), tear down its live sessions on the next sweep.
		if !node.Approved {
			return policy.Decision{Allow: false, Reason: "node approval revoked"}
		}
		labels = node.Labels
	}
	return s.policyFor(rec.WorkspaceID).Evaluate(policy.Input{
		User:          rec.User,
		Roles:         rec.Roles,
		NodeID:        rec.NodeID,
		NodeName:      rec.NodeName,
		NodeLabels:    labels,
		Action:        rec.Action,
		ClientPath:    rec.ClientPath,
		Service:       rec.Service,
		ServiceKind:   rec.ServiceKind,
		ServiceLabels: rec.ServiceLabels,
		Now:           time.Now(),
	})
}

// pushReadOnlyDelta signs + pushes a read-only downgrade for a live session whose
// policy tightened to read-only. The caps stay within the grant ceiling (so the
// agent's VerifyDowngrade accepts them); the delta carries the lease, so it also
// serves as this tick's converge-on-state heartbeat. Pushed to the agent (primary)
// and the client end. Idempotent under per-tick re-drive (epoch climbs).
func (s *Server) pushReadOnlyDelta(rec *SessionRecord) {
	epoch := s.nextEpoch(rec.WorkspaceID, rec.ID)
	caps := &genezav1.SessionCaps{
		Allow:            true,
		AllowPty:         rec.GrantAllowPTY,
		AllowInput:       false, // read-only
		AllowSftpWrite:   false,
		AllowNewChannels: true,
		ForwardTargets:   rec.GrantForwardTargets, // forwards unchanged by a read-only tighten
	}
	delta, err := s.signDelta(rec, epoch, "read_only", "", caps, leaseExpiryMs(), "continuous-authz: read-only")
	if err != nil {
		slog.Error("sign read-only delta failed", "session", rec.ID, "err", err)
		return
	}
	_ = s.registry.SendSessionPolicyDelta(rec.NodeID, delta)
	s.sessionSignals.touch(rec.ID)
	s.sessionSignals.deliverControl(rec.ID, &genezav1.ControllerEnforcement{
		Msg: &genezav1.ControllerEnforcement_SessionPolicyDelta{SessionPolicyDelta: delta}})
}

// revokeSession terminates a live session: mark the record revoked, signal the
// node to tear down the tunnel, and audit. Idempotent on already-terminal records.
//
// The push is NOT assumed to have landed. A node's session host is a separate
// process that outlives the agent's control stream, so an offline agent — or one
// whose stream is already dying (a gRPC send can buffer-succeed into a dead
// connection) — does NOT imply the PTY is gone. We therefore treat the cut as
// confirmed only when the agent acks with a "revoked" event (which it emits after
// actually killing the host session). Until then it is owed (RevokeDelivered=
// false) and re-pushed on every sweep tick (while online) and on agent reattach.
// The audit records only whether we had a live stream to push to — it never
// claims a delivery the agent has not confirmed.
// onSuspendFanout tears down the principal's sessions whose agent stream THIS
// controller holds, in response to a peer announcing a suspension. It is sharded by
// local ownership so each session is cut by exactly one controller; the durable
// suspension row the peer wrote is the authority and the sweep is the backstop.
func (s *Server) onSuspendFanout(ws, provider, subject string) {
	if subject == "" {
		return
	}
	// A peer suspended this principal: drop any cached allow so this controller's
	// deny check sees the suspension sub-TTL instead of waiting out the cache.
	s.deny.invalidateSuspension(ws, provider, subject)
	want := normProvider(provider)
	sessions, err := s.store.ListAllSessions()
	if err != nil {
		return
	}
	for _, rec := range sessions {
		if rec.WorkspaceID != ws || normProvider(rec.Provider) != want || rec.Subject != subject {
			continue
		}
		if !s.registry.Online(rec.NodeID) {
			continue // another controller holds this agent; it tears its own down
		}
		switch rec.State {
		case SessionActive, SessionDetached:
			_ = s.revokeSession(rec, "suspended: "+want)
		case SessionRevoked:
			if !rec.RevokeDelivered {
				s.rePushRevoke(rec)
			}
		}
	}
}

// signRevokeRec signs a fresh-epoch revoke from a record the caller already
// holds (the common local path), so no store reload is needed.
func (s *Server) signRevokeRec(rec *SessionRecord, reason string) (*genezav1.SessionRevoke, error) {
	return s.signRevoke(rec, s.nextEpoch(rec.WorkspaceID, rec.ID), reason)
}

// signRevokeForRouter loads a session and signs a fresh-epoch revoke for it. The
// router calls this on the controller that owns the agent stream, so the revoke is
// signed with that controller's epoch view and the agent's replay protection stays
// consistent across a re-home.
func (s *Server) signRevokeForRouter(nodeID, sessionID, reason string) (*genezav1.SessionRevoke, error) {
	ws, err := s.store.WorkspaceForNode(nodeID)
	if err != nil {
		return nil, err
	}
	rec, err := s.store.GetSession(ws, sessionID)
	if err != nil {
		return nil, err
	}
	return s.signRevoke(rec, s.nextEpoch(ws, sessionID), reason)
}

func (s *Server) revokeSession(rec *SessionRecord, reason string) error {
	if rec.State != SessionActive && rec.State != SessionDetached && rec.State != SessionPending {
		return nil
	}
	// Route the teardown to the controller holding the agent's stream; it signs a
	// fresh-epoch revoke so a DIRECT-path agent verifies it independently and
	// rejects any replay/rollback. On the local path the signed message comes back
	// so the client end can be cut too.
	pushed, rev, serr := s.router.SendRevoke(rec, reason)
	if serr != nil {
		slog.Error("sign/route revoke failed", "session", rec.ID, "err", serr)
	}
	// Belt-and-suspenders: push the SAME signed revoke to the client end (if
	// attached) BEFORE unregistering, so a compromised agent that ignores the cut
	// cannot keep the conduit alive — the client closes its own end.
	if rev != nil {
		s.sessionSignals.deliverControl(rec.ID, &genezav1.ControllerEnforcement{
			Msg: &genezav1.ControllerEnforcement_SessionRevoke{SessionRevoke: rev}})
	}
	_ = s.store.UpdateSession(rec.WorkspaceID, rec.ID, func(r *SessionRecord) {
		r.State = SessionRevoked
		r.EndedUnix = time.Now().Unix()
		r.RevokeReason = reason
		r.RevokeDelivered = false // confirmed later by the agent's "revoked" ack
		s.overlayFor(rec.WorkspaceID).release(r.OverlayIP)
	})
	s.sessionSignals.unregister(rec.ID) // free any session p2p signaling entry
	if err := s.audit.AppendWS(rec.WorkspaceID, "session_revoked", "", rec.NodeID, rec.ID, map[string]string{
		"user":   rec.User,
		"reason": reason,
		"pushed": strconv.FormatBool(pushed),
	}); err != nil {
		return err
	}
	if pushed {
		slog.Info("session revoke pushed (awaiting agent ack)", "session", rec.ID, "user", rec.User, "node", rec.NodeID, "reason", reason)
	} else {
		slog.Warn("session revoke owed (agent offline)", "session", rec.ID, "user", rec.User, "node", rec.NodeID, "reason", reason)
	}
	return nil
}

// confirmRevokeDelivered marks an owed revoke as delivered once the agent acks it
// (a "revoked" SessionEvent). Idempotent; audits the confirmation once.
func (s *Server) confirmRevokeDelivered(ws, sessionID, nodeID string) {
	var firstConfirm bool
	_ = s.store.UpdateSession(ws, sessionID, func(r *SessionRecord) {
		if r.State == SessionRevoked && !r.RevokeDelivered {
			r.RevokeDelivered = true
			firstConfirm = true
		}
	})
	if firstConfirm {
		_ = s.audit.AppendWS(ws, "session_revoke_confirmed", "", nodeID, sessionID, nil)
		slog.Info("session revoke confirmed by agent", "session", sessionID, "node", nodeID)
	}
}

// rePushRevoke re-sends an owed teardown to the node (best-effort). It mints a
// FRESH epoch each time: the agent applies a revoke only when its epoch strictly
// exceeds what it last saw, so a re-push with the same epoch would be ignored as a
// replay and never re-drive. Delivery is confirmed only by the agent's "revoked"
// ack.
func (s *Server) rePushRevoke(rec *SessionRecord) {
	if _, _, err := s.router.SendRevoke(rec, rec.RevokeReason); err != nil {
		slog.Error("sign/route revoke (re-push) failed", "session", rec.ID, "err", err)
	}
}

// refreshLease mints + pushes a fresh signed lease for a still-authorized live
// session. It is the converge-on-state heartbeat: re-sent every sweep tick and on
// agent reconnect, it re-arms the agent's fail-closed timer so a lost revoke or a
// partition tears the conduit within ~1 lease TTL instead of at the 24h session
// TTL. The lease is pushed to the agent (primary) AND the client end.
func (s *Server) refreshLease(rec *SessionRecord) {
	epoch := s.nextEpoch(rec.WorkspaceID, rec.ID)
	expiry := leaseExpiryMs()
	lease, err := s.signLease(rec.ID, epoch, expiry, rec.ClientNoisePub)
	if err != nil {
		slog.Error("sign lease failed", "session", rec.ID, "err", err)
		return
	}
	_ = s.registry.SendSessionLease(rec.NodeID, lease)
	s.sessionSignals.touch(rec.ID) // keep the whole-session control entry alive
	// The client lease tracks CLIENT<->controller liveness + authorization, NOT agent
	// reachability: on a client<->controller partition the client's lease starves and
	// it fails closed; on an agent<->controller partition the client keeps its lease
	// and AUTO-REATTACHES (each reattach is controller-re-authorized, so it can never
	// re-establish a conduit it is no longer allowed). The agent's own lease is what
	// fails the conduit closed when the controller cannot reach it.
	s.sessionSignals.deliverControl(rec.ID, &genezav1.ControllerEnforcement{
		Msg: &genezav1.ControllerEnforcement_SessionLease{SessionLease: lease}})
}

// redeliverPendingRevokes re-pushes every owed teardown for a node when its agent
// (re)connects. This is what lets a revoke that was decided while the node was
// offline actually take effect once it comes back: the agent acks each, settling it.
func (s *Server) redeliverPendingRevokes(nodeID string) {
	sessions, err := s.store.ListAllSessions()
	if err != nil {
		return
	}
	for _, rec := range sessions {
		if rec.NodeID != nodeID {
			continue
		}
		switch rec.State {
		case SessionRevoked:
			if !rec.RevokeDelivered {
				s.rePushRevoke(rec)
			}
		case SessionActive, SessionDetached:
			// Converge-on-state on reconnect: re-apply the FULL current decision
			// (lease, or re-push a read-only delta) so a worker that restarted under a
			// still-read-only policy re-syncs its caps to the host immediately, not a
			// sweep interval later. Also re-arms the fail-closed lease timer.
			s.driveLiveSession(rec)
		}
	}
}

// revokeByID revokes a single session by id (admin "kick").
func (s *Server) revokeByID(ws, sessionID, reason string) error {
	rec, err := s.store.GetSession(ws, sessionID)
	if err != nil {
		return err
	}
	return s.revokeSession(rec, reason)
}

// suspendPrincipal writes the durable deny row THEN immediately nukes the
// principal's live tunnel + browser sessions (don't wait a sweep). The sticky
// row keeps the continuous sweep + login sites denying until lifted, so the deny
// survives re-login even though the keystone/oidc token was never touched.
func (s *Server) suspendPrincipal(ws, provider, subject, username, by, reason string) error {
	if err := s.store.SuspendPrincipal(ws, provider, subject, username, by, reason); err != nil {
		return err
	}
	// Drop any cached allow so this controller denies the suspended principal
	// immediately, not after the cache TTL.
	s.deny.invalidateSuspension(ws, provider, subject)
	n := s.revokeBySubject(ws, provider, subject, "suspended: "+reason)
	// Fan the suspension out so a controller holding one of this principal's streams
	// elsewhere tears it down sub-second instead of waiting for its sweep tick. The
	// durable row above is the authority; this is only the fast path (a no-op on the
	// single-node router).
	s.router.PublishSuspend(ws, provider, subject)
	if killed, derr := s.store.RevokeAuthSessionsForSubject(provider, subject); derr != nil {
		slog.Error("suspend: drop auth sessions failed", "subject", subject, "err", derr)
	} else if killed > 0 {
		slog.Info("suspend: dropped browser sessions", "subject", subject, "count", killed)
	}
	_ = s.audit.AppendWS(ws, "principal_suspended", username, "", "", map[string]string{
		"workspace": ws, "provider": normProvider(provider), "subject": subject,
		"by": by, "reason": reason, "tunnels_revoked": strconv.Itoa(n),
	})
	return nil
}

// liftSuspension removes the durable deny. The next login is clean (the IdP
// token was never touched — only authorization was revoked, now restored).
func (s *Server) liftSuspension(ws, provider, subject, by string) error {
	if err := s.store.LiftSuspension(ws, provider, subject); err != nil {
		return err
	}
	// Drop the cached deny so access is restored immediately, not after the TTL.
	s.deny.invalidateSuspension(ws, provider, subject)
	_ = s.audit.AppendWS(ws, "principal_unsuspended", "", "", "", map[string]string{
		"workspace": ws, "provider": normProvider(provider), "subject": subject, "by": by,
	})
	return nil
}

// revokeBySubject revokes every active/detached tunnel session whose captured
// (Provider, Subject) match — the precise principal identity, not the mutable
// display name. Returns the count revoked.
func (s *Server) revokeBySubject(ws, provider, subject, reason string) int {
	if subject == "" {
		return 0
	}
	want := normProvider(provider)
	sessions, err := s.store.ListAllSessions()
	if err != nil {
		return 0
	}
	n := 0
	for _, rec := range sessions {
		if rec.WorkspaceID != ws || normProvider(rec.Provider) != want || rec.Subject != subject {
			continue
		}
		if rec.State != SessionActive && rec.State != SessionDetached {
			continue
		}
		if err := s.revokeSession(rec, reason); err == nil {
			n++
		}
	}
	return n
}

// revokeByNodeID revokes every active/detached session bound to a node. Used when
// a node is quarantined so its live conduits drop now instead of next sweep tick.
func (s *Server) revokeByNodeID(ws, nodeID, reason string) int {
	sessions, err := s.store.ListAllSessions()
	if err != nil {
		return 0
	}
	n := 0
	for _, rec := range sessions {
		if rec.WorkspaceID != ws || rec.NodeID != nodeID {
			continue
		}
		if rec.State != SessionActive && rec.State != SessionDetached {
			continue
		}
		if err := s.revokeSession(rec, reason); err == nil {
			n++
		}
	}
	return n
}

// quarantineNode is the single entrypoint for taking a node out of service. BOTH
// the admin "Quarantine" button (reason "manual") and the automatic drift detectors
// (reason "binary_tamper" / "identity_clone") funnel through here, so a manual and
// an automatic quarantine produce identical state: the sticky deny + cause row, an
// immediate teardown of the node's live sessions (the sweep would also catch them
// via the Approved=false gate next tick), the node cut from every co-member's
// overlay peer set, and one hash-chained audit event. It is authorization
// revocation only — the node keeps its cert and control stream, so the controller can
// keep measuring it and an admin can later re-approve it.
func (s *Server) quarantineNode(ws, nodeID, reason, by string, detail map[string]string) error {
	if _, err := s.store.QuarantineNode(ws, nodeID, reason, by, detail); err != nil {
		return err
	}
	revoked := s.revokeByNodeID(ws, nodeID, "quarantined: "+reason)
	// Cut the node from every Network it co-members so the data plane drops with the
	// session plane (a quarantine severs the overlay, not just brokered sessions).
	s.repushAllNetworks(ws)
	ad := map[string]string{"reason": reason, "by": by, "sessions_revoked": strconv.Itoa(revoked)}
	for k, v := range detail {
		if _, taken := ad[k]; !taken {
			ad[k] = v
		}
	}
	_ = s.audit.AppendWS(ws, "node_quarantined", by, nodeID, "", ad)
	slog.Warn("node quarantined", "node", nodeID, "reason", reason, "by", by, "sessions_revoked", revoked)
	return nil
}

// approveNodeWithReason is the single admission-toggle entrypoint shared by the gRPC
// AdminAPI and the console, so a deny/re-approve from either surface behaves
// identically. On approve=false it quarantines through quarantineNode (reason
// "manual" if none given) — same state, teardown, overlay cut, and audit as an
// automatic quarantine. On approve=true it requires a recorded reason to clear a
// drift quarantine, fails closed on a quarantine-lookup error, clears the quarantine
// (the baseline is preserved by SetNodeApproval), and re-converges the overlay.
func (s *Server) approveNodeWithReason(ws string, node *NodeRecord, approve bool, reason, by string) error {
	reason = strings.TrimSpace(reason)
	if !approve {
		if reason == "" {
			reason = "manual"
		}
		return s.quarantineNode(ws, node.ID, reason, by, map[string]string{"name": node.Name})
	}
	q, qerr := s.store.GetQuarantine(ws, node.ID)
	if qerr != nil && !errors.Is(qerr, ErrNotFound) {
		return fmt.Errorf("check quarantine: %w", qerr)
	}
	quarantined := qerr == nil
	if quarantined && reason == "" {
		return errReasonRequired
	}
	if _, err := s.store.SetNodeApproval(ws, node.ID, true, by, time.Now()); err != nil {
		return fmt.Errorf("set approval: %w", err)
	}
	detail := map[string]string{"decision": "approve", "name": node.Name}
	if reason != "" {
		detail["reason"] = reason
	}
	if quarantined {
		detail["cleared_quarantine"] = q.Reason
	}
	_ = s.audit.AppendWS(node.WorkspaceID, "node_approval", by, node.ID, "", detail)
	slog.Info("node approved", "node", node.ID, "name", node.Name, "by", by, "cleared_quarantine", quarantined)
	s.repushAllNetworks(ws)
	return nil
}

// evaluateBinaryDrift is the controller-side verdict for a node's self-measured agent
// binary hash, run on every heartbeat that carries one. The agent only MEASURES;
// the controller decides. RecordNodeMeasurement pins the first hash seen after approval
// as the blessed baseline and reports drift when a later hash differs. A drift is
// TAMPER only if the new hash is not a release the controller itself published — an
// operator rolling the fleet to a new signed version (manually or via auto-rollout)
// changes the hash legitimately, and that re-pins silently.
//
// HONEST LIMIT: a fully root-compromised agent can replay its old good hash from
// patched measuring code; this is software posture detection, not hardware-measured
// integrity. It catches an on-disk binary swap + restart, which is the threat.
func (s *Server) evaluateBinaryDrift(ws, nodeID string, binHash []byte) {
	if len(binHash) == 0 {
		return
	}
	measuredUnix := time.Now().Unix()
	drift, pinned, node, err := s.store.RecordNodeMeasurement(ws, nodeID, binHash, measuredUnix)
	if err != nil {
		// A single failed measurement is a one-beat delay, not a permanent evasion: the
		// next heartbeat re-measures and catches any drift, and a quarantined node stops
		// being compared at all. So WARN (don't silently DEBUG) but don't quarantine a
		// healthy node on transient store trouble — the fail-CLOSED that matters is on a
		// CONFIRMED drift we cannot vet (below), not on a measurement we cannot take.
		slog.Warn("record node measurement failed", "node", nodeID, "err", err)
		return
	}
	if pinned {
		// First measurement after approval became the baseline. If it is a published
		// release, record its publish time as the anti-rollback floor (a custom build
		// leaves the floor at zero — no version ordering to enforce).
		if m, e := s.store.PublishedManifestForHash("geneza-agent", hex.EncodeToString(binHash)); e == nil {
			if rerr := s.store.RepinBaseline(ws, nodeID, binHash, m.CreatedAt.Unix()); rerr != nil {
				slog.Error("set baseline floor failed", "node", nodeID, "err", rerr)
			}
		}
		return
	}
	if !drift {
		return // steady-state match
	}
	// The running binary changed. Decide update vs downgrade vs tamper.
	m, perr := s.store.PublishedManifestForHash("geneza-agent", hex.EncodeToString(binHash))
	switch {
	case perr == nil:
		// A release the controller published. Reject a rollback to an OLDER release than
		// the node's blessed floor (downgrade to a known-vulnerable signed build);
		// accept a same-or-newer release as a sanctioned update (manual or rollout).
		if node.ApprovedBinaryCreatedUnix > 0 && m.CreatedAt.Unix() < node.ApprovedBinaryCreatedUnix {
			s.driftQuarantine(ws, nodeID, "binary_downgrade", measuredUnix, map[string]string{
				"measured_hash": hex.EncodeToString(binHash), "to_version": m.Version,
			})
			return
		}
		if rerr := s.store.RepinBaseline(ws, nodeID, binHash, m.CreatedAt.Unix()); rerr != nil {
			slog.Error("re-pin baseline failed", "node", nodeID, "err", rerr)
			return
		}
		_ = s.audit.AppendWS(ws, "node_binary_updated", "system", nodeID, "", map[string]string{
			"binary_hash": hex.EncodeToString(binHash), "version": m.Version,
		})
	case errors.Is(perr, ErrNotFound):
		// Not a release the controller published: tamper.
		s.driftQuarantine(ws, nodeID, "binary_tamper", measuredUnix, map[string]string{
			"measured_hash": hex.EncodeToString(binHash),
			"expected_hash": hex.EncodeToString(node.ApprovedBinaryHash),
		})
	default:
		// Fail closed on a CONFIRMED drift we cannot vet: a changed binary whose
		// provenance we cannot establish must not be silently accepted.
		slog.Error("published-binary lookup failed", "node", nodeID, "err", perr)
		s.driftQuarantine(ws, nodeID, "binary_tamper", measuredUnix, map[string]string{
			"measured_hash": hex.EncodeToString(binHash), "lookup_error": perr.Error(),
		})
	}
}

// driftQuarantine quarantines a node for a drift cause with two safeguards. First,
// it re-reads the node and ABORTS if an admin re-approved it at or after the moment
// this beat measured — the admin acted on newer information than this (possibly
// in-flight) beat carries, so their decision wins; the preserved baseline means a
// still-bad binary re-quarantines on the next fresh beat anyway. Second, if the full
// cause-row write fails, it still flips the admission gate closed so the next sweep
// denies the node — a storage error must never leave a drifted node operational.
func (s *Server) driftQuarantine(ws, nodeID, reason string, measuredUnix int64, detail map[string]string) {
	// Strictly-after: only a (re-)approval stamped LATER than this beat's measurement
	// is newer information; an equal timestamp is the ordinary case of a node approved
	// in the same second it first drifted, which must still quarantine.
	if fresh, err := s.store.GetNode(ws, nodeID); err == nil && fresh.Approved && fresh.ApprovedAtUnix > measuredUnix {
		slog.Info("drift quarantine superseded by fresh admin re-approval", "node", nodeID, "reason", reason)
		return
	}
	if err := s.quarantineNode(ws, nodeID, reason, "system", detail); err != nil {
		slog.Error("quarantine failed; failing closed via admission gate", "node", nodeID, "reason", reason, "err", err)
		if _, derr := s.store.SetNodeApproval(ws, nodeID, false, "system", time.Now()); derr != nil {
			slog.Error("defensive deny also failed", "node", nodeID, "err", derr)
		}
	}
}

// revokeUser revokes every active/detached remote-access session belonging to a
// user AND drops all their browser auth-sessions: web and CLI revocation
// are uniform — kicking a user must close their console too, not just their live
// tunnels. Returns the count of revoked remote-access sessions.
func (s *Server) revokeUser(user, reason string) (int, error) {
	sessions, err := s.store.ListAllSessions()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, rec := range sessions {
		if rec.User != user {
			continue
		}
		if rec.State != SessionActive && rec.State != SessionDetached {
			continue
		}
		if err := s.revokeSession(rec, reason); err == nil {
			n++
		}
	}
	if killed, derr := s.store.RevokeAuthSessionsForUser(user); derr != nil {
		slog.Error("revokeUser: drop auth sessions failed", "user", user, "err", derr)
	} else if killed > 0 {
		slog.Info("revokeUser: dropped browser sessions", "user", user, "count", killed)
	}
	return n, nil
}
