package gateway

import (
	"context"
	"log/slog"
	"time"

	"osie.cloud/geneza/internal/policy"
)

// Continuous authorization: re-evaluate every in-flight session against the
// CURRENT policy on a tick, and revoke (tear down over the control channel) any
// that are no longer permitted. This turns Geneza from per-session zero trust
// into continuous zero trust — a policy tightening, a time-window closing, or
// an explicit admin revoke takes effect on live sessions within one interval,
// not at TTL expiry. (Role/group membership is re-evaluated against current
// policy bindings using the roles captured at login; live IdP-group revocation
// is bounded by the short cert TTL.)

const defaultReauthInterval = 15 * time.Second

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
	sessions, err := s.store.ListSessions()
	if err != nil {
		slog.Warn("reauth sweep: list sessions", "err", err)
		return
	}
	for _, rec := range sessions {
		if rec.State != SessionActive && rec.State != SessionDetached {
			continue
		}
		if ok, reason := s.reauthorize(rec); !ok {
			if err := s.revokeSession(rec, "continuous-authz: "+reason); err != nil {
				slog.Warn("reauth revoke failed", "session", rec.ID, "err", err)
			}
		}
	}
}

// reauthorize re-runs the policy decision for a live session against the
// current policy. Returns false + a reason when access is no longer allowed.
func (s *Server) reauthorize(rec *SessionRecord) (bool, string) {
	var labels map[string]string
	if node, err := s.store.GetNode(rec.NodeID); err == nil {
		labels = node.Labels
	}
	d := s.policy().Evaluate(policy.Input{
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
	if !d.Allow {
		return false, d.Reason
	}
	return true, ""
}

// revokeSession terminates a live session: signal the node to tear down the
// tunnel (best-effort — if the node is offline the session is already gone),
// mark the record revoked, and audit. Idempotent on already-terminal records.
func (s *Server) revokeSession(rec *SessionRecord, reason string) error {
	if rec.State != SessionActive && rec.State != SessionDetached && rec.State != SessionPending {
		return nil
	}
	if s.registry.Online(rec.NodeID) {
		_ = s.registry.SendRevoke(rec.NodeID, rec.ID, reason)
	}
	_ = s.store.UpdateSession(rec.ID, func(r *SessionRecord) {
		r.State = SessionRevoked
		r.EndedUnix = time.Now().Unix()
	})
	if err := s.audit.Append("session_revoked", "", rec.NodeID, rec.ID, map[string]string{
		"user":   rec.User,
		"reason": reason,
	}); err != nil {
		return err
	}
	slog.Info("session revoked", "session", rec.ID, "user", rec.User, "node", rec.NodeID, "reason", reason)
	return nil
}

// revokeByID revokes a single session by id (admin "kick").
func (s *Server) revokeByID(sessionID, reason string) error {
	rec, err := s.store.GetSession(sessionID)
	if err != nil {
		return err
	}
	return s.revokeSession(rec, reason)
}

// revokeUser revokes every active/detached session belonging to a user and
// returns how many were revoked.
func (s *Server) revokeUser(user, reason string) (int, error) {
	sessions, err := s.store.ListSessions()
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
	return n, nil
}
