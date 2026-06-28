package controller

import (
	"fmt"
	"time"

	"geneza.io/internal/defaults"
	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/types"
)

// sessionenforce.go is the controller's signer for realtime session-enforcement
// messages on DIRECT (p2p) sessions. On a direct path the controller is off the
// data path, so the agent (and client) re-verify every revoke / lease / delta
// against the trusted grant key independently — exactly the way they verify a
// grant. We REUSE types.Sign and put the full types.Signed envelope in the
// message's `sig` field, so the verifier keeps the key id (and key rotation keeps
// working); we never hand-roll ed25519 here. Every payload carries a
// strictly-monotonic per-session epoch (nextEpoch) and the client's Noise static
// key, so a signature is non-replayable across sessions and non-rewindable.

// nextEpoch returns the next strictly-increasing epoch for a session by
// read-modify-writing the durable record in one store transaction. Keeping the
// counter on the record (not in a controller's memory) means a controller that takes
// the session over after a restart or a control-stream re-home continues the
// exact sequence the agent already saw, so a routed revoke or a fresh lease is
// never rejected as a replay. int64 never wraps in practice. A missing record
// yields 0, which the agent treats as non-advancing (fail-safe: no enforcement).
func (s *Server) nextEpoch(ws, sessionID string) int64 {
	var epoch int64
	_ = s.store.UpdateSession(ws, sessionID, func(r *SessionRecord) {
		r.EnforcementEpoch++
		epoch = r.EnforcementEpoch
	})
	return epoch
}

// signEnvelope marshals a session-policy payload into the domain-separated signed
// envelope and returns its opaque encoding for the message `sig` field.
func (s *Server) signEnvelope(payload any) ([]byte, error) {
	env, err := types.Sign(s.grantKey, s.grantKeyID, defaults.ContextSessionPolicy, payload)
	if err != nil {
		return nil, err
	}
	return env.Encode()
}

// leaseExpiryMs returns the wall-clock expiry (unix ms) of a fresh lease minted
// now. Wall-clock (not a relative TTL) so the agent's clock-skew window matches
// grant validation.
func leaseExpiryMs() int64 {
	return time.Now().Add(defaults.SessionLeaseTTL).UnixMilli()
}

func (s *Server) signLease(sessionID string, epoch, expiryMs int64, clientNoisePub []byte) (*genezav1.SessionLease, error) {
	sig, err := s.signEnvelope(types.LeasePayload{
		SessionID:      sessionID,
		Epoch:          epoch,
		ExpiryUnixMs:   expiryMs,
		ClientNoisePub: clientNoisePub,
	})
	if err != nil {
		return nil, fmt.Errorf("sign lease: %w", err)
	}
	return &genezav1.SessionLease{SessionId: sessionID, Epoch: epoch, LeaseExpiryUnixMs: expiryMs, Sig: sig}, nil
}

func (s *Server) signRevoke(rec *SessionRecord, epoch int64, reason string) (*genezav1.SessionRevoke, error) {
	sig, err := s.signEnvelope(types.RevokePayload{
		SessionID:      rec.ID,
		Epoch:          epoch,
		Reason:         reason,
		ClientNoisePub: rec.ClientNoisePub,
	})
	if err != nil {
		return nil, fmt.Errorf("sign revoke: %w", err)
	}
	return &genezav1.SessionRevoke{SessionId: rec.ID, Reason: reason, Epoch: epoch, Sig: sig}, nil
}

// signDelta signs a downgrade-only capability delta. The signer is wired here but
// the periodic sweep does NOT yet compute deltas (it emits lease-on-allow /
// revoke-on-deny instead); the per-op tighten path consumes these deltas.
func (s *Server) signDelta(rec *SessionRecord, epoch int64, op, target string, caps *genezav1.SessionCaps, expiryMs int64, reason string) (*genezav1.SessionPolicyDelta, error) {
	sig, err := s.signEnvelope(types.DeltaPayload{
		SessionID:         rec.ID,
		Epoch:             epoch,
		Op:                op,
		Target:            target,
		Caps:              capsToTypes(caps),
		LeaseExpiryUnixMs: expiryMs,
		ClientNoisePub:    rec.ClientNoisePub,
	})
	if err != nil {
		return nil, fmt.Errorf("sign delta: %w", err)
	}
	return &genezav1.SessionPolicyDelta{
		SessionId: rec.ID, Epoch: epoch, Op: op, Target: target,
		Caps: caps, LeaseExpiryUnixMs: expiryMs, Reason: reason, Sig: sig,
	}, nil
}

// capsToTypes mirrors a proto SessionCaps into the pb-free signed CapsPayload so
// the controller and agent hash byte-identical JSON.
func capsToTypes(c *genezav1.SessionCaps) *types.CapsPayload {
	if c == nil {
		return nil
	}
	return &types.CapsPayload{
		Allow:            c.GetAllow(),
		AllowPTY:         c.GetAllowPty(),
		AllowInput:       c.GetAllowInput(),
		ForwardTargets:   c.GetForwardTargets(),
		AllowSFTPWrite:   c.GetAllowSftpWrite(),
		AllowNewChannels: c.GetAllowNewChannels(),
	}
}
