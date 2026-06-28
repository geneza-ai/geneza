package types

import (
	"fmt"
)

// sessionpolicy.go holds the canonical signed payloads for realtime session
// enforcement on a DIRECT (p2p) session: the lease (fail-closed data-path
// heartbeat), the policy delta (downgrade-only capability change), and the
// revoke. All three are signed by the controller's grant key under
// defaults.ContextSessionPolicy and verified by the agent (and client) against
// the SAME trusted key set that verifies grants — reusing types.Sign /
// types.Verify, NOT a bespoke crypto path. Every payload binds the session_id +
// the client's Noise static key so a signature minted for one session can never
// be replayed onto another. The on-wire `bytes sig` field carries the FULL
// types.Signed envelope (payload+sig+key_id) so the verifier keeps the key id
// and survives grant-key rotation.

// CapsPayload is the downgrade-only capability set carried in a DeltaPayload. It
// mirrors the proto SessionCaps but lives here (pb-free) so it can be part of the
// signed JSON bytes both ends hash identically.
type CapsPayload struct {
	Allow            bool     `json:"allow"` // false = full cut
	AllowPTY         bool     `json:"allow_pty"`
	AllowInput       bool     `json:"allow_input"` // false = read-only shell
	ForwardTargets   []string `json:"forward_targets,omitempty"`
	AllowSFTPWrite   bool     `json:"allow_sftp_write"`
	AllowNewChannels bool     `json:"allow_new_channels"`
}

// LeasePayload is the signed body of a SessionLease.
type LeasePayload struct {
	SessionID      string `json:"session_id"`
	Epoch          int64  `json:"epoch"`
	ExpiryUnixMs   int64  `json:"expiry_unix_ms"`
	ClientNoisePub []byte `json:"client_noise_pub"`
}

// DeltaPayload is the signed body of a SessionPolicyDelta.
type DeltaPayload struct {
	SessionID         string       `json:"session_id"`
	Epoch             int64        `json:"epoch"`
	Op                string       `json:"op"`
	Target            string       `json:"target,omitempty"`
	Caps              *CapsPayload `json:"caps,omitempty"`
	LeaseExpiryUnixMs int64        `json:"lease_expiry_unix_ms"`
	ClientNoisePub    []byte       `json:"client_noise_pub"`
}

// RevokePayload is the signed body of a SessionRevoke (direct-session path).
type RevokePayload struct {
	SessionID      string `json:"session_id"`
	Epoch          int64  `json:"epoch"`
	Reason         string `json:"reason"`
	ClientNoisePub []byte `json:"client_noise_pub"`
}

// grantImpliedCaps is the MAXIMAL capability set a grant authorizes — the ceiling
// a downgrade delta may not exceed. The grant only carries AllowPTY and a single
// ForwardTarget explicitly; the rest are implied by the action (an interactive
// shell takes input only with a PTY; an sftp grant implies write; any session may
// open channels for its action).
func grantImpliedCaps(g *SessionGrant) CapsPayload {
	c := CapsPayload{
		Allow:            true,
		AllowPTY:         g.AllowPTY,
		AllowInput:       g.AllowPTY, // input is meaningful on a PTY shell; read-only = AllowInput false
		AllowSFTPWrite:   g.Action == ActionSFTP,
		AllowNewChannels: true,
	}
	if g.ForwardTarget != "" {
		c.ForwardTargets = []string{g.ForwardTarget}
	}
	return c
}

// VerifyDowngrade returns nil iff caps is a DOWNGRADE of (subset of) what grant
// authorizes — the agent's anti-escalation gate for a policy delta. A full cut
// (caps.Allow == false) is always valid. No capability bit may be turned ON that
// the grant withholds, and no forward target may appear that the grant did not
// authorize. This is the single source of truth shared by the agent's applyDelta
// and the unit tests.
func VerifyDowngrade(grant *SessionGrant, caps *CapsPayload) error {
	if caps == nil {
		return fmt.Errorf("nil caps")
	}
	if !caps.Allow {
		return nil // full cut is always a valid downgrade
	}
	ceil := grantImpliedCaps(grant)
	if caps.AllowPTY && !ceil.AllowPTY {
		return fmt.Errorf("delta grants pty the standing grant withholds")
	}
	if caps.AllowInput && !ceil.AllowInput {
		return fmt.Errorf("delta grants input the standing grant withholds")
	}
	if caps.AllowSFTPWrite && !ceil.AllowSFTPWrite {
		return fmt.Errorf("delta grants sftp-write the standing grant withholds")
	}
	// AllowNewChannels ceiling is always true (any session opens its channels), so
	// no check is needed; it only ever restricts at enforcement time.
	for _, t := range caps.ForwardTargets {
		if !contains(ceil.ForwardTargets, t) {
			return fmt.Errorf("delta adds forward target %q absent from the grant", t)
		}
	}
	return nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
