package controller

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"time"
)

// presence.go is the continuous-presence factor seam. A presence-
// required session must prove a human is present by beating a factor every
// heartbeat_interval; when beats stop, presence goes stale and the continuous
// sweep drops the session. This file is the SEAM: a PresenceFactor interface, a
// registry keyed by Kind with the software-stub safety gate, and the software
// factor itself. Real WebAuthn/FIDO2 factors implement the SAME interface
// and return the identical (newCounter, err) shape — no call-site changes.
//
// Every check fails closed: an empty/mismatched challenge, a session-id mismatch,
// a non-increasing counter, an unknown Kind, or a gated software factor all return
// an error, and the caller does NOT stamp last-presence — so the session stays
// stale and is reaped.

// Attestation is one beat's factor proof, bound to its session.
type Attestation struct {
	Kind        string
	SessionID   string
	Signature   []byte
	Counter     uint32
	ClientData  []byte // must echo the issued single-use challenge
	ChallengeID []byte
}

// EnrolledCredential is a principal's registered factor. A real hardware-enroll
// path populates these; today they are only read for the software-stub safety gate.
type EnrolledCredential struct {
	Kind      string
	PublicKey []byte
	AAGUID    []byte
	SignCount uint32
}

// PresenceFactor verifies one beat against the issued challenge + the principal's
// enrolled credential, bound to sessionID, returning the new monotonic counter.
type PresenceFactor interface {
	Kind() string
	Verify(att Attestation, challenge []byte, cred EnrolledCredential, sessionID string) (newCounter uint32, err error)
}

// softwareFactor is the no-crypto stub: it exercises the full challenge -> verify
// -> stamp path so the transport, staleness, and session-id binding are real from
// day one, but it proves nothing about hardware. "Unplug" = the client simply
// stops calling Heartbeat. WebAuthn replaces it with real signature + UV + clone
// checks behind the identical interface.
type softwareFactor struct{}

func (softwareFactor) Kind() string { return "software" }

func (softwareFactor) Verify(att Attestation, challenge []byte, _ EnrolledCredential, sessionID string) (uint32, error) {
	if len(challenge) == 0 || !bytes.Equal(att.ClientData, challenge) {
		return 0, fmt.Errorf("presence: challenge mismatch")
	}
	// Bind to the session HERE (not just in the handler) so a real factor inherits
	// the anti-cross-session-replay property.
	if att.SessionID != sessionID {
		return 0, fmt.Errorf("presence: session-id mismatch")
	}
	if att.Counter == 0 {
		return 0, fmt.Errorf("presence: counter must start at 1")
	}
	return att.Counter, nil
}

// presenceRegistry resolves a factor by Kind, enforcing the software-stub safety
// gate: once ANY hardware credential is enrolled for a principal (or software is
// globally disabled), Kind=="software" is refused — an ungated stub would be a
// presence hole, not a seam.
type presenceRegistry struct {
	byKind        map[string]PresenceFactor
	allowSoftware bool
}

func newPresenceRegistry(allowSoftware bool) *presenceRegistry {
	r := &presenceRegistry{byKind: map[string]PresenceFactor{}, allowSoftware: allowSoftware}
	r.byKind["software"] = softwareFactor{}
	r.byKind["webauthn"] = webauthnFactor{}
	return r
}

// webauthnFactor is the hardware-presence SEAM. It is wired into
// the registry and the enroll path (PutMember PresenceCredentials), so the
// software-stub safety gate already refuses "software" once a webauthn credential
// is enrolled. Its Verify is intentionally FAIL-CLOSED until the real assertion
// check lands: a principal who has enrolled a hardware factor cannot beat with a
// stub, and webauthn beats are rejected until the crypto is implemented.
//
// Drop-in (the seam): replace this Verify with go-webauthn/webauthn assertion
// verification — check (i) clientDataJSON.challenge == the issued single-use
// challenge, (ii) the assertion signature against cred.PublicKey, (iii)
// authData.signCount > cred.SignCount (clone detection), (iv) the UV flag, and (v)
// the session-id binding (att.SessionID == sessionID, as softwareFactor already
// does). Return the new signCount as newCounter. No call-site changes — the
// interface, the registry, the enroll storage, and the heartbeat transport are all
// already in place. See docs/authz-presence-spec.md.
type webauthnFactor struct{}

func (webauthnFactor) Kind() string { return "webauthn" }

func (webauthnFactor) Verify(att Attestation, challenge []byte, cred EnrolledCredential, sessionID string) (uint32, error) {
	return 0, fmt.Errorf("presence: webauthn factor not yet implemented (seam wired; see docs/authz-presence-spec.md)")
}

// Get returns the factor for kind, or a fail-closed error. The software gate:
// refuse "software" when it is globally disabled OR the principal has any hardware
// credential enrolled (so a stub beat can never stand in for a real factor).
func (r *presenceRegistry) Get(kind string, enrolled []EnrolledCredential) (PresenceFactor, error) {
	if kind == "software" {
		if !r.allowSoftware {
			return nil, fmt.Errorf("presence: software factor disabled (allow_software=false)")
		}
		for _, c := range enrolled {
			if c.Kind != "" && c.Kind != "software" {
				return nil, fmt.Errorf("presence: software factor refused (hardware credential enrolled)")
			}
		}
	}
	f, ok := r.byKind[kind]
	if !ok {
		return nil, fmt.Errorf("presence: unknown factor kind %q", kind)
	}
	return f, nil
}

// newPresenceChallenge mints a fresh single-use challenge.
func newPresenceChallenge() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}

// enrolledCreds returns a principal's enrolled presence credentials (for the gate).
func (s *Server) enrolledCreds(ws, provider, subject string) []EnrolledCredential {
	m, err := s.store.GetMember(ws, provider, subject)
	if err != nil || m == nil {
		return nil
	}
	return m.PresenceCredentials
}

// verifyBeat is the shared presence-verification core for both transports (CLI
// SessionRecord and browser AuthSession): resolve the factor (with the safety
// gate), pick the challenge to verify against (current, or the previous within a
// one-heartbeat-interval grace so a single lost response does not falsely fail),
// and verify the attestation bound to sessionID. Returns the rotated challenge on
// success; fail-closed (error, caller does NOT stamp) on any mismatch.
func (s *Server) verifyBeat(att Attestation, sessionID string, cur, prev []byte, prevUnix int64, enrolled []EnrolledCredential) ([]byte, error) {
	factor, err := s.presence.Get(att.Kind, enrolled)
	if err != nil {
		return nil, err
	}
	challenge := cur
	if len(prev) > 0 && bytes.Equal(att.ClientData, prev) {
		// Grace expires at EXACTLY one heartbeat_interval (strict <), so a beat that
		// arrives on schedule uses the current challenge, not the previous one — the
		// grace can only cover a single lost response, never mask a real unplug. The
		// monotonic counter check (verifyPresenceSession) prevents replaying a captured
		// beat within this window.
		if time.Now().Unix()-prevUnix < int64(s.cfg.Presence.HeartbeatInterval.D().Seconds()) {
			challenge = prev
		}
	}
	var cred EnrolledCredential
	for _, c := range enrolled {
		if c.Kind == att.Kind {
			cred = c
			break
		}
	}
	if _, verr := factor.Verify(att, challenge, cred, sessionID); verr != nil {
		return nil, verr
	}
	return newPresenceChallenge(), nil
}

// verifyPresenceSession verifies a CLI heartbeat for a tunnel session and, on
// success, atomically stamps last-presence + rotates the challenge. Suspension is
// checked FIRST so a suspended principal cannot keep a session alive by
// beating. A non-presence session is a no-op (never staled). On failure nothing
// is stamped, so the session stays stale and the sweep reaps it.
func (s *Server) verifyPresenceSession(ws, sessionID string, att Attestation) (next []byte, ttlSec int64, err error) {
	rec, err := s.store.GetSession(ws, sessionID)
	if err != nil {
		return nil, 0, err
	}
	if s.store.IsSuspended(rec.WorkspaceID, rec.Provider, rec.Subject) {
		return nil, 0, fmt.Errorf("principal suspended")
	}
	ttl := s.cfg.Presence.TTL.D()
	ttlSec = int64(ttl.Seconds())
	if !rec.RequirePresence || ttl <= 0 {
		return nil, ttlSec, nil // presence off for this session: accept, don't stamp
	}
	// Monotonic-nonce anti-replay: the beat counter must strictly exceed the last
	// accepted one, so a captured beat cannot be replayed (within the grace window)
	// to keep a stale session alive. The software stub does this in software; a real
	// factor's signed signCount does it in hardware.
	if att.Counter <= rec.LastPresenceCounter {
		return nil, ttlSec, fmt.Errorf("presence: non-monotonic counter")
	}
	next, err = s.verifyBeat(att, sessionID, rec.PresenceChallenge, rec.PrevPresenceChallenge, rec.PrevChallengeUnix, s.enrolledCreds(ws, rec.Provider, rec.Subject))
	if err != nil {
		return nil, ttlSec, err
	}
	now := time.Now().Unix()
	_ = s.store.UpdateSession(ws, sessionID, func(r *SessionRecord) {
		r.PrevPresenceChallenge = r.PresenceChallenge
		r.PrevChallengeUnix = now
		r.PresenceChallenge = next
		r.LastPresenceUnix = now
		r.LastPresenceCounter = att.Counter
	})
	return next, ttlSec, nil
}
