package controller

import (
	"encoding/json"
	"fmt"
	"time"

	bbolt "go.etcd.io/bbolt"
)

// Trusted-dashboard handoff. Horizon websso form-POSTs a keystone
// token to /openstack/{svc-uid}; the controller validates it server-side and 303s
// the browser to a CLEAN URL carrying only a single-use 256-bit handoff code (so
// the keystone token is NEVER reflected into a URL/log/Referer —). The SPA
// swaps the code (plus a bound HttpOnly+SameSite=Strict cookie — double-secret,
//) for the real session at /api/v1/session/handoff. The handoff record
// holds the RESOLVED identity (not a token); the session is minted at redeem.

var bucketHandoffCodes = []byte("handoff_codes") // sha256(code) -> HandoffRecord

// HandoffRecord is a resolved-but-not-yet-minted session, pending the SPA
// exchange. CookieHash is the second secret: a leaked code is useless without
// the companion cookie.
//
// A hosted-UI LAUNCH ticket (docs/hosted-ui-launch-spec.md) reuses this record
// with an EMPTY CookieHash, because the embed flow cannot rely on a cookie: the
// launch page is loaded inside the cloud provider's portal, where a third-party
// cookie write is blocked by Safari ITP and Chrome's phase-out. It substitutes
// fragment-only delivery (never in a Referer or an access log) + a shorter TTL +
// a narrowed scope for the second secret.
//
// The two redeem paths are MUTUALLY EXCLUSIVE and each fails closed against the
// other's records: RedeemHandoff refuses a record with no cookie leg, and
// RedeemLaunch refuses one that has it. So a cookie-bound handoff can never be
// spent through the cookieless path.
type HandoffRecord struct {
	CodeHash    string       `json:"code_hash"`
	CookieHash  string       `json:"cookie_hash"`
	Session     sessionInput `json:"session"`
	ExpiresUnix int64        `json:"expires_unix"`
}

func (s *bboltStore) PutHandoff(rec *HandoffRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return putJSON(tx, bucketHandoffCodes, rec.CodeHash, rec)
	})
}

// RedeemHandoff atomically consumes a handoff code: verify it exists, the cookie
// matches, it is unexpired and unredeemed, then DELETE it and return the
// resolved session input. Single bbolt Update = single-use.
func (s *bboltStore) RedeemHandoff(code, cookie string, now int64) (sessionInput, error) {
	ch := hashToken(code)
	var out sessionInput
	err := s.db.Update(func(tx *bbolt.Tx) error {
		var rec HandoffRecord
		if err := getJSON(tx, bucketHandoffCodes, ch, &rec); err != nil {
			return fmt.Errorf("invalid or used handoff code")
		}
		// Always delete on any redeem attempt (a bad cookie burns the code too).
		_ = tx.Bucket(bucketHandoffCodes).Delete([]byte(ch))
		if now >= rec.ExpiresUnix {
			return fmt.Errorf("handoff code expired")
		}
		// A hosted-UI launch ticket is never redeemable here. Discriminate on the
		// SCOPE, not on the cookie: a bound launch ticket also carries a cookie,
		// so a cookie test would let one through and mint an UNSCOPED session
		// from it — silently turning a one-node launch into a full console.
		if rec.Session.Scope != nil {
			return fmt.Errorf("not a handoff code")
		}
		if rec.CookieHash == "" || rec.CookieHash != hashToken(cookie) {
			return fmt.Errorf("handoff cookie mismatch")
		}
		out = rec.Session
		return nil
	})
	return out, err
}

// RedeemLaunch atomically consumes a hosted-UI launch ticket: verify it exists,
// is unexpired and unredeemed, check whatever second secret the record carries,
// then DELETE it and return the resolved (scoped) session input. Single bbolt
// Update = single-use; the code burns on any redeem attempt, successful or not.
//
// The cookie requirement is a property of the RECORD, not of the caller:
//   - CookieHash set → the cookie must match (the top-level flow, where stage one
//     minted code and cookie together);
//   - CookieHash empty → allowed only for an embed-scoped ticket, which cannot
//     carry a cookie because a third-party iframe may not be able to set one.
//
// So an unbound top-level ticket cannot be spent cookielessly by presenting it
// straight to the redeem endpoint.
func (s *bboltStore) RedeemLaunch(code, cookie string, now int64) (sessionInput, error) {
	ch := hashToken(code)
	var out sessionInput
	err := s.db.Update(func(tx *bbolt.Tx) error {
		var rec HandoffRecord
		if err := getJSON(tx, bucketHandoffCodes, ch, &rec); err != nil {
			return fmt.Errorf("invalid or used launch code")
		}
		_ = tx.Bucket(bucketHandoffCodes).Delete([]byte(ch))
		if now >= rec.ExpiresUnix {
			return fmt.Errorf("launch code expired")
		}
		// Scope, not CookieHash, is what tells the two ticket kinds apart: a
		// trusted-dashboard handoff carries no scope and must never be spendable here.
		if rec.Session.Scope == nil {
			return fmt.Errorf("not a launch code")
		}
		if rec.CookieHash != "" {
			if rec.CookieHash != hashToken(cookie) {
				return fmt.Errorf("launch cookie mismatch")
			}
		} else if !rec.Session.Scope.Embed {
			return fmt.Errorf("this launch ticket must be bound before it is redeemed")
		}
		out = rec.Session
		return nil
	})
	return out, err
}

// RedeemLaunchBind consumes an UNBOUND top-level launch ticket — stage one of
// the two-stage flow, where the controller mints the browser-facing code and its
// companion cookie together and re-stores them as a fresh record. It is the
// exact complement of RedeemLaunch: it accepts only what RedeemLaunch refuses
// (no cookie leg, not embed-scoped), so neither stage can consume the other's
// tickets and a bound ticket can never be re-bound.
func (s *bboltStore) RedeemLaunchBind(code string, now int64) (sessionInput, error) {
	ch := hashToken(code)
	var out sessionInput
	err := s.db.Update(func(tx *bbolt.Tx) error {
		var rec HandoffRecord
		if err := getJSON(tx, bucketHandoffCodes, ch, &rec); err != nil {
			return fmt.Errorf("invalid or used launch code")
		}
		_ = tx.Bucket(bucketHandoffCodes).Delete([]byte(ch)) // single-use
		if now >= rec.ExpiresUnix {
			return fmt.Errorf("launch code expired")
		}
		if rec.Session.Scope == nil {
			return fmt.Errorf("not a launch code")
		}
		if rec.CookieHash != "" || rec.Session.Scope.Embed {
			return fmt.Errorf("this launch ticket is not awaiting a bind")
		}
		out = rec.Session
		return nil
	})
	return out, err
}

// SweepExpiredHandoffs drops expired handoff codes (from the reauth sweep).
func (s *bboltStore) SweepExpiredHandoffs(now int64) (int, error) {
	n := 0
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketHandoffCodes)
		var dead [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			var rec HandoffRecord
			if jerr := json.Unmarshal(v, &rec); jerr != nil {
				return jerr
			}
			if now >= rec.ExpiresUnix {
				dead = append(dead, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range dead {
			_ = b.Delete(k)
			n++
		}
		return nil
	})
	return n, err
}

func (c *Config) handoffCodeTTL() time.Duration {
	if c.Console.Auth.HandoffCodeTTL > 0 {
		return c.Console.Auth.HandoffCodeTTL.D()
	}
	return 30 * time.Second
}
