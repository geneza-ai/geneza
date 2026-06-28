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
		if rec.CookieHash != hashToken(cookie) {
			return fmt.Errorf("handoff cookie mismatch")
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
