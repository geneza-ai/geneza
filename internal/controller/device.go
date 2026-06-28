package controller

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	bbolt "go.etcd.io/bbolt"
)

// RFC 8628 Device Authorization Grant. The CLI captures its CSR up front
// and requests a device+user code; a human approves it in the already-logged-in
// console (typing the user_code — no one-click); the CLI polls and, on
// approval, receives a cert ISSUED INSIDE the redeem txn from the stored CSR and
// the frozen approver tuple. The cert is NEVER persisted (no leak yields a
// signable secret); the device_code/user_code are stored hashed.

var (
	bucketDeviceCodes = []byte("device_codes") // sha256(device_code) -> DeviceGrant
	bucketUserCodes   = []byte("user_codes")   // sha256(user_code) -> sha256(device_code)
)

// Device-grant lifecycle states.
const (
	deviceStatePending  = "pending"
	deviceStateApproved = "approved"
	deviceStateDenied   = "denied"
	deviceStateRedeemed = "redeemed"
)

// DeviceGrant is one in-flight CLI login.
type DeviceGrant struct {
	DeviceHash   string `json:"device_hash"`    // sha256(device_code) — bucket key
	UserCodeHash string `json:"user_code_hash"` // sha256(normalized user_code)
	CSRPem       []byte `json:"csr_pem"`        // CLI's CSR (PUBLIC material only)
	ClientName   string `json:"client_name"`
	SourceIP     string `json:"source_ip"`
	State        string `json:"state"`

	// Bound at approval, from the approving console session (server-side, never
	// client-supplied —).
	ApprovedUser     string   `json:"approved_user,omitempty"`
	ApprovedSubject  string   `json:"approved_subject,omitempty"`
	ApprovedProvider string   `json:"approved_provider,omitempty"`
	ApprovedWS       string   `json:"approved_ws,omitempty"`
	ApprovedRoles    []string `json:"approved_roles,omitempty"`
	UpstreamExp      int64    `json:"upstream_exp,omitempty"` // caps the cert TTL
	ApprovedBy       string   `json:"approved_by,omitempty"`

	CreatedUnix  int64 `json:"created_unix"`
	ExpiresUnix  int64 `json:"expires_unix"`
	Interval     int32 `json:"interval"`
	LastPollUnix int64 `json:"last_poll_unix"`
}

// crockford is the Crockford base32 alphabet minus ambiguous I/L/O/U — a typed
// user_code is unambiguous.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newUserCode returns a formatted 8-char (40-bit) user code, e.g. "K7QW-3FMP".
func newUserCode() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	var sb strings.Builder
	for i, x := range b {
		if i == 4 {
			sb.WriteByte('-')
		}
		sb.WriteByte(crockford[int(x)%len(crockford)])
	}
	return sb.String(), nil
}

// normalizeUserCode upper-cases and strips separators/whitespace so a human can
// type "k7qw 3fmp" or "k7qw-3fmp" interchangeably.
func normalizeUserCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	return strings.NewReplacer("-", "", " ", "").Replace(s)
}

func (s *bboltStore) PutDeviceGrant(g *DeviceGrant) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		if err := putJSON(tx, bucketDeviceCodes, g.DeviceHash, g); err != nil {
			return err
		}
		return tx.Bucket(bucketUserCodes).Put([]byte(g.UserCodeHash), []byte(g.DeviceHash))
	})
}

func (s *bboltStore) getDeviceGrantTx(tx *bbolt.Tx, deviceHash string) (*DeviceGrant, error) {
	var g DeviceGrant
	if err := getJSON(tx, bucketDeviceCodes, deviceHash, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

// GetDeviceGrantByUserCode resolves a (normalized) user code to its grant, for
// the approval page. Returns ErrNotFound for unknown codes.
func (s *bboltStore) GetDeviceGrantByUserCode(userCode string) (*DeviceGrant, error) {
	uh := hashToken(normalizeUserCode(userCode))
	var g *DeviceGrant
	err := s.db.View(func(tx *bbolt.Tx) error {
		dh := tx.Bucket(bucketUserCodes).Get([]byte(uh))
		if dh == nil {
			return ErrNotFound
		}
		var err error
		g, err = s.getDeviceGrantTx(tx, string(dh))
		return err
	})
	return g, err
}

// ApproveDeviceGrant binds the approver tuple to a pending grant (by user code),
// atomically. mutate fills the approval fields from the approving session.
func (s *bboltStore) ApproveDeviceGrant(userCode string, mutate func(*DeviceGrant) error) error {
	uh := hashToken(normalizeUserCode(userCode))
	return s.db.Update(func(tx *bbolt.Tx) error {
		dh := tx.Bucket(bucketUserCodes).Get([]byte(uh))
		if dh == nil {
			return ErrNotFound
		}
		g, err := s.getDeviceGrantTx(tx, string(dh))
		if err != nil {
			return err
		}
		if g.State != deviceStatePending {
			return fmt.Errorf("device grant is %s, not pending", g.State)
		}
		if time.Now().Unix() >= g.ExpiresUnix {
			return fmt.Errorf("device grant expired")
		}
		if err := mutate(g); err != nil {
			return err
		}
		return putJSON(tx, bucketDeviceCodes, g.DeviceHash, g)
	})
}

// DenyDeviceGrant marks a pending grant denied (by user code).
func (s *bboltStore) DenyDeviceGrant(userCode string) error {
	return s.ApproveDeviceGrant(userCode, func(g *DeviceGrant) error {
		g.State = deviceStateDenied
		return nil
	})
}

// deviceTokenError is an RFC 8628 token-endpoint error (authorization_pending,
// slow_down, access_denied, expired_token).
type deviceTokenError struct{ code string }

func (e deviceTokenError) Error() string { return e.code }

// PollDeviceGrant runs the RFC 8628 token-endpoint state machine for one poll.
// On success it issues the cert INSIDE the redeem txn (issue is called with the
// frozen approver tuple) and returns the cert PEM; otherwise a deviceTokenError.
// slow_down is enforced server-side by bumping the interval.
func (s *bboltStore) PollDeviceGrant(deviceCode string, now int64, issue func(g *DeviceGrant) ([]byte, error)) ([]byte, error) {
	dh := hashToken(deviceCode)
	var certPEM []byte
	err := s.db.Update(func(tx *bbolt.Tx) error {
		g, err := s.getDeviceGrantTx(tx, dh)
		if err != nil {
			return deviceTokenError{"expired_token"} // unknown == expired/invalid
		}
		if now >= g.ExpiresUnix {
			_ = tx.Bucket(bucketDeviceCodes).Delete([]byte(dh))
			_ = tx.Bucket(bucketUserCodes).Delete([]byte(g.UserCodeHash))
			return deviceTokenError{"expired_token"}
		}
		// Terminal states resolve regardless of poll timing.
		switch g.State {
		case deviceStateDenied:
			_ = tx.Bucket(bucketDeviceCodes).Delete([]byte(dh))
			_ = tx.Bucket(bucketUserCodes).Delete([]byte(g.UserCodeHash))
			return deviceTokenError{"access_denied"}
		case deviceStateRedeemed:
			return deviceTokenError{"expired_token"} // already consumed (single-use)
		case deviceStateApproved:
			// Authorization gate: a SUSPENDED principal gets no
			// cert even though their login succeeded — authn != authz. Refuse here
			// (inside the redeem txn) rather than leak the bbolt tx to the caller.
			if isSuspendedTx(tx, g.ApprovedWS, g.ApprovedProvider, g.ApprovedSubject) {
				return deviceTokenError{"access_denied"}
			}
			pem, ierr := issue(g) // cert minted inside the txn; never persisted
			if ierr != nil {
				return ierr // rolls the txn back; the grant stays approved for retry
			}
			certPEM = pem
			g.State = deviceStateRedeemed
			return putJSON(tx, bucketDeviceCodes, g.DeviceHash, g)
		}
		// Still pending: throttle a too-fast poll (RFC 8628 slow_down).
		if g.LastPollUnix > 0 && now-g.LastPollUnix < int64(g.Interval) {
			g.Interval += 5
			g.LastPollUnix = now
			_ = putJSON(tx, bucketDeviceCodes, dh, g)
			return deviceTokenError{"slow_down"}
		}
		g.LastPollUnix = now
		_ = putJSON(tx, bucketDeviceCodes, dh, g)
		return deviceTokenError{"authorization_pending"}
	})
	if err != nil {
		return nil, err
	}
	return certPEM, nil
}

// countDeviceGrants returns the number of stored device grants (DoS backstop).
func (s *bboltStore) countDeviceGrants() (int, error) {
	n := 0
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketDeviceCodes).ForEach(func(_, _ []byte) error { n++; return nil })
	})
	return n, err
}

// SweepExpiredDeviceGrants drops expired grants (called from the reauth sweep).
func (s *bboltStore) SweepExpiredDeviceGrants(now int64) (int, error) {
	n := 0
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketDeviceCodes)
		uc := tx.Bucket(bucketUserCodes)
		var dead []*DeviceGrant
		if err := b.ForEach(func(_, v []byte) error {
			var g DeviceGrant
			if err := json.Unmarshal(v, &g); err != nil {
				return err
			}
			if now >= g.ExpiresUnix {
				dead = append(dead, &g)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, g := range dead {
			_ = b.Delete([]byte(g.DeviceHash))
			_ = uc.Delete([]byte(g.UserCodeHash))
			n++
		}
		return nil
	})
	return n, err
}
