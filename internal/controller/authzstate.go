package controller

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	bbolt "go.etcd.io/bbolt"
)

// Authorization state — the layer that decides whether a principal may act RIGHT
// NOW, separate from authentication (whether their token/cert is valid). A
// suspension is a persistent, principal-scoped, sticky-until-lift DENY: a
// suspended principal keeps a perfectly valid keystone/oidc token and mTLS cert,
// but every new session is refused and every live one is torn down, across
// re-login, until an admin lifts it. This is the "revoke authorization even with
// a valid token" the operator asked for.

var bucketSuspensions = []byte("suspensions") // global: principalKey -> SuspensionRecord

// SuspensionRecord is one suspended principal. Keyed by (workspace, provider,
// subject) — NEVER by the mutable display name nor a cert serial (which
// dies at re-login; we must deny the NEXT login too).
type SuspensionRecord struct {
	Workspace     string `json:"workspace"`
	Provider      string `json:"provider"`
	Subject       string `json:"subject"`
	Username      string `json:"username,omitempty"` // audit/display only, NEVER the key
	Reason        string `json:"reason,omitempty"`
	SuspendedBy   string `json:"suspended_by,omitempty"`
	SuspendedUnix int64  `json:"suspended_unix"`
}

// principalKey is the durable authorization key. It normalizes the provider so
// the key WRITTEN by SuspendPrincipal (from a console session, provider e.g.
// "keystone") and the key READ at the broker/sweep (from a cert whose provider
// claim is "device:keystone") are BYTE-EQUAL for the same login.
func principalKey(ws, provider, subject string) string {
	return ws + "|" + normProvider(provider) + "|" + subject
}

func normProvider(provider string) string { return strings.TrimPrefix(provider, "device:") }

// suspendable reports whether a principal is member-suspendable: only login
// principals (which always carry a stable Subject post Subject-plumbing). An
// EMPTY subject is an operational cert (break-glass / node) — NOT member-
// suspendable (those are killed via the cert-revocation denylist), so the
// suspension check no-ops for them rather than denying every operator RPC.
func suspendable(subject string) bool { return subject != "" }

// SuspendPrincipal writes the sticky deny row. A non-empty subject is required
// (a login principal is always keyable; refuse otherwise — fail closed).
func (s *bboltStore) SuspendPrincipal(ws, provider, subject, username, by, reason string) error {
	if subject == "" {
		return fmt.Errorf("cannot suspend: empty subject (principal is not keyable)")
	}
	rec := &SuspensionRecord{
		Workspace: ws, Provider: normProvider(provider), Subject: subject, Username: username,
		Reason: reason, SuspendedBy: by, SuspendedUnix: time.Now().Unix(),
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		return putJSON(tx, bucketSuspensions, principalKey(ws, provider, subject), rec)
	})
}

func (s *bboltStore) LiftSuspension(ws, provider, subject string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketSuspensions).Delete([]byte(principalKey(ws, provider, subject)))
	})
}

// IsSuspended reports whether a login principal is currently suspended. An empty
// subject (operational cert) is never member-suspended. A local read error fails
// OPEN (single-node behavior the deny cache's fail-open branch preserves).
func (s *bboltStore) IsSuspended(ws, provider, subject string) bool {
	susp, _ := s.IsSuspendedE(ws, provider, subject)
	return susp
}

// IsSuspendedE is the error-returning twin the deny cache fronts.
func (s *bboltStore) IsSuspendedE(ws, provider, subject string) (bool, error) {
	if !suspendable(subject) {
		return false, nil
	}
	var susp bool
	err := s.db.View(func(tx *bbolt.Tx) error {
		susp = isSuspendedTx(tx, ws, provider, subject)
		return nil
	})
	return susp, err
}

// isSuspendedTx is the tx-scoped check — MUST be used inside an existing Update
// (e.g. the device-redeem txn) to avoid a nested bbolt transaction deadlock
// (single-writer). A corrupt row fails closed (deny).
func isSuspendedTx(tx *bbolt.Tx, ws, provider, subject string) bool {
	if !suspendable(subject) {
		return false
	}
	v := tx.Bucket(bucketSuspensions).Get([]byte(principalKey(ws, provider, subject)))
	if v == nil {
		return false
	}
	var rec SuspensionRecord
	if err := json.Unmarshal(v, &rec); err != nil {
		return true // corrupt suspension row => deny
	}
	return true
}

func (s *bboltStore) ListSuspensions(ws string) ([]*SuspensionRecord, error) {
	var out []*SuspensionRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketSuspensions).ForEach(func(_, v []byte) error {
			var rec SuspensionRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if ws == "" || rec.Workspace == ws {
				out = append(out, &rec)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SuspendedUnix > out[j].SuspendedUnix })
	return out, nil
}

// suspendedSet loads all suspension keys once (the sweep checks N sessions per
// tick — one map beats N bucket-gets).
func (s *bboltStore) suspendedSet() (map[string]bool, error) {
	set := map[string]bool{}
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketSuspensions).ForEach(func(k, _ []byte) error {
			set[string(k)] = true
			return nil
		})
	})
	return set, err
}

// --- node drift quarantine: the node-scoped sibling of a suspension ---
//
// A node quarantine is to a node what a suspension is to a login principal: a
// persistent, sticky-until-admin DENY layered on the Approved=false admission
// gate, separate from authentication (the node keeps a valid cert). The controller
// raises it automatically when it detects drift (the agent binary was swapped, or
// the node identity is in use from two hosts at once); an admin also raises it by
// hand via the same path the existing "Quarantine" button already uses
// (SetNodeApproval false). It is cleared only by an admin re-approval, which lifts
// the deny and this row together (see SetNodeApproval). Enforcement is the existing
// continuous-authz sweep + broker gate — this record only adds the cause and the
// re-enroll/anti-launder evidence; it is NOT a second enforcement engine.

var bucketQuarantines = []byte("quarantines") // global: quarantineKey -> QuarantineRecord

// QuarantineRecord is one quarantined node. Keyed by (workspace, node id). It also
// carries the node's stable host evidence (HostUUID) so a wipe-and-re-enroll of the
// SAME physical host is routed back to PENDING for admin review instead of
// laundering the quarantine away behind a fresh node id.
type QuarantineRecord struct {
	Workspace       string            `json:"workspace"`
	NodeID          string            `json:"node_id"`
	Reason          string            `json:"reason"` // binary_tamper | identity_clone | downgrade | manual
	Detail          map[string]string `json:"detail,omitempty"`
	QuarantinedBy   string            `json:"quarantined_by,omitempty"` // "system" or an admin name
	QuarantinedUnix int64             `json:"quarantined_unix"`
	HostUUID        string            `json:"host_uuid,omitempty"`
}

func quarantineKey(ws, nodeID string) string { return ws + "|" + nodeID }

// copyDetail defensively copies a caller's detail map so a later mutation of the
// caller's map cannot alter the persisted quarantine record.
func copyDetail(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// QuarantineNode flips a node's admission gate closed AND writes the sticky reason
// row in one transaction, so a drifted node is never left denied-without-cause nor
// caused-without-deny. Idempotent: re-quarantining refreshes the reason/detail.
// Returns the updated node for the caller's overlay repush.
func (s *bboltStore) QuarantineNode(ws, nodeID, reason, by string, detail map[string]string) (*NodeRecord, error) {
	var n NodeRecord
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, ws, childNodes)
		if err != nil {
			return err
		}
		if err := getJSONB(b, nodeID, &n); err != nil {
			return err
		}
		n.Approved = false
		n.ApprovedBy = ""
		n.ApprovedAtUnix = 0
		if err := putJSONB(b, nodeID, &n); err != nil {
			return err
		}
		rec := &QuarantineRecord{
			Workspace: ws, NodeID: nodeID, Reason: reason, Detail: copyDetail(detail),
			QuarantinedBy: by, QuarantinedUnix: time.Now().Unix(), HostUUID: n.Platform.HostUUID,
		}
		return putJSON(tx, bucketQuarantines, quarantineKey(ws, nodeID), rec)
	})
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// GetQuarantine returns the active quarantine for a node, or ErrNotFound.
func (s *bboltStore) GetQuarantine(ws, nodeID string) (*QuarantineRecord, error) {
	var rec QuarantineRecord
	var found bool
	err := s.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bucketQuarantines).Get([]byte(quarantineKey(ws, nodeID)))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &rec)
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotFound
	}
	return &rec, nil
}

// ListQuarantines returns active quarantines, newest first; ws=="" lists all.
func (s *bboltStore) ListQuarantines(ws string) ([]*QuarantineRecord, error) {
	var out []*QuarantineRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketQuarantines).ForEach(func(_, v []byte) error {
			var rec QuarantineRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if ws == "" || rec.Workspace == ws {
				out = append(out, &rec)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].QuarantinedUnix > out[j].QuarantinedUnix })
	return out, nil
}

// FindQuarantineByHostUUID returns an active quarantine in ws whose pinned host
// evidence matches uuid — the hook that keeps a re-enrolling quarantined host out
// of auto-approval even though it presents a brand-new node id. An empty uuid never
// matches (a host that cannot prove stable hardware identity is gated by node id
// alone — a documented limit of the software baseline).
func (s *bboltStore) FindQuarantineByHostUUID(ws, uuid string) (*QuarantineRecord, error) {
	if uuid == "" {
		return nil, ErrNotFound
	}
	var found *QuarantineRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketQuarantines).ForEach(func(_, v []byte) error {
			var rec QuarantineRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.Workspace == ws && rec.HostUUID == uuid {
				r := rec
				found = &r
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, ErrNotFound
	}
	return found, nil
}
