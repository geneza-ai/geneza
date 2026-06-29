package controller

import (
	"encoding/json"
	"time"

	bbolt "go.etcd.io/bbolt"

	"geneza.io/internal/types"
)

// Relay fleet presence: each relay heartbeats its identity, region, addresses and
// server-cert public key to the controller registrar, which records it here. The
// leader periodically assembles these rows into the signed relay map inside the
// ClusterConfig. This is eventual presence data (rebuilt from heartbeats), NOT a
// deny-path or single-use invariant, so a plain upsert is correct — no
// SERIALIZABLE transaction. The whole path is dead code on the single-node bbolt
// store (a region is refused there), so it never runs in a single-node deploy.

var bucketRelays = []byte("relays") // global: "<region>/<relayID>" -> RelayRecord

// RelayRecord is one relay's last heartbeat: its signed-map entry plus when it
// was last seen, so a stale relay can be expired out of the fleet. Version is the
// relay binary's build version for the operator fleet view; it lives ONLY on this
// presence row (alongside LastSeenUnix), never on the embedded RelayNode, so the
// signed relay map's bytes are unaffected by carrying it.
type RelayRecord struct {
	types.RelayNode
	LastSeenUnix int64  `json:"last_seen_unix"`
	Version      string `json:"version,omitempty"`
	// ActiveCount is the relay's live splice + control-mux count at its last
	// heartbeat: the drained-gate observation. A draining relay's count falling to 0
	// is what tells a rollout the relay has cleared and is safe to swap. It rides the
	// presence row only (never the signed map), alongside LastSeenUnix/Version.
	ActiveCount int32 `json:"active_count,omitempty"`
	// CertSerial is the relay's current identity-cert serial (hex), refreshed on every
	// register and on renewal. Presence row only — the value an operator passes to
	// RevokeCert to decommission the relay, surfaced because renewal rotates it.
	CertSerial string `json:"cert_serial,omitempty"`
	// SealPub is the relay's ephemeral X25519 public key (from its mTLS heartbeat)
	// the controller seals this relay's funnel certs to. Presence row only.
	SealPub []byte `json:"seal_pub,omitempty"`
	// FunnelIP is the relay's public IP that funnel hostnames resolve to (empty
	// unless it serves funnel). The funnel-DNS reconciler publishes A records to it.
	FunnelIP string `json:"funnel_ip,omitempty"`
}

func relayKey(regionID, relayID string) string { return regionID + "/" + relayID }

// --- bbolt ---

func (s *bboltStore) UpsertRelay(rec *RelayRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return putJSON(tx, bucketRelays, relayKey(rec.RegionID, rec.RelayID), rec)
	})
}

func (s *bboltStore) ListRelays(region string) ([]*RelayRecord, error) {
	var out []*RelayRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketRelays)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var rec RelayRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if region == "" || rec.RegionID == region {
				out = append(out, &rec)
			}
			return nil
		})
	})
	return out, err
}

func (s *bboltStore) ExpireStaleRelays(ttl time.Duration) (int, error) {
	cutoff := time.Now().Add(-ttl).Unix()
	n := 0
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketRelays)
		if b == nil {
			return nil
		}
		var dead [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			var rec RelayRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.LastSeenUnix < cutoff {
				dead = append(dead, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range dead {
			if err := b.Delete(k); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// --- sqlStore ---

func (s *sqlStore) UpsertRelay(rec *RelayRecord) error {
	doc, err := marshalDoc(rec)
	if err != nil {
		return err
	}
	_, err = s.exec(s.ctx(), s.db, `INSERT INTO relays (region_id, relay_id, lastseen_unix, doc) VALUES ($1, $2, $3, $4::jsonb)
		 ON CONFLICT (region_id, relay_id) DO UPDATE SET lastseen_unix = EXCLUDED.lastseen_unix, doc = EXCLUDED.doc`,
		rec.RegionID, rec.RelayID, rec.LastSeenUnix, doc)
	return err
}

func (s *sqlStore) ListRelays(region string) ([]*RelayRecord, error) {
	if region == "" {
		return sqlListDocs[RelayRecord](s.ctx(), s, s.db, `SELECT doc FROM relays ORDER BY region_id, relay_id`)
	}
	return sqlListDocs[RelayRecord](s.ctx(), s, s.db,
		`SELECT doc FROM relays WHERE region_id=$1 ORDER BY relay_id`, region)
}

func (s *sqlStore) ExpireStaleRelays(ttl time.Duration) (int, error) {
	ct, err := s.exec(s.ctx(), s.db, `DELETE FROM relays WHERE lastseen_unix < $1`, time.Now().Add(-ttl).Unix())
	if err != nil {
		return 0, err
	}
	n, _ := ct.RowsAffected()
	return int(n), nil
}
