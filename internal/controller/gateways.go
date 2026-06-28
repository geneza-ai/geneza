package controller

import (
	"encoding/json"
	"time"

	bbolt "go.etcd.io/bbolt"

	"geneza.io/internal/types"
)

// Controller fleet presence: each controller upserts its own dialable endpoint here on a
// timer, and the rows are assembled into the signed ControllerEndpoints set inside the
// ClusterConfig — the discovery + failover view agents/relays/clients re-home
// across. Like the relay fleet this is eventual presence data (rebuilt from
// heartbeats), NOT a deny-path or single-use invariant, so a plain upsert is
// correct. The whole path is dead code on the single-node bbolt store (no fleet to
// discover), so it never runs in a single-node deploy.

var bucketControllers = []byte("controllers") // global: controllerID -> ControllerRecord

// ControllerRecord is one controller's last self-heartbeat: its signed-map endpoint plus
// when it was last seen, so a dead controller can be expired out of the fleet view.
// Version is the controller binary's build version for the operator fleet view; it
// lives ONLY on this presence row (alongside LastSeenUnix), never on the embedded
// ControllerEndpoint, so the signed discovery set's bytes are unaffected by it.
type ControllerRecord struct {
	types.ControllerEndpoint
	LastSeenUnix int64  `json:"last_seen_unix"`
	Version      string `json:"version,omitempty"`
}

// --- bbolt ---

func (s *bboltStore) UpsertController(rec *ControllerRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return putJSON(tx, bucketControllers, rec.ControllerID, rec)
	})
}

func (s *bboltStore) ListControllers() ([]*ControllerRecord, error) {
	var out []*ControllerRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketControllers)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var rec ControllerRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			out = append(out, &rec)
			return nil
		})
	})
	return out, err
}

func (s *bboltStore) ExpireStaleControllers(ttl time.Duration) (int, error) {
	cutoff := time.Now().Add(-ttl).Unix()
	n := 0
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketControllers)
		if b == nil {
			return nil
		}
		var dead [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			var rec ControllerRecord
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

func (s *sqlStore) UpsertController(rec *ControllerRecord) error {
	doc, err := marshalDoc(rec)
	if err != nil {
		return err
	}
	_, err = s.exec(s.ctx(), s.db, `INSERT INTO controllers (controller_id, lastseen_unix, doc) VALUES ($1, $2, $3::jsonb)
		 ON CONFLICT (controller_id) DO UPDATE SET lastseen_unix = EXCLUDED.lastseen_unix, doc = EXCLUDED.doc`,
		rec.ControllerID, rec.LastSeenUnix, doc)
	return err
}

func (s *sqlStore) ListControllers() ([]*ControllerRecord, error) {
	return sqlListDocs[ControllerRecord](s.ctx(), s, s.db, `SELECT doc FROM controllers ORDER BY controller_id`)
}

func (s *sqlStore) ExpireStaleControllers(ttl time.Duration) (int, error) {
	ct, err := s.exec(s.ctx(), s.db, `DELETE FROM controllers WHERE lastseen_unix < $1`, time.Now().Add(-ttl).Unix())
	if err != nil {
		return 0, err
	}
	n, _ := ct.RowsAffected()
	return int(n), nil
}
