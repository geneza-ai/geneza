package controller

import (
	"encoding/json"
	"time"

	bbolt "go.etcd.io/bbolt"
)

// Agent fleet presence: each agent heartbeats its build version, health and
// session counts on its control stream. The stream is pinned to exactly ONE
// controller (agent affinity), so the in-memory Registry only knows the agents
// homed locally. The staged-rollout controller needs a fleet-wide view of which
// agents run which version and are healthy — across all controllers — so each
// controller records its homed agents' heartbeats here, in the shared store. Any
// controller can then evaluate a rollout wave's health regardless of where the
// agents are homed. This is eventual presence data rebuilt from heartbeats (not
// a deny-path invariant), so a plain upsert is correct.

var bucketAgentPresence = []byte("agent_presence") // global: nodeID -> AgentPresenceRecord

// AgentPresenceRecord is one agent's last heartbeat, shared across controllers. It
// mirrors the live-only fields of the in-memory AgentInfo that a rollout cares
// about (version + health + freshness); richer live state stays in the Registry.
type AgentPresenceRecord struct {
	NodeID       string `json:"node_id"`
	Version      string `json:"version,omitempty"`
	Healthy      bool   `json:"healthy"`
	Active       uint32 `json:"active,omitempty"`
	Detached     uint32 `json:"detached,omitempty"`
	LastSeenUnix int64  `json:"last_seen_unix"`
}

// --- bbolt ---

func (s *bboltStore) PutAgentPresence(rec *AgentPresenceRecord) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return putJSON(tx, bucketAgentPresence, rec.NodeID, rec)
	})
}

func (s *bboltStore) ListAgentPresence() ([]*AgentPresenceRecord, error) {
	var out []*AgentPresenceRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketAgentPresence)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var rec AgentPresenceRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			out = append(out, &rec)
			return nil
		})
	})
	return out, err
}

func (s *bboltStore) ExpireStaleAgentPresence(ttl time.Duration) (int, error) {
	cutoff := time.Now().Add(-ttl).Unix()
	n := 0
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketAgentPresence)
		if b == nil {
			return nil
		}
		var dead [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			var rec AgentPresenceRecord
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

func (s *sqlStore) PutAgentPresence(rec *AgentPresenceRecord) error {
	doc, err := marshalDoc(rec)
	if err != nil {
		return err
	}
	_, err = s.exec(s.ctx(), s.db, `INSERT INTO agent_presence (node_id, lastseen_unix, doc) VALUES ($1, $2, $3::jsonb)
		 ON CONFLICT (node_id) DO UPDATE SET lastseen_unix = EXCLUDED.lastseen_unix, doc = EXCLUDED.doc`,
		rec.NodeID, rec.LastSeenUnix, doc)
	return err
}

func (s *sqlStore) ListAgentPresence() ([]*AgentPresenceRecord, error) {
	return sqlListDocs[AgentPresenceRecord](s.ctx(), s, s.db, `SELECT doc FROM agent_presence ORDER BY node_id`)
}

func (s *sqlStore) ExpireStaleAgentPresence(ttl time.Duration) (int, error) {
	ct, err := s.exec(s.ctx(), s.db, `DELETE FROM agent_presence WHERE lastseen_unix < $1`, time.Now().Add(-ttl).Unix())
	if err != nil {
		return 0, err
	}
	n, _ := ct.RowsAffected()
	return int(n), nil
}
