package controller

import (
	"database/sql"
	"errors"
	"time"

	bbolt "go.etcd.io/bbolt"

	"geneza.io/internal/types"
)

// Affinity directory: which controller currently owns each agent's live control
// stream, plus which controller holds each session's client signaling stream, plus a
// durable copy of each agent's advertised services. In a multi-controller deployment
// a control-plane push raised on one controller uses these to reach the controller that
// actually holds the stream. The epoch is a fence token: every (re)connect bumps
// it, so a delivery carrying a lower epoch is by construction a superseded
// ("zombie") stream and is routed to the current owner instead of being silently
// lost. The single-node store runs the same logic — one controller always owns
// everything, so it is a no-op in effect, but the epoch bump also closes the
// single-node window where a half-open stream could swallow a revoke.

var bucketAgentAffinity = []byte("agent_affinity") // global: nodeID -> agentAffinityRow

const (
	childAdvServices = "adv_services" // per-ws: nodeID -> advServicesRow
)

type agentAffinityRow struct {
	NodeID      string `json:"node_id"`
	ControllerID   string `json:"controller_id"`
	Epoch       int64  `json:"epoch"`
	ClaimedUnix int64  `json:"claimed_unix"`
}

type advServicesRow struct {
	Epoch    int64           `json:"epoch"`
	Services []types.Service `json:"services,omitempty"`
}

// --- bbolt ---

func (s *bboltStore) ClaimAgentAffinity(nodeID, controllerID string, now time.Time) (int64, error) {
	var epoch int64
	err := s.db.Update(func(tx *bbolt.Tx) error {
		var row agentAffinityRow
		if e := getJSON(tx, bucketAgentAffinity, nodeID, &row); e != nil && !errors.Is(e, ErrNotFound) {
			return e
		}
		row.Epoch++ // a (re)connect to any controller always outranks a stale one
		row.NodeID, row.ControllerID, row.ClaimedUnix = nodeID, controllerID, now.Unix()
		epoch = row.Epoch
		return putJSON(tx, bucketAgentAffinity, nodeID, &row)
	})
	return epoch, err
}

func (s *bboltStore) AgentAffinity(nodeID string) (string, int64, bool) {
	var row agentAffinityRow
	if err := s.db.View(func(tx *bbolt.Tx) error { return getJSON(tx, bucketAgentAffinity, nodeID, &row) }); err != nil {
		return "", 0, false
	}
	return row.ControllerID, row.Epoch, true
}

func (s *bboltStore) ReleaseAgentAffinity(nodeID, controllerID string, epoch int64) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		var row agentAffinityRow
		if e := getJSON(tx, bucketAgentAffinity, nodeID, &row); e != nil {
			if errors.Is(e, ErrNotFound) {
				return nil
			}
			return e
		}
		if row.ControllerID != controllerID || row.Epoch != epoch {
			return nil // superseded: keep the live owner
		}
		return tx.Bucket(bucketAgentAffinity).Delete([]byte(nodeID))
	})
}

func (s *bboltStore) PutAdvertisedServices(ws, nodeID string, epoch int64, svcs []types.Service) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, ws, childAdvServices)
		if err != nil {
			return err
		}
		var existing advServicesRow
		if e := getJSONB(b, nodeID, &existing); e == nil && existing.Epoch > epoch {
			return nil // an older claim never overwrites a newer connection's set
		}
		return putJSONB(b, nodeID, &advServicesRow{Epoch: epoch, Services: svcs})
	})
}

func (s *bboltStore) AdvertisedServices(ws, nodeID string) ([]types.Service, error) {
	var row advServicesRow
	err := s.db.View(func(tx *bbolt.Tx) error {
		return getJSONB(wsChildR(tx, ws, childAdvServices), nodeID, &row)
	})
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return row.Services, nil
}

func (s *bboltStore) ClearAdvertisedServices(ws, nodeID string, epoch int64) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childAdvServices)
		if b == nil {
			return nil
		}
		var row advServicesRow
		if e := getJSONB(b, nodeID, &row); e != nil {
			return nil
		}
		if row.Epoch != epoch {
			return nil // a newer connection owns the set
		}
		return b.Delete([]byte(nodeID))
	})
}

// --- sqlStore ---

func (s *sqlStore) ClaimAgentAffinity(nodeID, controllerID string, now time.Time) (int64, error) {
	var epoch int64
	err := s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		var e error
		epoch, e = s.dialect.claimAffinity(s.ctx(), tx, nodeID, controllerID, now.Unix())
		return e
	})
	return epoch, err
}

func (s *sqlStore) AgentAffinity(nodeID string) (string, int64, bool) {
	var gw string
	var ep int64
	if err := s.queryRow(s.ctx(), s.db, `SELECT controller_id, epoch FROM agent_affinity WHERE node_id=$1`, nodeID).Scan(&gw, &ep); err != nil {
		return "", 0, false
	}
	return gw, ep, true
}

func (s *sqlStore) ReleaseAgentAffinity(nodeID, controllerID string, epoch int64) error {
	_, err := s.exec(s.ctx(), s.db, `DELETE FROM agent_affinity WHERE node_id=$1 AND controller_id=$2 AND epoch=$3`,
		nodeID, controllerID, epoch) // 0 rows affected = already superseded = nil, matching bbolt
	return err
}

func (s *sqlStore) PutAdvertisedServices(ws, nodeID string, epoch int64, svcs []types.Service) error {
	doc, err := marshalDoc(svcs)
	if err != nil {
		return err
	}
	return s.dialect.putAdvertisedServices(s.ctx(), s.db, ws, nodeID, epoch, doc)
}

func (s *sqlStore) AdvertisedServices(ws, nodeID string) ([]types.Service, error) {
	out, err := sqlGetDoc[[]types.Service](s.ctx(), s, s.db,
		`SELECT doc FROM advertised_services WHERE workspace_id=$1 AND node_id=$2`, ws, nodeID)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return *out, nil
}

func (s *sqlStore) ClearAdvertisedServices(ws, nodeID string, epoch int64) error {
	_, err := s.exec(s.ctx(), s.db, `DELETE FROM advertised_services WHERE workspace_id=$1 AND node_id=$2 AND epoch=$3`, ws, nodeID, epoch)
	return err
}
