package controller

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	bbolt "go.etcd.io/bbolt"
)

// Funnel: deliberately exposing one workspace service to the PUBLIC internet
// (the Tailscale-Funnel analog, see docs/managed-domain-spec.md §1b). A binding
// maps a public hostname — which MUST be under one of the workspace's managed
// subdomain reservations — to a target service on the overlay. The controller mints
// a NARROW leaf cert per hostname (never the workspace wildcard) and a pool of
// relays terminate public TLS for it and reverse-proxy into the overlay. This is
// the one place relays stop being payload-blind, by explicit per-service opt-in.

const maxWorkspaceFunnels = 10

var bucketFunnels = []byte("funnel_bindings") // key: hostname -> FunnelBinding

var (
	errFunnelTaken = errors.New("funnel hostname already in use")
	errFunnelLimit = errors.New("workspace funnel limit reached")
	errFunnelHost  = errors.New("funnel hostname is not under a workspace reservation")
)

// FunnelBinding is one public exposure: Hostname (a public FQDN under a
// reservation) → Target (host:port on the overlay) on NodeID, proxied as Mode.
type FunnelBinding struct {
	Hostname    string `json:"hostname"`
	WorkspaceID string `json:"workspace_id"`
	NodeID      string `json:"node_id"`
	Target      string `json:"target"` // host:port reachable on the overlay
	Mode        string `json:"mode"`   // "http" | "tcp"
	// RegToken is the controller-minted secret that authorizes funnel registration:
	// delivered to the owning agent (in FunnelServe) and to relays (in the sealed
	// cert push), so a relay only honors a registration presenting this exact
	// token. Without it, any agent could claim any tenant's public hostname.
	RegToken    string `json:"reg_token,omitempty"`
	CreatedUnix int64  `json:"created_unix"`
	CreatedBy   string `json:"created_by,omitempty"`
}

// --- bbolt ---

func (s *bboltStore) CreateFunnelBinding(rec *FunnelBinding, max int) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketFunnels)
		if raw := b.Get([]byte(rec.Hostname)); raw != nil {
			var ex FunnelBinding
			if err := json.Unmarshal(raw, &ex); err != nil {
				return err
			}
			if ex.WorkspaceID != rec.WorkspaceID {
				return errFunnelTaken
			}
			return putJSONB(b, rec.Hostname, rec) // owner may update target/mode
		}
		count := 0
		if err := b.ForEach(func(_, v []byte) error {
			var f FunnelBinding
			if err := json.Unmarshal(v, &f); err != nil {
				return err
			}
			if f.WorkspaceID == rec.WorkspaceID {
				count++
			}
			return nil
		}); err != nil {
			return err
		}
		if count >= max {
			return errFunnelLimit
		}
		return putJSONB(b, rec.Hostname, rec)
	})
}

func (s *bboltStore) GetFunnelBinding(hostname string) (*FunnelBinding, error) {
	var rec FunnelBinding
	err := s.db.View(func(tx *bbolt.Tx) error {
		return getJSONB(tx.Bucket(bucketFunnels), hostname, &rec)
	})
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *bboltStore) ListWorkspaceFunnels(workspaceID string) ([]*FunnelBinding, error) {
	var out []*FunnelBinding
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketFunnels).ForEach(func(_, v []byte) error {
			var f FunnelBinding
			if err := json.Unmarshal(v, &f); err != nil {
				return err
			}
			if f.WorkspaceID == workspaceID {
				out = append(out, &f)
			}
			return nil
		})
	})
	return out, err
}

func (s *bboltStore) ListFunnelBindings() ([]*FunnelBinding, error) {
	var out []*FunnelBinding
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketFunnels).ForEach(func(_, v []byte) error {
			var f FunnelBinding
			if err := json.Unmarshal(v, &f); err != nil {
				return err
			}
			out = append(out, &f)
			return nil
		})
	})
	return out, err
}

func (s *bboltStore) DeleteFunnelBinding(hostname, workspaceID string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketFunnels)
		raw := b.Get([]byte(hostname))
		if raw == nil {
			return nil
		}
		var ex FunnelBinding
		if err := json.Unmarshal(raw, &ex); err != nil {
			return err
		}
		if ex.WorkspaceID != workspaceID {
			return errFunnelTaken
		}
		return b.Delete([]byte(hostname))
	})
}

// --- sql ---

func (s *sqlStore) CreateFunnelBinding(rec *FunnelBinding, max int) error {
	return s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		var raw []byte
		err := s.queryRow(s.ctx(), tx, `SELECT doc FROM funnel_bindings WHERE hostname=$1 FOR UPDATE`, rec.Hostname).Scan(&raw)
		if err == nil {
			var ex FunnelBinding
			if uerr := json.Unmarshal(raw, &ex); uerr != nil {
				return uerr
			}
			if ex.WorkspaceID != rec.WorkspaceID {
				return errFunnelTaken
			}
		} else if errors.Is(err, sql.ErrNoRows) {
			var count int
			if err := s.queryRow(s.ctx(), tx, `SELECT COUNT(*) FROM funnel_bindings WHERE workspace_id=$1`, rec.WorkspaceID).Scan(&count); err != nil {
				return err
			}
			if count >= max {
				return errFunnelLimit
			}
		} else {
			return err
		}
		doc, err := marshalDoc(rec)
		if err != nil {
			return err
		}
		_, err = s.exec(s.ctx(), tx, `INSERT INTO funnel_bindings (hostname, workspace_id, doc) VALUES ($1, $2, $3::jsonb)
			 ON CONFLICT (hostname) DO UPDATE SET workspace_id = EXCLUDED.workspace_id, doc = EXCLUDED.doc`,
			rec.Hostname, rec.WorkspaceID, doc)
		return err
	})
}

func (s *sqlStore) GetFunnelBinding(hostname string) (*FunnelBinding, error) {
	return sqlGetDoc[FunnelBinding](s.ctx(), s, s.db, `SELECT doc FROM funnel_bindings WHERE hostname=$1`, hostname)
}

func (s *sqlStore) ListWorkspaceFunnels(workspaceID string) ([]*FunnelBinding, error) {
	return sqlListDocs[FunnelBinding](s.ctx(), s, s.db, `SELECT doc FROM funnel_bindings WHERE workspace_id=$1 ORDER BY hostname`, workspaceID)
}

func (s *sqlStore) ListFunnelBindings() ([]*FunnelBinding, error) {
	return sqlListDocs[FunnelBinding](s.ctx(), s, s.db, `SELECT doc FROM funnel_bindings ORDER BY hostname`)
}

func (s *sqlStore) DeleteFunnelBinding(hostname, workspaceID string) error {
	_, err := s.exec(s.ctx(), s.db, `DELETE FROM funnel_bindings WHERE hostname=$1 AND workspace_id=$2`, hostname, workspaceID)
	return err
}

// --- controller logic ---

// hostnameUnderReservation reports whether the workspace owns a reservation the
// hostname falls under (== the zone or one label below it isn't required — any
// name under the reserved zone is fair game for a funnel).
func (s *Server) hostnameUnderReservation(ws, hostname string) bool {
	subs, err := s.store.ListWorkspaceSubdomains(ws)
	if err != nil {
		return false
	}
	for _, r := range subs {
		zone := r.Zone()
		if hostname == zone || strings.HasSuffix(hostname, "."+zone) {
			return true
		}
	}
	return false
}

// createFunnel validates and records a public exposure for the caller's
// workspace. The hostname must be a valid DNS name under one of the workspace's
// reservations; target must be host:port; mode defaults to http.
func (s *Server) createFunnel(ws, hostname, nodeID, target, mode, by string) (*FunnelBinding, error) {
	if !s.cfg.ManagedDomain.enabled() {
		return nil, errManagedDomainDisabled
	}
	hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	if !validFunnelHostname(hostname) {
		return nil, fmt.Errorf("invalid funnel hostname %q", hostname)
	}
	if !s.hostnameUnderReservation(ws, hostname) {
		return nil, errFunnelHost
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		return nil, fmt.Errorf("target must be host:port: %w", err)
	}
	switch mode {
	case "", "http":
		mode = "http"
	case "tcp":
	default:
		return nil, fmt.Errorf("mode must be http or tcp, got %q", mode)
	}
	rec := &FunnelBinding{
		Hostname: hostname, WorkspaceID: ws, NodeID: nodeID, Target: target, Mode: mode,
		RegToken: newFunnelRegToken(), CreatedUnix: time.Now().Unix(), CreatedBy: by,
	}
	// Preserve the registration token across an update by the same owner, so a
	// re-create (target/mode change) doesn't churn the relays' authorization.
	if prev, err := s.store.GetFunnelBinding(hostname); err == nil && prev.WorkspaceID == ws && prev.RegToken != "" {
		rec.RegToken = prev.RegToken
	}
	if err := s.store.CreateFunnelBinding(rec, maxWorkspaceFunnels); err != nil {
		return nil, err
	}
	_ = s.audit.AppendWS(ws, "funnel_create", by, nodeID, "", map[string]string{
		"workspace": ws, "hostname": hostname, "target": target, "mode": mode,
	})
	s.managedCerts.kickReconcile()    // mint the narrow leaf now
	s.pushNodeFunnels(ws, rec.NodeID) // tell the agent to start serving the funnel
	return rec, nil
}

func (s *Server) deleteFunnel(ws, hostname, by string) error {
	hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	rec, _ := s.store.GetFunnelBinding(hostname)
	if err := s.store.DeleteFunnelBinding(hostname, ws); err != nil {
		return err
	}
	_ = s.audit.AppendWS(ws, "funnel_delete", by, "", "", map[string]string{"workspace": ws, "hostname": hostname})
	s.managedCerts.kickReconcile() // GC the leaf on the next reconcile
	if rec != nil {
		s.pushNodeFunnels(ws, rec.NodeID) // tell the agent to stop serving it
	}
	return nil
}

// newFunnelRegToken mints an unguessable funnel registration secret.
func newFunnelRegToken() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

// validFunnelHostname accepts a multi-label DNS name (each label RFC-1035).
func validFunnelHostname(h string) bool {
	if h == "" || len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if !validSubdomainLabel(label) {
			return false
		}
	}
	return true
}
