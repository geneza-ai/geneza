package controller

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	bbolt "go.etcd.io/bbolt"
)

// Workspace subdomain reservations: a workspace admin claims a subdomain label
// on one of the configured managed domains (see docs/managed-domain-spec.md). A
// (domain, label) pair is globally unique — first to reserve it owns it — and a
// workspace may hold at most maxWorkspaceSubdomains of them. The reservation is
// the durable source of truth; the cert manager issues a wildcard per
// reservation. Reservations are keyed by their FQDN zone so uniqueness is a
// single keyed lookup, and both backends enforce the per-workspace cap inside
// the same atomic write so two concurrent claims cannot both slip past it.

// maxWorkspaceSubdomains caps reservations per workspace. Tunable upward later.
const maxWorkspaceSubdomains = 3

var bucketSubdomains = []byte("subdomain_reservations") // key: "<label>.<domain>" -> SubdomainReservation

var (
	errSubdomainTaken = errors.New("subdomain already reserved")
	errSubdomainLimit = errors.New("workspace subdomain limit reached")
)

// SubdomainReservation is one workspace's claim on a subdomain under a managed
// domain. The zone the wildcard covers is "<Label>.<Domain>".
type SubdomainReservation struct {
	Domain      string `json:"domain"` // managed base domain, e.g. "geneza.app"
	Label       string `json:"label"`  // chosen subdomain label, e.g. "acme-prod"
	WorkspaceID string `json:"workspace_id"`
	CreatedUnix int64  `json:"created_unix"`
	CreatedBy   string `json:"created_by,omitempty"`
}

// Zone is the FQDN the reservation's wildcard covers, "<label>.<domain>".
func (r *SubdomainReservation) Zone() string { return r.Label + "." + r.Domain }

func subdomainKey(domain, label string) string { return label + "." + domain }

var errManagedDomainDisabled = errors.New("managed domain is not enabled")

// validSubdomainLabel reports whether label is a single RFC-1035 DNS label
// (1–63 chars, [a-z0-9] with internal hyphens). The label is the workspace's
// chosen subdomain; the wildcard issued for it is one level below.
func validSubdomainLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}
	for i, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-':
			if i == 0 || i == len(label)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// reserveWorkspaceSubdomain claims a subdomain for a workspace on one of the
// configured managed domains. An empty label falls back to the workspace's
// derived default token. It enforces the managed-domain allowlist, label
// validity, global uniqueness, and the per-workspace cap (the last two atomically
// in the store).
func (s *Server) reserveWorkspaceSubdomain(workspaceID, domain, label, by string) (*SubdomainReservation, error) {
	if !s.cfg.ManagedDomain.enabled() {
		return nil, errManagedDomainDisabled
	}
	if !s.cfg.ManagedDomain.isManagedDomain(domain) {
		return nil, fmt.Errorf("%q is not a managed domain", domain)
	}
	label = strings.ToLower(strings.TrimSpace(label))
	if label == "" {
		label = managedWorkspaceToken(workspaceID)
	}
	if !validSubdomainLabel(label) {
		return nil, fmt.Errorf("invalid subdomain label %q", label)
	}
	rec := &SubdomainReservation{
		Domain: domain, Label: label, WorkspaceID: workspaceID,
		CreatedUnix: time.Now().Unix(), CreatedBy: by,
	}
	if err := s.store.ReserveSubdomain(rec, maxWorkspaceSubdomains); err != nil {
		return nil, err
	}
	_ = s.audit.AppendWS(workspaceID, "subdomain_reserve", by, "", "", map[string]string{
		"workspace": workspaceID, "zone": rec.Zone(),
	})
	s.managedCerts.kickReconcile() // issue the wildcard now, not on the next tick
	return rec, nil
}

// releaseWorkspaceSubdomain drops a workspace's reservation; the cert manager
// GCs the wildcard on its next tick.
func (s *Server) releaseWorkspaceSubdomain(workspaceID, domain, label, by string) error {
	if err := s.store.ReleaseSubdomain(domain, label, workspaceID); err != nil {
		return err
	}
	_ = s.audit.AppendWS(workspaceID, "subdomain_release", by, "", "", map[string]string{
		"workspace": workspaceID, "zone": label + "." + domain,
	})
	return nil
}

// --- bbolt ---

func (s *bboltStore) ReserveSubdomain(rec *SubdomainReservation, max int) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSubdomains)
		key := subdomainKey(rec.Domain, rec.Label)
		if raw := b.Get([]byte(key)); raw != nil {
			var ex SubdomainReservation
			if err := json.Unmarshal(raw, &ex); err != nil {
				return err
			}
			if ex.WorkspaceID != rec.WorkspaceID {
				return errSubdomainTaken
			}
			return nil // idempotent: this workspace already owns it
		}
		count := 0
		if err := b.ForEach(func(_, v []byte) error {
			var r SubdomainReservation
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			if r.WorkspaceID == rec.WorkspaceID {
				count++
			}
			return nil
		}); err != nil {
			return err
		}
		if count >= max {
			return errSubdomainLimit
		}
		return putJSONB(b, key, rec)
	})
}

func (s *bboltStore) GetSubdomainReservation(domain, label string) (*SubdomainReservation, error) {
	var rec SubdomainReservation
	err := s.db.View(func(tx *bbolt.Tx) error {
		return getJSONB(tx.Bucket(bucketSubdomains), subdomainKey(domain, label), &rec)
	})
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *bboltStore) ListWorkspaceSubdomains(workspaceID string) ([]*SubdomainReservation, error) {
	var out []*SubdomainReservation
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketSubdomains).ForEach(func(_, v []byte) error {
			var r SubdomainReservation
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			if r.WorkspaceID == workspaceID {
				out = append(out, &r)
			}
			return nil
		})
	})
	return out, err
}

func (s *bboltStore) ListSubdomainReservations() ([]*SubdomainReservation, error) {
	var out []*SubdomainReservation
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketSubdomains).ForEach(func(_, v []byte) error {
			var r SubdomainReservation
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			out = append(out, &r)
			return nil
		})
	})
	return out, err
}

func (s *bboltStore) ReleaseSubdomain(domain, label, workspaceID string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSubdomains)
		key := subdomainKey(domain, label)
		raw := b.Get([]byte(key))
		if raw == nil {
			return nil // already gone
		}
		var ex SubdomainReservation
		if err := json.Unmarshal(raw, &ex); err != nil {
			return err
		}
		if ex.WorkspaceID != workspaceID {
			return errSubdomainTaken // not yours to release
		}
		return b.Delete([]byte(key))
	})
}

// --- sql ---

func (s *sqlStore) ReserveSubdomain(rec *SubdomainReservation, max int) error {
	return s.inSerializable(s.ctx(), func(tx *sql.Tx) error {
		var raw []byte
		err := s.queryRow(s.ctx(), tx, `SELECT doc FROM subdomain_reservations WHERE domain=$1 AND label=$2 FOR UPDATE`, rec.Domain, rec.Label).Scan(&raw)
		if err == nil {
			var ex SubdomainReservation
			if uerr := json.Unmarshal(raw, &ex); uerr != nil {
				return uerr
			}
			if ex.WorkspaceID != rec.WorkspaceID {
				return errSubdomainTaken
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var count int
		if err := s.queryRow(s.ctx(), tx, `SELECT COUNT(*) FROM subdomain_reservations WHERE workspace_id=$1`, rec.WorkspaceID).Scan(&count); err != nil {
			return err
		}
		if count >= max {
			return errSubdomainLimit
		}
		doc, err := marshalDoc(rec)
		if err != nil {
			return err
		}
		_, err = s.exec(s.ctx(), tx, `INSERT INTO subdomain_reservations (domain, label, workspace_id, doc) VALUES ($1, $2, $3, $4::jsonb)`,
			rec.Domain, rec.Label, rec.WorkspaceID, doc)
		return err
	})
}

func (s *sqlStore) GetSubdomainReservation(domain, label string) (*SubdomainReservation, error) {
	return sqlGetDoc[SubdomainReservation](s.ctx(), s, s.db, `SELECT doc FROM subdomain_reservations WHERE domain=$1 AND label=$2`, domain, label)
}

func (s *sqlStore) ListWorkspaceSubdomains(workspaceID string) ([]*SubdomainReservation, error) {
	return sqlListDocs[SubdomainReservation](s.ctx(), s, s.db, `SELECT doc FROM subdomain_reservations WHERE workspace_id=$1 ORDER BY domain, label`, workspaceID)
}

func (s *sqlStore) ListSubdomainReservations() ([]*SubdomainReservation, error) {
	return sqlListDocs[SubdomainReservation](s.ctx(), s, s.db, `SELECT doc FROM subdomain_reservations ORDER BY domain, label`)
}

func (s *sqlStore) ReleaseSubdomain(domain, label, workspaceID string) error {
	_, err := s.exec(s.ctx(), s.db, `DELETE FROM subdomain_reservations WHERE domain=$1 AND label=$2 AND workspace_id=$3`, domain, label, workspaceID)
	return err
}
