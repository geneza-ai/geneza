package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	bbolt "go.etcd.io/bbolt"
)

// Store-backed per-workspace membership. Today roles come from two sources
// that this layer unifies: operator-configured policy bindings (local/oidc
// operators) and dynamic store membership (keystone access-plane joins, and
// future admin-managed members). A member row lets keystone/oidc/local users
// coexist in one workspace and survive a restart — config-only membership could
// not record a keystone user who logged in. Members live under the per-workspace
// sub-bucket ws/<wsID>/members so a cross-tenant read is structurally NotFound.
//
// The member KEY is "<provider>:<subject>" using the STABLE provider subject id
// (keystone user-id, oidc `sub`; local = username), NOT the mutable display
// name — renaming an IdP account can never hijack another member's row.

const childMembers = "members"

// MemberRecord is one principal's membership of one workspace.
type MemberRecord struct {
	Provider    string   `json:"provider"`             // keystone|oidc|local
	Username    string   `json:"username"`             // canonical display name (no ':')
	Subject     string   `json:"subject"`              // stable provider id; local = username
	SourceUID   string   `json:"source_uid,omitempty"` // keystone svc-uid (binds the principal to one cloud)
	Roles       []string `json:"roles"`                // ws-admin|ws-member|ws-viewer — NEVER a reserved cluster role
	Groups      []string `json:"groups,omitempty"`
	AddedBy     string   `json:"added_by,omitempty"` // auto:keystone:first-user | auto:keystone:role_map | admin:<name>
	CreatedUnix int64    `json:"created_unix"`
	UpdatedUnix int64    `json:"updated_unix"`
	// PresenceCredentials are the principal's enrolled hardware presence factors
	// (WebAuthn/FIDO2). Empty while only the software presence stub is in use; the
	// registry reads it for the software-stub safety gate. Hardware enrollment
	// populates it.
	PresenceCredentials []EnrolledCredential `json:"presence_credentials,omitempty"`
}

// memberKey is the bucket key for a principal. Subjects are validated to contain
// no ':' (see validateMemberIdentity) so the two-segment key is unambiguous.
func memberKey(provider, subject string) string { return provider + ":" + subject }

// validateMemberIdentity fails closed on a subject/provider that would corrupt
// the "<provider>:<subject>" key namespace.
func validateMemberIdentity(provider, subject string) error {
	if provider == "" || subject == "" {
		return fmt.Errorf("member identity requires provider and subject")
	}
	if strings.Contains(provider, ":") || strings.Contains(subject, ":") {
		return fmt.Errorf("member provider/subject must not contain ':' (got %q:%q)", provider, subject)
	}
	return nil
}

// PutMember writes/overwrites a member row. Reserved cluster roles are stripped
// before persistence so a row can never carry admin/platform-admin even if a
// caller passes one (defense-in-depth on top of the login-path stripping).
// AddPresenceCredential appends an enrolled hardware presence credential to a
// member (creating a minimal member row if none exists). Idempotent by public
// key. Once present, the software-stub safety gate refuses Kind=="software" for
// this principal (presence.go). This is the hardware-enrollment seam; the
// WebAuthn assertion check is the documented drop-in.
func (s *bboltStore) AddPresenceCredential(ws, provider, subject string, cred EnrolledCredential) error {
	if err := validateMemberIdentity(provider, subject); err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, ws, childMembers)
		if err != nil {
			return err
		}
		var rec MemberRecord
		if err := getJSONB(b, memberKey(provider, subject), &rec); err != nil {
			rec = MemberRecord{Provider: provider, Subject: subject, Username: subject, CreatedUnix: time.Now().Unix()}
		}
		for _, c := range rec.PresenceCredentials {
			if bytesEqual(c.PublicKey, cred.PublicKey) && c.Kind == cred.Kind {
				return nil // already enrolled
			}
		}
		rec.PresenceCredentials = append(rec.PresenceCredentials, cred)
		rec.UpdatedUnix = time.Now().Unix()
		return putJSONB(b, memberKey(provider, subject), &rec)
	})
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (s *bboltStore) PutMember(ws string, rec *MemberRecord) error {
	if err := validateMemberIdentity(rec.Provider, rec.Subject); err != nil {
		return err
	}
	rec.Roles = stripReservedRoles(rec.Roles)
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := wsChildW(tx, ws, childMembers)
		if err != nil {
			return err
		}
		return putJSONB(b, memberKey(rec.Provider, rec.Subject), rec)
	})
}

func (s *bboltStore) GetMember(ws, provider, subject string) (*MemberRecord, error) {
	var rec MemberRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		return getJSONB(wsChildR(tx, ws, childMembers), memberKey(provider, subject), &rec)
	})
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *bboltStore) ListMembers(ws string) ([]*MemberRecord, error) {
	var out []*MemberRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childMembers)
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, v []byte) error {
			var m MemberRecord
			if err := json.Unmarshal(v, &m); err != nil {
				return err
			}
			out = append(out, &m)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		return memberKey(out[i].Provider, out[i].Subject) < memberKey(out[j].Provider, out[j].Subject)
	})
	return out, nil
}

func (s *bboltStore) DeleteMember(ws, provider, subject string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := wsChildR(tx, ws, childMembers)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(memberKey(provider, subject)))
	})
}

// ListMemberWorkspaces returns every workspace the principal is a member of.
// O(workspaces) — fine at lab/single-tenant scale; add a subject->[]ws index if
// the workspace count grows large.
func (s *bboltStore) ListMemberWorkspaces(provider, subject string) ([]string, error) {
	key := []byte(memberKey(provider, subject))
	var out []string
	err := s.db.View(func(tx *bbolt.Tx) error {
		return forEachWS(tx, childMembers, func(wsID string, b *bbolt.Bucket) error {
			if b != nil && b.Get(key) != nil {
				out = append(out, wsID)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// UpsertFirstAdmin atomically joins a principal to a workspace, applying the
// "first human in an auto-provisioned workspace becomes ws-admin" rule
// race-free in a single write txn. Semantics:
//   - existing member  -> refresh display name/groups/timestamp, PRESERVE roles
//     (an admin promotion or a manual role edit sticks across re-login).
//   - new + workspace has NO members yet -> roles := [ws-admin], isFirstAdmin=true.
//   - new + workspace already has members -> roles := rec.Roles (caller's mapped
//     roles, e.g. from the keystone role_map).
//
// Because bbolt serializes writers, two concurrent first logins cannot both see
// an empty bucket: exactly one wins ws-admin, the loser is mapped normally.
func (s *bboltStore) UpsertFirstAdmin(ws string, rec *MemberRecord) (isFirstAdmin bool, err error) {
	if verr := validateMemberIdentity(rec.Provider, rec.Subject); verr != nil {
		return false, verr
	}
	now := rec.UpdatedUnix
	if now == 0 {
		now = time.Now().Unix()
	}
	err = s.db.Update(func(tx *bbolt.Tx) error {
		b, berr := wsChildW(tx, ws, childMembers)
		if berr != nil {
			return berr
		}
		key := memberKey(rec.Provider, rec.Subject)
		if raw := b.Get([]byte(key)); raw != nil {
			var ex MemberRecord
			if uerr := json.Unmarshal(raw, &ex); uerr != nil {
				return uerr
			}
			ex.Username = rec.Username
			ex.Groups = rec.Groups
			if rec.SourceUID != "" {
				ex.SourceUID = rec.SourceUID
			}
			ex.UpdatedUnix = now
			*rec = ex // hand the canonical stored record back to the caller
			return putJSONB(b, key, &ex)
		}
		// New member. Is this workspace's membership empty? (the first human wins admin)
		c := b.Cursor()
		firstKey, _ := c.First()
		if firstKey == nil {
			rec.Roles = []string{roleWSAdmin}
			isFirstAdmin = true
			if rec.AddedBy == "" {
				rec.AddedBy = "auto:first-user"
			}
		}
		rec.Roles = stripReservedRoles(rec.Roles)
		if rec.CreatedUnix == 0 {
			rec.CreatedUnix = now
		}
		rec.UpdatedUnix = now
		return putJSONB(b, key, rec)
	})
	return isFirstAdmin, err
}

// --- server-side workspace + role resolution (the SOLE role source) ---

// workspacesForUserStore returns the workspaces a principal may log into: the
// config-derived candidates (open workspaces + configured members/groups) UNION
// the workspaces it holds a store membership in. The store union is what lets a
// keystone/oidc user joined at login re-appear after a restart.
func (s *Server) workspacesForUserStore(provider, user, subject string, groups []string) []string {
	set := map[string]bool{}
	for _, w := range s.workspacesForUser(user, groups) {
		set[w] = true
	}
	if stored, err := s.store.ListMemberWorkspaces(provider, subject); err == nil {
		for _, w := range stored {
			set[w] = true
		}
	}
	out := make([]string, 0, len(set))
	for w := range set {
		out = append(out, w)
	}
	sort.Strings(out)
	return out
}

// rolesForMember is the ONE role source feeding both console sessions and CLI
// cert issuance. It unions store-membership roles with config-policy roles, then
// strips reserved cluster roles. The config-policy path runs ONLY for the
// config-identity providers (local/oidc): keystone identities get roles
// EXCLUSIVELY from store membership (written by the role_map at login), so a
// config `users:`/`groups:` binding can never leak onto a keystone principal
// that happens to share a name.
func (s *Server) rolesForMember(ws, provider, user, subject string, groups []string) []string {
	set := map[string]bool{}
	if rec, err := s.store.GetMember(ws, provider, subject); err == nil {
		for _, r := range rec.Roles {
			set[r] = true
		}
	} else if !errors.Is(err, ErrNotFound) {
		slog.Error("rolesForMember: store lookup failed", "ws", ws, "provider", provider, "err", err)
	}
	if provider != providerKeystone {
		for _, r := range s.policyFor(ws).RolesFor(user, groups) {
			set[r] = true
		}
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	out = stripReservedRoles(out)
	sort.Strings(out)
	return out
}
