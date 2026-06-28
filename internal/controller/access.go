package controller

import (
	"context"
	"fmt"
	"time"
)

// The ACCESS plane: a human authenticated to OpenStack drives Geneza. It
// mirrors the VM-enrollment plane's resolve-or-auto-provision (vendordata.go's
// resolveOSWorkspace) but with human semantics:
// - a SEPARATE allow_human_auto_provision gate — VM auto-provision
//     must not implicitly create a workspace for a human, and vice versa;
//   - it JOINS the human as a member (the first one becomes ws-admin);
//   - it NEVER falls back to an empty result (an unbound project is a 403,
//     surfaced to the operator, not a silent misroute).

// keystoneJoin is the resolved+joined result of a human keystone login.
type keystoneJoin struct {
	Workspace   string
	Roles       []string
	Subject     string
	FirstAdmin  bool
	Provisioned bool
}

// keystoneSubject is the stable member/session key for a keystone caller (the
// keystone user-id, never the mutable display name —).
func keystoneSubject(caller osCaller) string {
	if caller.UserID != "" {
		return caller.UserID
	}
	return caller.UserName
}

// resolveAccessWorkspace resolves the workspace for a human keystone login and
// joins them as a member. The caller MUST already have passed
// validateHumanKeystoneToken.
func (s *Server) resolveAccessWorkspace(ctx context.Context, svcUID string, cl CloudConfig, caller osCaller) (keystoneJoin, error) {
	bindingKey := osProjectBindingKey(svcUID, caller.ProjectID)
	var ws string
	provisioned := false

	if b, err := s.store.GetSourceBinding(bindingKey); err == nil {
		ws = b.WorkspaceID
	} else if err != ErrNotFound {
		return keystoneJoin{}, err
	} else {
		// Unbound project: only auto-provision for a human if the cloud opts in.
		if !cl.AllowHumanAutoProvision {
			return keystoneJoin{}, errUnboundProject
		}
		slug := accessWorkspaceSlug(svcUID, caller)
		if err := s.ensureWorkspace(slug, caller.ProjectName, defaultOverlayCIDR); err != nil {
			return keystoneJoin{}, fmt.Errorf("provision workspace: %w", err)
		}
		if err := s.store.PutSourceBinding(&SourceBinding{
			Key:             bindingKey,
			WorkspaceID:     slug,
			CreatedUnix:     time.Now().Unix(),
			CreatedBy:       "auto:keystone",
			AutoProvisioned: true,
		}); err != nil {
			return keystoneJoin{}, fmt.Errorf("record binding: %w", err)
		}
		s.registerDynamicWorkspace(slug) // loads the auto-provision (role-name) policy
		ws = slug
		provisioned = true
	}

	// Join: the first human in the workspace becomes ws-admin; everyone else maps
	// via the cloud role_map (atomic — UpsertFirstAdmin is race-free).
	subject := keystoneSubject(caller)
	rec := &MemberRecord{
		Provider:    providerKeystone,
		Username:    caller.UserName,
		Subject:     subject,
		SourceUID:   svcUID,
		Roles:       cl.mapKeystoneRoles(caller.Roles),
		AddedBy:     "auto:keystone",
		CreatedUnix: time.Now().Unix(),
		UpdatedUnix: time.Now().Unix(),
	}
	firstAdmin, err := s.store.UpsertFirstAdmin(ws, rec)
	if err != nil {
		return keystoneJoin{}, fmt.Errorf("join workspace: %w", err)
	}
	return keystoneJoin{
		Workspace:   ws,
		Roles:       rec.Roles,
		Subject:     subject,
		FirstAdmin:  firstAdmin,
		Provisioned: provisioned,
	}, nil
}

// accessWorkspaceSlug builds <project-name>-<short-uuid> from the human's
// project-scoped token (project name is already present — no extra lookup).
func accessWorkspaceSlug(svcUID string, caller osCaller) string {
	short := caller.ProjectID
	if len(short) > 8 {
		short = short[:8]
	}
	base := slugify(caller.ProjectName)
	if base == "" {
		base = "os-" + slugify(svcUID)
	}
	return base + "-" + short
}
