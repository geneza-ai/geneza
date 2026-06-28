package controller

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Managed-domain subdomain reservations, console REST. A workspace admin claims
// a subdomain label on one of the configured managed domains; any member may
// list the workspace's reservations and the domains available to claim under.
// The cert manager issues a wildcard per reservation out of band.

func reservationJSON(r *SubdomainReservation) map[string]any {
	return map[string]any{
		"domain":      r.Domain,
		"label":       r.Label,
		"zone":        r.Zone(),
		"createdUnix": r.CreatedUnix,
		"createdBy":   r.CreatedBy,
	}
}

// handleListSubdomains returns the workspace's reservations plus the claimable
// domains and the per-workspace cap, so a UI can render the picker without a
// second call.
func (c *consoleAPI) handleListSubdomains(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	subs, err := c.s.store.ListWorkspaceSubdomains(u.Workspace)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list reservations")
		return
	}
	out := make([]map[string]any, 0, len(subs))
	for _, s := range subs {
		out = append(out, reservationJSON(s))
	}
	domains := make([]string, 0, len(c.s.cfg.ManagedDomain.Domains))
	for _, d := range c.s.cfg.ManagedDomain.Domains {
		domains = append(domains, d.Base)
	}
	writeJSON(w, map[string]any{
		"enabled":      c.s.cfg.ManagedDomain.enabled(),
		"domains":      domains,
		"max":          maxWorkspaceSubdomains,
		"reservations": out,
	})
}

// handleReserveSubdomain claims a subdomain for the caller's workspace (admin).
// Body: {"domain": "...", "label": "..."}. An empty label takes the workspace's
// derived default.
func (c *consoleAPI) handleReserveSubdomain(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	var req struct {
		Domain string `json:"domain"`
		Label  string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	rec, err := c.s.reserveWorkspaceSubdomain(u.Workspace, req.Domain, req.Label, "console:"+u.Name)
	if err != nil {
		switch {
		case errors.Is(err, errSubdomainTaken):
			writeErr(w, http.StatusConflict, "that subdomain is already reserved")
		case errors.Is(err, errSubdomainLimit):
			writeErr(w, http.StatusConflict, "workspace subdomain limit reached")
		case errors.Is(err, errManagedDomainDisabled):
			writeErr(w, http.StatusNotFound, "managed domain is not enabled")
		default:
			writeErr(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	writeJSON(w, reservationJSON(rec))
}

// handleReleaseSubdomain drops one of the workspace's reservations (admin). The
// cert manager GCs the wildcard on its next tick.
func (c *consoleAPI) handleReleaseSubdomain(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	domain := r.PathValue("domain")
	label := r.PathValue("label")
	if domain == "" || label == "" {
		writeErr(w, http.StatusBadRequest, "domain and label required")
		return
	}
	if err := c.s.releaseWorkspaceSubdomain(u.Workspace, domain, label, "console:"+u.Name); err != nil {
		if errors.Is(err, errSubdomainTaken) {
			writeErr(w, http.StatusForbidden, "that subdomain belongs to another workspace")
			return
		}
		writeErr(w, http.StatusInternalServerError, "release reservation")
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}
