package controller

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Funnel exposures, console REST. List (any member) + create/delete (ws-admin),
// mirroring the ClusterAPI; both call the same Server methods.

func funnelJSON(f *FunnelBinding) map[string]any {
	return map[string]any{
		"hostname": f.Hostname, "node": f.NodeID, "target": f.Target, "mode": f.Mode,
		"createdUnix": f.CreatedUnix, "createdBy": f.CreatedBy,
	}
}

func (c *consoleAPI) handleListFunnels(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	fs, err := c.s.store.ListWorkspaceFunnels(u.Workspace)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list funnels")
		return
	}
	out := make([]map[string]any, 0, len(fs))
	for _, f := range fs {
		out = append(out, funnelJSON(f))
	}
	writeJSON(w, map[string]any{"funnels": out, "max": maxWorkspaceFunnels})
}

func (c *consoleAPI) handleCreateFunnel(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	var req struct {
		Hostname string `json:"hostname"`
		Node     string `json:"node"`
		Target   string `json:"target"`
		Mode     string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	rec, err := c.s.createFunnel(u.Workspace, req.Hostname, req.Node, req.Target, req.Mode, "console:"+u.Name)
	if err != nil {
		switch {
		case errors.Is(err, errFunnelTaken):
			writeErr(w, http.StatusConflict, "that funnel hostname is already in use")
		case errors.Is(err, errFunnelLimit):
			writeErr(w, http.StatusConflict, "workspace funnel limit reached")
		case errors.Is(err, errFunnelHost):
			writeErr(w, http.StatusBadRequest, "hostname is not under one of your reservations")
		case errors.Is(err, errManagedDomainDisabled):
			writeErr(w, http.StatusNotFound, "managed domain is not enabled")
		default:
			writeErr(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	writeJSON(w, funnelJSON(rec))
}

func (c *consoleAPI) handleDeleteFunnel(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	hostname := r.PathValue("hostname")
	if hostname == "" {
		writeErr(w, http.StatusBadRequest, "hostname required")
		return
	}
	if err := c.s.deleteFunnel(u.Workspace, hostname, "console:"+u.Name); err != nil {
		if errors.Is(err, errFunnelTaken) {
			writeErr(w, http.StatusForbidden, "that funnel belongs to another workspace")
			return
		}
		writeErr(w, http.StatusInternalServerError, "delete funnel")
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}
