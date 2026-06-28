package controller

import (
	"net/http"
	"strings"
)

// consoleCanViewVulns is the console-side mirror of canViewVulns: it gates the
// vulnerability surface (a node's CVEs, the nodes a CVE affects, a node's
// inventory) on operating standing — ws-member or higher. A read-only ws-viewer
// is deliberately too low, exactly as on the gRPC plane: the data reveals a
// fleet's exploitable surface. The reserved cluster roles are stripped from
// every console login, so matching them here is only for the break-glass cert
// path that the cert mount also serves.
func consoleCanViewVulns(u *consoleUser) bool {
	return contains(u.Roles, roleWSMember) || contains(u.Roles, roleWSAuditor) ||
		contains(u.Roles, roleWSAdmin) || contains(u.Roles, roleAdmin) ||
		contains(u.Roles, rolePlatformAdmin)
}

// nodeCVEJSON flattens a stored verdict row into the camelCase wire shape the
// console types expect, mirroring the gRPC NodeCVEInfo field set.
func nodeCVEJSON(r NodeCVERecord) map[string]any {
	return map[string]any{
		"nodeId":           r.NodeID,
		"cve":              r.CVE,
		"purl":             r.Purl,
		"status":           r.Status,
		"severity":         r.Severity,
		"kev":              r.KEV,
		"epss":             r.EPSS,
		"fixedVersion":     r.FixedVersion,
		"vexJustification": r.VEXJustification,
		"matchedUnix":      r.MatchedUnix,
	}
}

// handleNodeCVEs answers "what CVEs affect this node?" from the computed node_cve
// table, scoped to the caller's workspace. ?affected_only= narrows to the still-
// actionable rows; ?limit=&offset= page the result.
func (c *consoleAPI) handleNodeCVEs(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	if !consoleCanViewVulns(u) {
		writeErr(w, http.StatusForbidden, "workspace-member capability required")
		return
	}
	node, err := c.s.store.FindNode(u.Workspace, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}
	rows, err := cvesForNodeFanned(c.s.store, u.Workspace, node.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list node cves")
		return
	}
	rows = dedupCVEsForNode(rows)
	affectedOnly := r.URL.Query().Get("affected_only") == "true"
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		if affectedOnly && row.Status != "affected" {
			continue
		}
		out = append(out, nodeCVEJSON(row))
	}
	pg := pageParams(r)
	total := len(out)
	lo, hi := pg.bounds(total)
	writeJSON(w, pageEnvelope("cves", out[lo:hi], total, pg))
}

// handleNodesAffectedByCVE answers the inverse "what nodes does this CVE affect?"
// across the caller's workspace fleet, same cert/workspace tenancy as the by-node
// view.
func (c *consoleAPI) handleNodesAffectedByCVE(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	if !consoleCanViewVulns(u) {
		writeErr(w, http.StatusForbidden, "workspace-member capability required")
		return
	}
	cve := r.PathValue("cve")
	if cve == "" {
		writeErr(w, http.StatusBadRequest, "cve is required")
		return
	}
	rows, err := nodesAffectedByCVEFanned(c.s.store, u.Workspace, cve)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "nodes affected by cve")
		return
	}
	rows = dedupNodesForCVE(rows)
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, nodeCVEJSON(row))
	}
	pg := pageParams(r)
	total := len(out)
	lo, hi := pg.bounds(total)
	writeJSON(w, pageEnvelope("nodes", out[lo:hi], total, pg))
}

// workspaceCVEJSON flattens a rollup row into the camelCase wire shape the console
// types expect.
func workspaceCVEJSON(r WorkspaceCVERollup) map[string]any {
	nodes := r.Nodes
	if nodes == nil {
		nodes = []string{}
	}
	return map[string]any{
		"cve":          r.CVE,
		"severity":     r.Severity,
		"status":       r.Status,
		"fixedVersion": r.FixedVersion,
		"nodeCount":    r.NodeCount,
		"nodes":        nodes,
	}
}

// handleWorkspaceCVEs answers "what CVEs affect this workspace's fleet?" as a
// rollup, scoped to the caller's workspace: one row per CVE with the distinct
// affected-node count and list (host and image verdicts unioned), the
// representative severity/status, and a fixing version. ?cve= filters by a
// case-insensitive substring; ?limit=&offset= page the result.
func (c *consoleAPI) handleWorkspaceCVEs(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	if !consoleCanViewVulns(u) {
		writeErr(w, http.StatusForbidden, "workspace-member capability required")
		return
	}
	rollups, err := c.s.store.WorkspaceCVERollups(u.Workspace)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "workspace cves")
		return
	}
	if q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("cve"))); q != "" {
		filtered := rollups[:0]
		for _, row := range rollups {
			if strings.Contains(strings.ToLower(row.CVE), q) {
				filtered = append(filtered, row)
			}
		}
		rollups = filtered
	}
	out := make([]map[string]any, 0, len(rollups))
	for _, row := range rollups {
		out = append(out, workspaceCVEJSON(row))
	}
	pg := pageParams(r)
	total := len(out)
	lo, hi := pg.bounds(total)
	writeJSON(w, pageEnvelope("cves", out[lo:hi], total, pg))
}

// handleNodeComponents returns a node's resolved software inventory (the
// flattened component set the matcher joins against), workspace-scoped.
func (c *consoleAPI) handleNodeComponents(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	if !consoleCanViewVulns(u) {
		writeErr(w, http.StatusForbidden, "workspace-member capability required")
		return
	}
	node, err := c.s.store.FindNode(u.Workspace, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}
	rows, err := c.s.store.ListNodeComponents(u.Workspace, node.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list node components")
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, comp := range rows {
		out = append(out, map[string]any{
			"purl":      comp.Purl,
			"source":    comp.Source,
			"ecosystem": comp.Ecosystem,
			"name":      comp.Name,
			"version":   comp.Version,
			"distro":    comp.Distro,
		})
	}
	pg := pageParams(r)
	total := len(out)
	lo, hi := pg.bounds(total)
	writeJSON(w, pageEnvelope("components", out[lo:hi], total, pg))
}
