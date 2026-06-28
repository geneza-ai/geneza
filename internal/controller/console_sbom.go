package controller

import (
	"context"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	openvex "github.com/openvex/go-vex/pkg/vex"

	"geneza.io/internal/sbom"
)

// The open SBOM/findings edges let external tooling exchange a node's inventory and
// verdicts in standard formats without going through the agent: an auditor or SIEM
// pulls the node's CycloneDX SBOM and its OpenVEX findings, and an external scanner
// (trivy in CI, a registry webhook) pushes a CycloneDX SBOM the controller matches on
// the same path the agent's gRPC report uses. The exports are built from the stored
// component index and verdict table, so they reflect exactly what the fleet view
// shows; the import shares the node's component index with the agent (partitioned by
// source) so the two producers never wipe each other.

// maxUploadedSBOMBytes caps one uploaded CycloneDX document. A real node SBOM is far
// smaller; the bound guards the decode against an exhaustion payload on an operator-
// authenticated but otherwise open input.
const maxUploadedSBOMBytes = 16 << 20

// handleNodeSBOMExport serves a node's stored inventory as a CycloneDX JSON
// document, built from the same component set the vuln query joins against: the
// node's host components plus the components of every image digest it runs (the same
// fan-out cvesForNodeFanned uses), so an image's packages appear in the exported
// SBOM. Workspace-scoped and gated on the vuln-view capability, like every other
// inventory read.
func (c *consoleAPI) handleNodeSBOMExport(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	if !consoleCanViewVulns(u) {
		writeErr(w, http.StatusForbidden, "workspace-member capability required")
		return
	}
	node, err := c.s.store.FindNode(u.Workspace, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}
	comps, err := c.nodeSBOMComponents(u.Workspace, node.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "load node components")
		return
	}
	doc, err := sbom.Encode(node.ID, comps)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "encode sbom")
		return
	}
	w.Header().Set("Content-Type", sbom.MediaType)
	_, _ = w.Write(doc)
}

// nodeSBOMComponents resolves a node's full component set for export: its stored
// host components unioned with the components of every image digest it runs. The
// image components are fanned through the node->digest association exactly as the
// verdict view fans image_cve, so the exported SBOM and the node's CVE list describe
// the same inventory. Duplicates across host and image (the same purl+source) are
// collapsed so an image whose package also shows on the host lists once.
func (c *consoleAPI) nodeSBOMComponents(ws, nodeID string) ([]sbom.Component, error) {
	host, err := c.s.store.ListNodeComponents(ws, nodeID)
	if err != nil {
		return nil, err
	}
	seen := map[[2]string]struct{}{}
	out := make([]sbom.Component, 0, len(host))
	add := func(purl, source, ecosystem, name, version, distro string) {
		k := [2]string{purl, source}
		if _, dup := seen[k]; dup {
			return
		}
		seen[k] = struct{}{}
		out = append(out, sbom.Component{
			Purl: purl, Name: name, Version: version,
			Ecosystem: ecosystem, Distro: distro, Source: source,
		})
	}
	for _, h := range host {
		add(h.Purl, h.Source, h.Ecosystem, h.Name, h.Version, h.Distro)
	}
	digests, err := c.s.store.NodeImageDigests(ws, nodeID)
	if err != nil {
		return nil, err
	}
	for _, d := range digests {
		ics, err := c.s.store.ListImageComponents(d)
		if err != nil {
			return nil, err
		}
		for _, ic := range ics {
			add(ic.Purl, ic.Source, ic.Ecosystem, ic.Name, ic.Version, ic.Distro)
		}
	}
	return out, nil
}

// handleNodeFindingsVEX serves a node's CVE verdicts as an OpenVEX document: one
// statement per (CVE, purl), the status mapped from the matcher's verdict. It is the
// findings counterpart to the SBOM export — an auditor or SIEM consumes the fleet's
// per-node verdicts in a standard, tool-agnostic format. Workspace-scoped and gated
// on the same vuln-view capability.
func (c *consoleAPI) handleNodeFindingsVEX(w http.ResponseWriter, r *http.Request, u *consoleUser) {
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
	doc := nodeVEXDocument(node.ID, rows)
	w.Header().Set("Content-Type", "application/vnd.openvex+json")
	if err := doc.ToJSON(w); err != nil {
		writeErr(w, http.StatusInternalServerError, "encode vex")
		return
	}
}

// nodeVEXDocument renders a node's deduped verdict rows into an OpenVEX document,
// one statement per row keyed on (vulnerability, product purl). The matcher's status
// maps to the OpenVEX vocabulary: an "affected" verdict carries an action statement
// naming the fixed version; "fixed" and "not_affected" both become not_affected
// (fixed because the installed version already carries the patch, so the vulnerable
// code is not present; not_affected because a VEX suppression cleared it); an
// "under_investigation" verdict carries that status verbatim. The node is the
// product the statement is about.
func nodeVEXDocument(nodeID string, rows []NodeCVERecord) openvex.VEX {
	doc := openvex.New()
	doc.Author = "geneza"
	for _, r := range rows {
		if r.CVE == "" || r.Purl == "" {
			continue
		}
		st := openvex.Statement{
			Vulnerability: openvex.Vulnerability{Name: openvex.VulnerabilityID(r.CVE)},
			Products: []openvex.Product{{
				Component: openvex.Component{
					ID:          nodeID,
					Identifiers: map[openvex.IdentifierType]string{openvex.PURL: r.Purl},
				},
			}},
		}
		switch r.Status {
		case "affected":
			st.Status = openvex.StatusAffected
			if r.FixedVersion != "" {
				st.ActionStatement = "update to " + r.FixedVersion
			} else {
				st.ActionStatement = "update the affected component"
			}
		case "fixed":
			st.Status = openvex.StatusNotAffected
			st.Justification = openvex.VulnerableCodeNotPresent
		case "not_affected":
			st.Status = openvex.StatusNotAffected
			// Carry the recorded VEX justification through when the suppression named one;
			// fall back to a generic not-present justification so the statement stays valid
			// (OpenVEX requires a justification or impact statement for not_affected).
			if j := openvex.Justification(r.VEXJustification); j.Valid() {
				st.Justification = j
			} else {
				st.Justification = openvex.VulnerableCodeNotPresent
			}
		case "under_investigation":
			st.Status = openvex.StatusUnderInvestigation
		default:
			st.Status = openvex.StatusUnderInvestigation
		}
		doc.Statements = append(doc.Statements, st)
	}
	sortVEXStatements(&doc)
	return doc
}

// handleNodeSBOMIngest accepts a CycloneDX JSON SBOM for a node from an external
// scanner and feeds it down the SAME match path the agent's gRPC inventory report
// uses, so the verdicts surface in the existing queries — without our agent on the
// node. The components are tagged with a distinct "external" source (or
// "external:<tool>" from ?source=) so they coexist with the agent's own os/lang/image
// components; re-posting replaces the prior external set (idempotent) and never
// touches the agent-collected components. Operator-gated (ws-admin/admin) and
// workspace-scoped: the workspace is the caller's, the node is resolved within it.
func (c *consoleAPI) handleNodeSBOMIngest(w http.ResponseWriter, r *http.Request, u *consoleUser) {
	if !u.Admin {
		writeErr(w, http.StatusForbidden, "admin role required")
		return
	}
	node, err := c.s.store.FindNode(u.Workspace, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "node not found")
		return
	}
	body, err := io.ReadAll(io.LimitReader(http.MaxBytesReader(w, r.Body, maxUploadedSBOMBytes), maxUploadedSBOMBytes+1))
	if err != nil || int64(len(body)) > maxUploadedSBOMBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "sbom too large")
		return
	}
	comps, err := sbom.Extract(body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid cyclonedx sbom")
		return
	}
	source := externalSourceTag(r.URL.Query().Get("source"))
	written, err := c.s.ingestExternalSBOM(r.Context(), u.Workspace, node.ID, source, comps)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "ingest sbom")
		return
	}
	_ = c.s.audit.AppendWS(u.Workspace, "external_sbom_ingested", "console:"+u.Name, node.ID, "", map[string]string{
		"source": source, "components": strconv.Itoa(len(comps)),
	})
	writeJSON(w, map[string]any{"ok": true, "components": len(comps), "source": source, "verdicts": written})
}

// externalSourceTag resolves the source tag stamped on uploaded components: a
// caller-supplied scanner name narrows the bare "external" to "external:<tool>" so an
// operator can tell which tool produced an upload, while an empty or whitespace value
// falls back to the bare tag. A "/" is stripped so the tag never collides with the
// "image:<ref>" or digest separators the source field also uses.
func externalSourceTag(q string) string {
	q = strings.TrimSpace(q)
	q = strings.ReplaceAll(q, "/", "")
	q = strings.ReplaceAll(q, "@", "")
	if q == "" {
		return externalSource
	}
	return externalSource + ":" + q
}

// ingestExternalSBOM replaces a node's externally-uploaded component set with the
// supplied components (tagged source) and re-matches the node against the feed, the
// same match RematchNode runs for an agent report. The agent-collected components are
// carried through untouched, so the upload and the agent's gRPC stream share the
// node's component index without wiping each other; a re-upload drops the prior
// external rows (replace-set) but leaves the agent's. Returns the verdict rows the
// re-match wrote.
func (s *Server) ingestExternalSBOM(ctx context.Context, ws, nodeID, source string, comps []sbom.Component) (int, error) {
	prior, err := s.store.ListNodeComponents(ws, nodeID)
	if err != nil {
		return 0, err
	}
	agent, _ := partitionBySource(prior)

	// Stamp the supplied components with the external source and collapse duplicates the
	// upload itself may carry (same purl twice), so the stored external slice is a clean
	// set keyed the same (purl, source) way the agent's is.
	seen := map[string]struct{}{}
	merged := make([]ComponentRecord, 0, len(agent)+len(comps))
	merged = append(merged, agent...)
	for _, comp := range comps {
		if comp.Purl == "" {
			continue
		}
		if _, dup := seen[comp.Purl]; dup {
			continue
		}
		seen[comp.Purl] = struct{}{}
		merged = append(merged, ComponentRecord{
			WorkspaceID: ws,
			NodeID:      nodeID,
			Purl:        comp.Purl,
			Source:      source,
			Ecosystem:   comp.Ecosystem,
			Name:        comp.Name,
			Version:     comp.Version,
			Distro:      comp.Distro,
		})
	}
	// Replace-set the whole node_components for the node with the agent slice plus the
	// new external slice: the prior external rows are dropped (re-upload idempotency)
	// while the agent's are preserved.
	if err := s.store.UpsertNodeComponents(ws, nodeID, merged); err != nil {
		return 0, err
	}
	if s.inventoryFeed == nil {
		return 0, nil
	}
	return s.RematchNode(ctx, s.inventoryFeed, s.inventoryVEX, ws, nodeID)
}

// sortVEXStatements orders a document's statements deterministically by
// (vulnerability, product purl) so an export of the same verdict set is byte-stable
// across calls — an auditor diffing two pulls sees only real changes.
func sortVEXStatements(doc *openvex.VEX) {
	sort.SliceStable(doc.Statements, func(i, j int) bool {
		a, b := doc.Statements[i], doc.Statements[j]
		if a.Vulnerability.Name != b.Vulnerability.Name {
			return a.Vulnerability.Name < b.Vulnerability.Name
		}
		return vexProductPurl(a) < vexProductPurl(b)
	})
}

// vexProductPurl returns a statement's product purl (its identifier), used as the
// stable tiebreaker when two statements name the same vulnerability.
func vexProductPurl(st openvex.Statement) string {
	if len(st.Products) == 0 {
		return ""
	}
	return st.Products[0].Identifiers[openvex.PURL]
}
