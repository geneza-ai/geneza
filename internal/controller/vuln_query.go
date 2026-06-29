package controller

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// ListNodeCVEs answers "what CVEs affect node N?" from the computed node_cve table.
// The workspace is taken from the caller's cert (never a request field), so a query
// can only ever read the caller's own tenant — a node in another workspace is
// invisible even by id. affected_only narrows the view to the still-actionable rows.
func (u *workspaceAPIService) ListNodeCVEs(ctx context.Context, req *genezav1.ListNodeCVEsRequest) (*genezav1.ListNodeCVEsResponse, error) {
	ident, _, ok := identityFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no verified identity")
	}
	if !canViewVulns(ident) {
		return nil, status.Error(codes.PermissionDenied, "workspace-member capability required")
	}
	// Resolve id-or-name within the caller's workspace; FindNode is workspace-scoped,
	// so a foreign node never resolves here.
	node, err := u.s.store.FindNode(ident.Workspace, req.GetNodeId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "node %q not found", req.GetNodeId())
	}
	rows, err := cvesForNodeFanned(u.s.store, ident.Workspace, node.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list node cves: %v", err)
	}
	rows = dedupCVEsForNode(rows)
	out := make([]NodeCVERecord, 0, len(rows))
	for _, r := range rows {
		if req.GetAffectedOnly() && r.Status != "affected" {
			continue
		}
		out = append(out, r)
	}
	total := len(out)
	lo, hi := (Page{Limit: int(req.GetLimit()), Offset: int(req.GetOffset())}).bounds(total)
	infos := make([]*genezav1.NodeCVEInfo, 0, hi-lo)
	for _, r := range out[lo:hi] {
		infos = append(infos, nodeCVEInfo(r))
	}
	return &genezav1.ListNodeCVEsResponse{Cves: infos, Total: int32(total)}, nil
}

// ListNodesAffectedByCVE answers the inverse "what nodes does CVE-X affect?" across
// the caller's workspace fleet. Same cert-scoped tenancy: the rows come only from
// the caller's workspace, so the blast-radius view of one tenant's CVE never reveals
// another tenant's nodes.
func (u *workspaceAPIService) ListNodesAffectedByCVE(ctx context.Context, req *genezav1.ListNodesAffectedByCVERequest) (*genezav1.ListNodesAffectedByCVEResponse, error) {
	ident, _, ok := identityFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no verified identity")
	}
	if !canViewVulns(ident) {
		return nil, status.Error(codes.PermissionDenied, "workspace-member capability required")
	}
	cve := req.GetCve()
	if cve == "" {
		return nil, status.Error(codes.InvalidArgument, "cve is required")
	}
	rows, err := nodesAffectedByCVEFanned(u.s.store, ident.Workspace, cve)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "nodes affected by cve: %v", err)
	}
	rows = dedupNodesForCVE(rows)
	total := len(rows)
	lo, hi := (Page{Limit: int(req.GetLimit()), Offset: int(req.GetOffset())}).bounds(total)
	infos := make([]*genezav1.NodeCVEInfo, 0, hi-lo)
	for _, r := range rows[lo:hi] {
		infos = append(infos, nodeCVEInfo(r))
	}
	return &genezav1.ListNodesAffectedByCVEResponse{Nodes: infos, Total: int32(total)}, nil
}

// ListWorkspaceCVEs answers "what CVEs affect this workspace's fleet?" as a rollup:
// one row per CVE with the distinct affected-node count and list (host and image
// verdicts unioned), the representative severity/status, and a fixing version. The
// workspace is taken from the caller's cert, so the rollup never spans tenants. An
// optional cve filter narrows the listing by a case-insensitive substring.
func (u *workspaceAPIService) ListWorkspaceCVEs(ctx context.Context, req *genezav1.ListWorkspaceCVEsRequest) (*genezav1.ListWorkspaceCVEsResponse, error) {
	ident, _, ok := identityFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no verified identity")
	}
	if !canViewVulns(ident) {
		return nil, status.Error(codes.PermissionDenied, "workspace-member capability required")
	}
	rollups, err := u.s.store.WorkspaceCVERollups(ident.Workspace)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "workspace cves: %v", err)
	}
	rollups = filterWorkspaceCVEs(rollups, req.GetCve())
	total := len(rollups)
	lo, hi := (Page{Limit: int(req.GetLimit()), Offset: int(req.GetOffset())}).bounds(total)
	infos := make([]*genezav1.WorkspaceCVEInfo, 0, hi-lo)
	for _, r := range rollups[lo:hi] {
		infos = append(infos, workspaceCVEInfo(r))
	}
	return &genezav1.ListWorkspaceCVEsResponse{Cves: infos, Total: int32(total)}, nil
}

// filterWorkspaceCVEs narrows a rollup listing to the CVEs whose id contains the
// given substring (case-insensitive). An empty filter keeps every row.
func filterWorkspaceCVEs(rollups []WorkspaceCVERollup, filter string) []WorkspaceCVERollup {
	q := strings.ToLower(strings.TrimSpace(filter))
	if q == "" {
		return rollups
	}
	out := make([]WorkspaceCVERollup, 0, len(rollups))
	for _, r := range rollups {
		if strings.Contains(strings.ToLower(r.CVE), q) {
			out = append(out, r)
		}
	}
	return out
}

// workspaceCVEInfo flattens a rollup into its wire form.
func workspaceCVEInfo(r WorkspaceCVERollup) *genezav1.WorkspaceCVEInfo {
	return &genezav1.WorkspaceCVEInfo{
		Cve:          r.CVE,
		Severity:     r.Severity,
		Status:       r.Status,
		FixedVersion: r.FixedVersion,
		NodeCount:    int32(r.NodeCount),
		Nodes:        r.Nodes,
	}
}

// ListNodeComponents returns a node's resolved software inventory (the flattened
// component set the matcher joins against). Workspace-scoped from the cert, like the
// CVE queries.
func (u *workspaceAPIService) ListNodeComponents(ctx context.Context, req *genezav1.ListNodeComponentsRequest) (*genezav1.ListNodeComponentsResponse, error) {
	ident, _, ok := identityFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no verified identity")
	}
	if !canViewVulns(ident) {
		return nil, status.Error(codes.PermissionDenied, "workspace-member capability required")
	}
	node, err := u.s.store.FindNode(ident.Workspace, req.GetNodeId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "node %q not found", req.GetNodeId())
	}
	rows, err := u.s.store.ListNodeComponents(ident.Workspace, node.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list node components: %v", err)
	}
	total := len(rows)
	lo, hi := (Page{Limit: int(req.GetLimit()), Offset: int(req.GetOffset())}).bounds(total)
	infos := make([]*genezav1.ComponentInfo, 0, hi-lo)
	for _, c := range rows[lo:hi] {
		infos = append(infos, &genezav1.ComponentInfo{
			Purl:      c.Purl,
			Source:    c.Source,
			Ecosystem: c.Ecosystem,
			Name:      c.Name,
			Version:   c.Version,
			Distro:    c.Distro,
		})
	}
	return &genezav1.ListNodeComponentsResponse{Components: infos, Total: int32(total)}, nil
}

// nodeCVEInfo flattens a stored verdict row into its wire form.
func nodeCVEInfo(r NodeCVERecord) *genezav1.NodeCVEInfo {
	return &genezav1.NodeCVEInfo{
		NodeId:           r.NodeID,
		Cve:              r.CVE,
		Purl:             r.Purl,
		Status:           r.Status,
		Severity:         r.Severity,
		Kev:              r.KEV,
		Epss:             r.EPSS,
		FixedVersion:     r.FixedVersion,
		VexJustification: r.VEXJustification,
		MatchedUnix:      r.MatchedUnix,
	}
}
