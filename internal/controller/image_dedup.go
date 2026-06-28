package controller

import (
	"sort"
	"strings"
)

// Container-image components arrive tagged with a Source of the form
// "image:<ref>@sha256:<hex>" (set by the agent's container collector). The digest
// is content-addressable: the same image bytes produce the same digest on every
// node and for every tenant, so an image's component set and its CVE verdicts are a
// property of the digest alone — they need to be stored and matched ONCE, then
// attributed to every node currently running that digest. A component whose Source
// is anything else (an OS package "os", a language dep "lang"), or an image with no
// resolvable digest (bare "image:<ref>", no "@sha256:"), stays on the per-node path
// unchanged.

// imageSourcePrefix and digestSep are the markers of a digest-pinned image source.
const (
	imageSourcePrefix = "image:"
	digestSep         = "@sha256:"
)

// externalSource is the source tag stamped on components ingested through the
// open SBOM-upload edge (an external scanner: trivy in CI, a registry webhook),
// as opposed to the agent's own "os"/"lang"/"kernel"/"image:" origins. A
// "?source=" qualifier on the upload narrows it to "external:<tool>". The tag is
// what lets the two producers share one node's component index: the agent's
// inventory paths replace only their own (non-external) slice and the upload path
// replaces only the external slice, so neither wipes the other.
const externalSource = "external"

// isExternalSource reports whether a component's source came from the open
// SBOM-upload edge rather than the agent. It is the partition both writers use to
// own only their own slice of node_components.
func isExternalSource(source string) bool {
	return source == externalSource || strings.HasPrefix(source, externalSource+":")
}

// imageDigestFromSource returns the content digest ("sha256:<hex>") carried in an
// image component's Source, and ok=false when the source is not a digest-pinned
// image source (an OS/language component, or an image whose digest was not
// resolvable). The digest-less image case falls through to the per-node path, so a
// node without a runtime-reported digest keeps working exactly as before.
func imageDigestFromSource(source string) (digest string, ok bool) {
	if !strings.HasPrefix(source, imageSourcePrefix) {
		return "", false
	}
	i := strings.Index(source, digestSep)
	if i < 0 {
		return "", false
	}
	// The digest is the "@" onward, minus the leading "@": "sha256:<hex>". An empty
	// or whitespace-only hex is treated as unresolvable so a malformed source never
	// keys an image table.
	d := source[i+1:]
	if strings.TrimSpace(d) == "sha256:" || strings.TrimSpace(d) == "" {
		return "", false
	}
	return d, true
}

// imageCVEAsNodeRow stamps a digest verdict with a node id so an image-sourced
// finding presents identically to a host verdict in the per-node answer shape.
func imageCVEAsNodeRow(ws, nodeID string, r ImageCVERecord) NodeCVERecord {
	return NodeCVERecord{
		WorkspaceID:      ws,
		NodeID:           nodeID,
		CVE:              r.CVE,
		Purl:             r.Purl,
		Status:           r.Status,
		Severity:         r.Severity,
		KEV:              r.KEV,
		EPSS:             r.EPSS,
		VEXJustification: r.VEXJustification,
		FixedVersion:     r.FixedVersion,
		MatchedUnix:      r.MatchedUnix,
	}
}

// cvesForNodeFanned returns a node's full verdict set: its own host node_cve rows
// plus, fanned out from the node->digest association, the verdicts of every image
// digest it currently runs. The dedup keeps the answer correct across both store
// engines without re-storing the image set per node. A (cve, purl) seen on both the
// host and an image is collapsed to one row (the host's, taken first), so a package
// present both in the host and a container does not double-list.
func cvesForNodeFanned(s Store, ws, nodeID string) ([]NodeCVERecord, error) {
	rows, err := s.CVEsForNode(ws, nodeID)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	out := make([]NodeCVERecord, 0, len(rows))
	for _, r := range rows {
		seen[r.CVE+"\x00"+r.Purl] = struct{}{}
		out = append(out, r)
	}
	digests, err := s.NodeImageDigests(ws, nodeID)
	if err != nil {
		return nil, err
	}
	for _, d := range digests {
		ivs, err := s.ImageCVEsForDigest(d)
		if err != nil {
			return nil, err
		}
		for _, iv := range ivs {
			k := iv.CVE + "\x00" + iv.Purl
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, imageCVEAsNodeRow(ws, nodeID, iv))
		}
	}
	return out, nil
}

// nodesAffectedByCVEFanned answers "which nodes does CVE-X affect?" by unioning the
// host node_cve rows for the cve with, for each digest whose image_cve carries the
// cve, every node in the workspace currently running that digest. A (node, purl) seen
// on both the host and an image is collapsed so a node is not double-listed. The scan
// is bounded by the affected fan-out (the digests carrying the cve), never the fleet.
func nodesAffectedByCVEFanned(s Store, ws, cve string) ([]NodeCVERecord, error) {
	rows, err := s.NodesAffectedByCVE(ws, cve)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	out := make([]NodeCVERecord, 0, len(rows))
	for _, r := range rows {
		seen[r.NodeID+"\x00"+r.Purl] = struct{}{}
		out = append(out, r)
	}
	// Find the digests whose verdicts include this cve, then fan each to its nodes.
	// There is no global cve->digest index, so this resolves through the per-workspace
	// associations: for every digest any node in the ws runs, check whether it carries
	// the cve. The set of distinct digests in a workspace is small (shared images), so
	// this stays far below a fleet scan.
	digestNodes, err := workspaceDigestNodes(s, ws)
	if err != nil {
		return nil, err
	}
	for digest, nodes := range digestNodes {
		ivs, err := s.ImageCVEsForDigest(digest)
		if err != nil {
			return nil, err
		}
		for _, iv := range ivs {
			if iv.CVE != cve {
				continue
			}
			for _, nodeID := range nodes {
				k := nodeID + "\x00" + iv.Purl
				if _, dup := seen[k]; dup {
					continue
				}
				seen[k] = struct{}{}
				out = append(out, imageCVEAsNodeRow(ws, nodeID, iv))
			}
		}
	}
	return out, nil
}

// workspaceDigestNodes builds the digest -> [nodeID] map for a workspace directly
// from its node->digest associations, so the by-cve fan-out resolves each carrying
// digest to its running nodes without a fleet scan — and without depending on a node
// record existing (an inventory-only node still fans correctly).
func workspaceDigestNodes(s Store, ws string) (map[string][]string, error) {
	assocs, err := s.WorkspaceNodeImages(ws)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, a := range assocs {
		out[a.Digest] = append(out[a.Digest], a.NodeID)
	}
	return out, nil
}

// basePurl strips a PURL's qualifiers and subpath ("?source=UNKNOWN", "#path"),
// leaving the type/namespace/name@version that identifies the package and version
// regardless of which extractor found it. Two extractors that find the same package
// (a lockfile and the installed module) emit the same base PURL but differ only in a
// trailing qualifier, so collapsing on the base de-duplicates them.
func basePurl(purl string) string {
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		return purl[:i]
	}
	return purl
}

// purlIsClassified reports whether a PURL's source qualifier names a real extractor
// origin rather than "UNKNOWN" (the marker an extractor sets when it could not
// classify the find). When two rows collapse to the same base PURL, the classified
// one is kept so the displayed PURL is the meaningful one.
func purlIsClassified(purl string) bool {
	i := strings.IndexByte(purl, '?')
	if i < 0 {
		return true
	}
	for _, kv := range strings.Split(purl[i+1:], "&") {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "source" {
			return !strings.EqualFold(v, "UNKNOWN")
		}
	}
	return true
}

// dedupNodeCVERows collapses verdict rows that name the same finding under different
// extractor sources. keyOf builds the per-row collision key (cve+base-purl for the
// per-node view, node+base-purl for the per-cve view); the base PURL folds the
// differing source qualifier away. Within a collision the row whose PURL carries a
// classified source is preferred over an "UNKNOWN" one, so the surviving row shows
// the meaningful package id. Order is otherwise preserved (stable), and a later
// classified row replaces an earlier UNKNOWN one in place.
func dedupNodeCVERows(rows []NodeCVERecord, keyOf func(NodeCVERecord) string) []NodeCVERecord {
	pos := map[string]int{}
	out := make([]NodeCVERecord, 0, len(rows))
	for _, r := range rows {
		k := keyOf(r)
		if i, seen := pos[k]; seen {
			// Prefer the row with a classified source over the kept UNKNOWN one.
			if !purlIsClassified(out[i].Purl) && purlIsClassified(r.Purl) {
				out[i] = r
			}
			continue
		}
		pos[k] = len(out)
		out = append(out, r)
	}
	return out
}

// dedupCVEsForNode collapses a node's verdict rows that are the same (cve, package,
// version) found by two extractors into one.
func dedupCVEsForNode(rows []NodeCVERecord) []NodeCVERecord {
	return dedupNodeCVERows(rows, func(r NodeCVERecord) string {
		return r.CVE + "\x00" + basePurl(r.Purl)
	})
}

// dedupNodesForCVE collapses the per-cve view's rows that name the same (node,
// package, version) under two extractor sources into one row per node+package.
func dedupNodesForCVE(rows []NodeCVERecord) []NodeCVERecord {
	return dedupNodeCVERows(rows, func(r NodeCVERecord) string {
		return r.NodeID + "\x00" + basePurl(r.Purl)
	})
}

// severityRank orders the qualitative severity labels so the rollup can pick the
// most severe verdict as a CVE's representative and sort the listing by it. An
// unrecognized or empty label ranks lowest.
func severityRank(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM", "MODERATE":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// statusRank orders verdict statuses so the rollup reports the most actionable one
// for a CVE: an affected node outranks one merely under investigation, which
// outranks a fixed/not-affected verdict.
func statusRank(status string) int {
	switch status {
	case "affected":
		return 3
	case "under_investigation":
		return 2
	case "fixed":
		return 1
	default:
		return 0
	}
}

// rollupCVENodeRows collapses the union of a workspace's host and image verdicts
// into one rollup per CVE: the distinct affected nodes (so a node carrying the CVE
// from both its host and a container counts once, while two nodes on the same
// affected image count twice), the most severe severity seen, the most actionable
// status, and a representative fixing version. The result is sorted by severity
// descending then node count descending, which is the listing order callers render.
func rollupCVENodeRows(rows []cveNodeRow) []WorkspaceCVERollup {
	type agg struct {
		severity string
		status   string
		fixed    string
		nodes    map[string]struct{}
		order    []string // distinct node ids in first-seen order
	}
	byCVE := map[string]*agg{}
	cveOrder := []string{}
	for _, r := range rows {
		if r.CVE == "" {
			continue
		}
		a := byCVE[r.CVE]
		if a == nil {
			a = &agg{nodes: map[string]struct{}{}}
			byCVE[r.CVE] = a
			cveOrder = append(cveOrder, r.CVE)
		}
		if _, dup := a.nodes[r.NodeID]; !dup && r.NodeID != "" {
			a.nodes[r.NodeID] = struct{}{}
			a.order = append(a.order, r.NodeID)
		}
		if severityRank(r.Severity) > severityRank(a.severity) {
			a.severity = r.Severity
		}
		if statusRank(r.Status) > statusRank(a.status) {
			a.status = r.Status
			// Pair the fixing version with the representative (most actionable) status,
			// so an affected CVE shows the version to upgrade to rather than a fixed
			// node's already-applied version.
			a.fixed = r.FixedVersion
		} else if a.fixed == "" && r.FixedVersion != "" && statusRank(r.Status) == statusRank(a.status) {
			a.fixed = r.FixedVersion
		}
	}
	out := make([]WorkspaceCVERollup, 0, len(byCVE))
	for _, cve := range cveOrder {
		a := byCVE[cve]
		nodes := make([]string, len(a.order))
		copy(nodes, a.order)
		sort.Strings(nodes)
		out = append(out, WorkspaceCVERollup{
			CVE:          cve,
			Severity:     a.severity,
			Status:       a.status,
			FixedVersion: a.fixed,
			NodeCount:    len(nodes),
			Nodes:        nodes,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := severityRank(out[i].Severity), severityRank(out[j].Severity)
		if si != sj {
			return si > sj
		}
		if out[i].NodeCount != out[j].NodeCount {
			return out[i].NodeCount > out[j].NodeCount
		}
		return out[i].CVE < out[j].CVE
	})
	return out
}

// splitInventory partitions a node's reported components into the host set (kept on
// the per-node path) and the per-digest image sets (stored and matched once, keyed
// by digest). The returned digests slice is the set of digests this node currently
// runs, in first-seen order, which becomes the node's image association set. A
// component with an unresolvable image digest is treated as a host component so it
// is never silently dropped.
func splitInventory(comps []ComponentRecord) (host []ComponentRecord, byDigest map[string][]ComponentRecord, digests []string) {
	byDigest = map[string][]ComponentRecord{}
	for _, c := range comps {
		digest, ok := imageDigestFromSource(c.Source)
		if !ok {
			host = append(host, c)
			continue
		}
		if _, seen := byDigest[digest]; !seen {
			digests = append(digests, digest)
		}
		byDigest[digest] = append(byDigest[digest], c)
	}
	return host, byDigest, digests
}
