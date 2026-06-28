package controller

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/sbom"
)

// maxInventoryBytes caps one compressed inventory upload (disk/parse-exhaustion
// guard); a real node SBOM is well under this even uncompressed.
const maxInventoryBytes = 64 << 20

// errInventoryNeedFull is returned when a delta cannot be applied because the controller
// does not hold the base it names (no SBOM stored, or a different content hash). The
// stream handler catches it and asks the node to resend a full SBOM; tests assert on
// it directly. It is not a corruption error — the node and controller just lost sync.
var errInventoryNeedFull = errors.New("inventory delta base not held; full resend required")

// ingestInventoryReport applies a node's reported inventory — a full SBOM or a delta
// against the set the controller last held — re-indexes its components, and re-matches
// it against the feed. ws/nodeID are the AUTHENTICATED identity of the reporting
// stream, never the report's self-named node — a node only ever reports its own
// inventory. It is idempotent: re-reporting the same content re-derives the same
// component set, and the unchanged path is gated upstream by the heartbeat hash so a
// steady-state node never sends a report at all. Returns the number of node_cve
// verdict rows the re-match wrote. A delta whose base the controller cannot match
// returns errInventoryNeedFull so the caller can request a full resend.
func (s *Server) ingestInventoryReport(ctx context.Context, ws, nodeID string, rep *genezav1.InventoryReport) (int, error) {
	if rep.GetFull() || len(rep.GetSbom()) > 0 {
		return s.ingestFullInventory(ctx, ws, nodeID, rep)
	}
	return s.ingestInventoryDelta(ctx, ws, nodeID, rep)
}

// ingestFullInventory is the full-SBOM path: the report carries the whole zstd
// CycloneDX document. It verifies the claimed hash against the shipped bytes, then
// commits the set.
func (s *Server) ingestFullInventory(ctx context.Context, ws, nodeID string, rep *genezav1.InventoryReport) (int, error) {
	blob := rep.GetSbom()
	if len(blob) == 0 {
		return 0, fmt.Errorf("inventory report carries no sbom")
	}
	if len(blob) > maxInventoryBytes {
		return 0, fmt.Errorf("inventory report exceeds %d bytes", int64(maxInventoryBytes))
	}

	doc, err := sbom.Decompress(blob)
	if err != nil {
		return 0, fmt.Errorf("decompress inventory: %w", err)
	}
	// Verify the agent's claimed hash against the bytes it shipped: the heartbeat's
	// change detection is keyed on this hash, so a blob whose content does not match
	// the claim would desync the steady-state no-op check. A mismatch is a corrupt or
	// lying report; reject it rather than store an SBOM under the wrong hash.
	sum := sbom.Hash(doc)
	if claimed := rep.GetContentHash(); len(claimed) > 0 {
		if hex.EncodeToString(sum[:]) != hex.EncodeToString(claimed) {
			return 0, fmt.Errorf("inventory content hash does not match shipped sbom")
		}
	}

	comps, err := sbom.Extract(doc)
	if err != nil {
		return 0, fmt.Errorf("parse inventory sbom: %w", err)
	}
	return s.commitInventory(ctx, ws, nodeID, rep, blob, sum, comps)
}

// ingestInventoryDelta is the delta path: the report carries only the components that
// changed since base_hash. It rebuilds the node's full set from the components the
// controller holds plus the delta, re-derives the canonical document and its hash, and
// commits — but only if base_hash matches the set it actually holds AND the rebuilt
// set hashes to the report's content_hash. A base mismatch returns errInventoryNeedFull
// (the controller lost the base; ask for a full); a content-hash mismatch is a corrupt
// delta and is rejected outright.
func (s *Server) ingestInventoryDelta(ctx context.Context, ws, nodeID string, rep *genezav1.InventoryReport) (int, error) {
	base := rep.GetBaseHash()
	if len(base) == 0 {
		return 0, fmt.Errorf("inventory delta carries no base hash")
	}
	prior, err := s.store.GetNodeSBOM(ws, nodeID)
	if err != nil {
		return 0, fmt.Errorf("load node sbom for delta: %w", err)
	}
	// The base the delta applies on top of must be the content hash the controller holds.
	// If it holds none, or a different one, it cannot reconstruct the set and asks for
	// a full resend.
	if prior == nil || prior.ContentHash == "" || prior.ContentHash != hex.EncodeToString(base) {
		return 0, errInventoryNeedFull
	}

	priorComps, err := s.store.ListNodeComponents(ws, nodeID)
	if err != nil {
		return 0, fmt.Errorf("load node components for delta: %w", err)
	}
	// The delta is built against the agent's OWN inventory, so the base it applies on
	// top of is the agent-collected slice only — any components a separate SBOM upload
	// stored under "external" are invisible to the agent and must not enter the set the
	// controller re-encodes and hashes against the agent's claim. Keeping them out is what
	// makes the re-hash reproduce the agent's canonical document regardless of an
	// external upload, so an upload never desyncs the delta stream.
	agentBase, _ := partitionBySource(priorComps)
	next := sbom.Apply(componentsFromRecords(agentBase),
		componentsFromProto(rep.GetAdded()), componentsFromProto(rep.GetRemoved()))

	// Re-encode the rebuilt set into the canonical document the agent hashed, and
	// require the result to match the report's content_hash. This proves the delta
	// landed on the expected base and reconstructed the agent's exact set — a corrupt
	// or misordered delta cannot slip a wrong inventory in under a claimed hash.
	doc, err := sbom.Encode(nodeID, next)
	if err != nil {
		return 0, fmt.Errorf("encode delta result: %w", err)
	}
	sum := sbom.Hash(doc)
	if claimed := rep.GetContentHash(); len(claimed) > 0 {
		if hex.EncodeToString(sum[:]) != hex.EncodeToString(claimed) {
			return 0, fmt.Errorf("inventory delta result hash does not match claimed content hash")
		}
	}
	blob, err := sbom.Compress(doc)
	if err != nil {
		return 0, fmt.Errorf("compress delta result: %w", err)
	}
	return s.commitInventory(ctx, ws, nodeID, rep, blob, sum, next)
}

// commitInventory stores the resolved SBOM blob + content hash, replaces the node's
// component index with the resolved set, and re-matches against the feed. It is the
// shared tail of the full and delta paths so both land identically: the same stored
// blob shape, the same replace-set semantics, the same re-match.
func (s *Server) commitInventory(ctx context.Context, ws, nodeID string, rep *genezav1.InventoryReport, blob []byte, sum [32]byte, comps []sbom.Component) (int, error) {
	hashHex := hex.EncodeToString(sum[:])
	format := rep.GetFormat()
	if format == "" {
		format = sbom.MediaType
	}
	collected := rep.GetCollectedUnix()
	if collected == 0 {
		collected = time.Now().Unix()
	}
	if err := s.store.PutNodeSBOM(ws, nodeID, &NodeSBOMRecord{
		WorkspaceID:   ws,
		NodeID:        nodeID,
		Format:        format,
		ContentHash:   hashHex,
		CollectedUnix: collected,
		SBOM:          blob,
	}); err != nil {
		return 0, fmt.Errorf("store node sbom: %w", err)
	}

	recs := make([]ComponentRecord, 0, len(comps))
	for _, c := range comps {
		recs = append(recs, ComponentRecord{
			WorkspaceID: ws,
			NodeID:      nodeID,
			Purl:        c.Purl,
			Source:      c.Source,
			Ecosystem:   c.Ecosystem,
			Name:        c.Name,
			Version:     c.Version,
			Distro:      c.Distro,
		})
	}

	// Split the reported set: host (OS/language) components stay on the per-node path
	// unchanged; container-image components are deduped by content digest so an image
	// many nodes run is stored and matched ONCE, with its verdicts fanned to every
	// node running it. A digest-less image component falls back to the per-node path.
	host, byDigest, digests := splitInventory(recs)

	// Preserve any components a separate SBOM upload stored under "external": the agent
	// owns only its own slice of node_components, so its replace-set carries the prior
	// external rows through unchanged. Without this the agent report would wipe an
	// operator's externally-ingested scan, and vice versa the upload path preserves the
	// agent's rows the same way.
	external, err := s.externalComponents(ws, nodeID)
	if err != nil {
		return 0, fmt.Errorf("load external components: %w", err)
	}

	// Replace-set: the node's prior host component rows are dropped and these (the
	// agent's host inventory plus the preserved external slice) become its inventory, so
	// a removed agent package leaves no stale row the matcher would keep flagging.
	if err := s.store.UpsertNodeComponents(ws, nodeID, append(host, external...)); err != nil {
		return 0, fmt.Errorf("index node components: %w", err)
	}

	// Store each newly-seen digest's image component set ONCE, and refresh the node's
	// digest associations (replace-set) so a stopped image stops fanning to this node.
	newDigests, err := s.storeImageDigests(byDigest)
	if err != nil {
		return 0, fmt.Errorf("index image components: %w", err)
	}
	if err := s.store.SetNodeImages(ws, nodeID, digests); err != nil {
		return 0, fmt.Errorf("associate node images: %w", err)
	}

	// Re-match only when a feed is configured; with none the SBOM and component index
	// are still updated (the answer table is just empty until a feed lands and a
	// post-sync pass fills it).
	if s.inventoryFeed == nil {
		return 0, nil
	}
	written, err := s.RematchNode(ctx, s.inventoryFeed, s.inventoryVEX, ws, nodeID)
	if err != nil {
		return 0, fmt.Errorf("re-match node inventory: %w", err)
	}
	// Match each first-seen digest ONCE (an already-stored digest already has its
	// verdicts; they fan to this node via the association without re-matching).
	imageWritten := 0
	for _, d := range newDigests {
		w, merr := s.RematchImageDigest(ctx, s.inventoryFeed, s.inventoryVEX, d)
		if merr != nil {
			return 0, fmt.Errorf("re-match image digest: %w", merr)
		}
		imageWritten += w
	}
	slog.Info("node inventory ingested", "node", nodeID, "components", len(host),
		"images", len(digests), "verdicts", written, "image_verdicts", imageWritten, "hash", hashHex)
	return written + imageWritten, nil
}

// storeImageDigests stores each digest's image component set, skipping a digest
// already present (its set is content-addressable and identical). It returns the
// digests that were NOT already stored — the first-seen set the caller matches once.
// A node re-reporting an already-seen digest therefore never re-stores or re-matches
// the whole image, only refreshes its own association.
func (s *Server) storeImageDigests(byDigest map[string][]ComponentRecord) ([]string, error) {
	var firstSeen []string
	for digest, comps := range byDigest {
		has, err := s.store.HasImageComponents(digest)
		if err != nil {
			return nil, err
		}
		if has {
			continue
		}
		recs := make([]ImageComponentRecord, 0, len(comps))
		for _, c := range comps {
			recs = append(recs, ImageComponentRecord{
				Digest:    digest,
				Purl:      c.Purl,
				Source:    c.Source,
				Ecosystem: c.Ecosystem,
				Name:      c.Name,
				Version:   c.Version,
				Distro:    c.Distro,
			})
		}
		if err := s.store.PutImageComponents(digest, recs); err != nil {
			return nil, err
		}
		firstSeen = append(firstSeen, digest)
	}
	return firstSeen, nil
}

// partitionBySource splits a node's stored component rows into the agent-collected
// slice and the externally-uploaded slice. The two producers — the agent's gRPC
// inventory stream and the open SBOM-upload edge — each replace only their own
// slice of node_components, so neither wipes the other; this is the partition both
// write paths use to compute the slice they own.
func partitionBySource(recs []ComponentRecord) (agent, external []ComponentRecord) {
	for _, r := range recs {
		if isExternalSource(r.Source) {
			external = append(external, r)
		} else {
			agent = append(agent, r)
		}
	}
	return agent, external
}

// externalComponents returns the node's currently-stored externally-uploaded
// component rows, the slice the agent's inventory commit must carry through so an
// agent report never wipes an operator's uploaded scan.
func (s *Server) externalComponents(ws, nodeID string) ([]ComponentRecord, error) {
	recs, err := s.store.ListNodeComponents(ws, nodeID)
	if err != nil {
		return nil, err
	}
	_, external := partitionBySource(recs)
	return external, nil
}

// componentsFromRecords lifts stored component rows back into the flat SBOM view the
// delta applier and encoder work on.
func componentsFromRecords(recs []ComponentRecord) []sbom.Component {
	out := make([]sbom.Component, 0, len(recs))
	for _, r := range recs {
		out = append(out, sbom.Component{
			Purl:      r.Purl,
			Name:      r.Name,
			Version:   r.Version,
			Ecosystem: r.Ecosystem,
			Distro:    r.Distro,
			Source:    r.Source,
		})
	}
	return out
}

// componentsFromProto lifts a delta's wire components into the flat SBOM view.
func componentsFromProto(in []*genezav1.InventoryComponent) []sbom.Component {
	out := make([]sbom.Component, 0, len(in))
	for _, c := range in {
		out = append(out, sbom.Component{
			Purl:      c.GetPurl(),
			Name:      c.GetName(),
			Version:   c.GetVersion(),
			Ecosystem: c.GetEcosystem(),
			Distro:    c.GetDistro(),
			Source:    c.GetSource(),
		})
	}
	return out
}
