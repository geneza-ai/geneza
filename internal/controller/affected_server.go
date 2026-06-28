package controller

import (
	"context"

	"geneza.io/internal/affected/engine"
	"geneza.io/internal/affected/vulnfeed"
)

// affectedMatcher builds a matcher bound to this server's store. vex is the
// suppression source (nil suppresses nothing); the single-node default has none
// until a workspace records statements. The KEV/EPSS enricher (nil when no feed is
// configured) is passed as a nil interface, not a typed nil, so the matcher's nil
// check holds.
func (s *Server) affectedMatcher(vex engine.VEXSource) *affectedMatcher {
	var enricher cveEnricher
	if s.inventoryEnricher != nil {
		enricher = s.inventoryEnricher
	}
	m := newAffectedMatcher(s.store, vex, enricher)
	// Fold in the configured registry scan-by-digest provider; the constructor's no-op
	// default stays in place when none is wired, so the image match path is unchanged.
	if s.inventoryImageAdvisor != nil {
		m.imageAdvisor = s.inventoryImageAdvisor
	}
	return m
}

// RematchChangedAdvisory is the post-sync hook: after a feed writes a changed
// advisory, re-evaluate the (tiny) set of nodes carrying its package across every
// workspace and update node_cve, AND re-match every image digest carrying the package
// (once, digest-keyed) so image-sourced verdicts converge too — no node contact, no
// fleet scan. Returns the number of verdict rows written across both.
func (s *Server) RematchChangedAdvisory(ctx context.Context, vex engine.VEXSource, adv vulnfeed.Vulnerability) (int, error) {
	m := s.affectedMatcher(vex)
	n, err := m.MatchAdvisoryAllWorkspaces(ctx, adv)
	if err != nil {
		return n, err
	}
	if s.inventoryFeed == nil {
		return n, nil
	}
	w, err := m.MatchAdvisoryImages(ctx, s.inventoryFeed, adv)
	return n + w, err
}

// RematchNode is the node-change hook: re-evaluate one node's stored host components
// against the feed and update node_cve. Image-sourced verdicts are matched per digest
// (see RematchImageDigest) rather than here, since they are shared across nodes.
// Returns the number of rows written.
func (s *Server) RematchNode(ctx context.Context, feed vulnfeed.Feed, vex engine.VEXSource, ws, nodeID string) (int, error) {
	return s.affectedMatcher(vex).MatchNode(ctx, feed, ws, nodeID)
}

// RematchImageDigest re-evaluates one image digest's stored components against the
// feed and replace-sets its image_cve verdicts. Called once when a digest is first
// seen; its verdicts then fan to every associated node on read. Returns the rows
// written.
func (s *Server) RematchImageDigest(ctx context.Context, feed vulnfeed.Feed, vex engine.VEXSource, digest string) (int, error) {
	return s.affectedMatcher(vex).MatchImageDigest(ctx, feed, digest)
}
