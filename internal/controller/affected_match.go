package controller

import (
	"context"
	"time"

	"geneza.io/internal/affected"
	"geneza.io/internal/affected/engine"
	"geneza.io/internal/affected/vulnfeed"
)

// cveEnricher is the per-CVE prioritization lookup the matcher consults when it
// writes a verdict, so a newly computed row carries the KEV/EPSS signal without
// waiting for the next enrichment pass. The enrich.Enricher satisfies it; a nil
// enricher leaves the fields zero.
type cveEnricher interface {
	Lookup(cve string) (kev bool, epss float64)
}

// affectedMatcher runs the affectedness engine against the stored inventory and
// writes the verdicts into node_cve. It is the bridge between the feed/engine
// (which speak in seam types) and the store (which speaks in records): both
// triggers stay workspace-scoped and tenant-isolated, and neither contacts a node
// — matching is a join over already-stored data.
type affectedMatcher struct {
	store    Store
	vex      engine.VEXSource
	enricher cveEnricher
	// imageAdvisor is the registry scan-by-digest provider consulted when matching an
	// image digest: it contributes advisories a feed already knows the image carries,
	// so a digest the registry pre-scanned is covered even beyond the locally-synced
	// advisory set. Never nil — an unconfigured deployment holds the no-op default,
	// which contributes nothing, so the match path needs no presence check.
	imageAdvisor vulnfeed.ImageAdvisoryProvider
	now          func() time.Time
}

func newAffectedMatcher(store Store, vex engine.VEXSource, enricher cveEnricher) *affectedMatcher {
	return &affectedMatcher{store: store, vex: vex, enricher: enricher, imageAdvisor: vulnfeed.NoImageAdvisories{}, now: time.Now}
}

// componentFromRecord lifts a stored component into the engine's Component shape.
func componentFromRecord(r ComponentRecord) affected.Component {
	return affected.Component{
		NodeID:    r.NodeID,
		Purl:      r.Purl,
		Source:    r.Source,
		Ecosystem: r.Ecosystem,
		Name:      r.Name,
		Version:   r.Version,
		Distro:    r.Distro,
	}
}

// persist writes one match as a node_cve verdict for the workspace. The match's
// component carries the node id and purl that key the row; the KEV/EPSS fields are
// filled from the enricher's current snapshot (zero when no enricher is wired) so
// a freshly written verdict is prioritized immediately.
func (m *affectedMatcher) persist(ws string, mt affected.Match) error {
	var kev bool
	var epss float64
	if m.enricher != nil {
		kev, epss = m.enricher.Lookup(mt.CVE)
	}
	return m.store.UpsertNodeCVE(&NodeCVERecord{
		WorkspaceID:      ws,
		NodeID:           mt.Component.NodeID,
		CVE:              mt.CVE,
		Purl:             mt.Component.Purl,
		Status:           string(mt.Status),
		Severity:         mt.Severity,
		KEV:              kev,
		EPSS:             epss,
		VEXJustification: mt.VEXJustification,
		FixedVersion:     mt.FixedVersion,
		MatchedUnix:      m.now().Unix(),
	})
}

// imageComponentForMatch lifts a stored image component into the engine's Component
// shape. NodeID is left empty: an image verdict is keyed by digest, not node, and the
// node attribution is supplied at read-time fan-out from the node->digest association.
func imageComponentForMatch(r ImageComponentRecord) affected.Component {
	return affected.Component{
		Purl:      r.Purl,
		Source:    r.Source,
		Ecosystem: r.Ecosystem,
		Name:      r.Name,
		Version:   r.Version,
		Distro:    r.Distro,
	}
}

// persistImage writes one image match as an image_cve verdict keyed by digest. Like
// persist, it fills KEV/EPSS from the enricher so a freshly written digest verdict is
// prioritized immediately; the node attribution happens later at read fan-out.
func (m *affectedMatcher) persistImage(digest string, mt affected.Match) error {
	var kev bool
	var epss float64
	if m.enricher != nil {
		kev, epss = m.enricher.Lookup(mt.CVE)
	}
	return m.store.PutImageCVE(&ImageCVERecord{
		Digest:           digest,
		CVE:              mt.CVE,
		Purl:             mt.Component.Purl,
		Status:           string(mt.Status),
		Severity:         mt.Severity,
		KEV:              kev,
		EPSS:             epss,
		VEXJustification: mt.VEXJustification,
		FixedVersion:     mt.FixedVersion,
		MatchedUnix:      m.now().Unix(),
	})
}

// MatchImageDigest is the image-side node-change direction: re-match one image
// digest's stored components against the feed and replace-set its image_cve verdicts.
// It is digest-keyed and tenant-independent (the digest is content-addressable), so a
// match runs once and its result fans to every associated node on read. The VEX
// source is a digest-global one (image verdicts are not workspace-scoped); a
// per-workspace VEX statement does not apply here. Returns the rows written.
func (m *affectedMatcher) MatchImageDigest(ctx context.Context, feed vulnfeed.Feed, digest string) (int, error) {
	comps, err := m.store.ListImageComponents(digest)
	if err != nil {
		return 0, err
	}
	cs := make([]affected.Component, len(comps))
	for i := range comps {
		cs[i] = imageComponentForMatch(comps[i])
	}
	// Image verdicts are digest-global, so the engine runs without a workspace-scoped
	// VEX source: a node's per-workspace suppression cannot rewrite a shared image's
	// verdict for every other tenant running the same bytes.
	eng := engine.New("", nil)
	matches, err := eng.MatchNode(ctx, feed, digest, cs)
	if err != nil {
		return 0, err
	}
	// Consult the registry scan-by-digest provider: it contributes advisories the feed
	// already knows this image carries (a pre-scanned registry image), folded in the
	// same way as the locally-resolved ones. The no-op default contributes nothing, so
	// a deployment with no upstream behaves exactly as the local-only path.
	imgAdvs, err := m.imageAdvisor.AdvisoriesForDigest(ctx, digest)
	if err != nil {
		return 0, err
	}
	for _, adv := range imgAdvs {
		ms, err := eng.MatchAdvisory(ctx, adv, cs)
		if err != nil {
			return 0, err
		}
		matches = append(matches, ms...)
	}
	// Replace-set: clear the prior verdicts before writing the fresh set so a feed
	// retraction (or a re-pinned digest) leaves no stale image verdict behind. Dedup on
	// (cve, purl) so a provider advisory that duplicates a feed match writes one row.
	if err := m.store.ClearImageCVEs(digest); err != nil {
		return 0, err
	}
	seen := map[string]struct{}{}
	written := 0
	for _, mt := range matches {
		k := mt.CVE + "\x00" + mt.Component.Purl
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		if err := m.persistImage(digest, mt); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

// MatchAdvisoryImages is the image-side new-CVE direction: a feed sync changed an
// advisory, so re-match (once) every image digest carrying its package and replace
// each digest's verdicts. Digests are global, so this runs outside any workspace loop;
// the verdicts fan to nodes on read. Returns the number of image_cve rows written.
func (m *affectedMatcher) MatchAdvisoryImages(ctx context.Context, feed vulnfeed.Feed, adv vulnfeed.Vulnerability) (int, error) {
	seen := map[string]struct{}{}
	written := 0
	for _, a := range adv.Affected {
		if a.Package.Name == "" || a.Package.Ecosystem == "" {
			continue
		}
		digests, err := m.store.ImageDigestsForPackage(a.Package.Ecosystem, a.Package.Name)
		if err != nil {
			return written, err
		}
		for _, d := range digests {
			if _, ok := seen[d]; ok {
				continue
			}
			seen[d] = struct{}{}
			// Re-match the whole digest (not just this advisory): a digest's verdict set
			// is a replace-set, so matching it against the full feed keeps unrelated
			// verdicts for the same digest intact while the changed advisory is folded in.
			w, err := m.MatchImageDigest(ctx, feed, d)
			if err != nil {
				return written, err
			}
			written += w
		}
	}
	return written, nil
}

// MatchAdvisory is the new-CVE direction: a feed sync changed an advisory, so
// select only the nodes carrying its package (the tiny candidate set the
// component index returns — never a fleet scan), run the engine for that
// workspace, and upsert the verdicts. It evaluates each affected package the
// advisory names. Returns the number of node_cve rows written.
func (m *affectedMatcher) MatchAdvisory(ctx context.Context, ws string, adv vulnfeed.Vulnerability) (int, error) {
	eng := engine.New(ws, m.vex)
	written := 0
	for _, a := range adv.Affected {
		if a.Package.Name == "" || a.Package.Ecosystem == "" {
			continue
		}
		comps, err := m.store.ListComponentsByPackage(ws, a.Package.Ecosystem, a.Package.Name)
		if err != nil {
			return written, err
		}
		if len(comps) == 0 {
			continue
		}
		cands := make([]affected.Component, len(comps))
		for i := range comps {
			cands[i] = componentFromRecord(comps[i])
		}
		matches, err := eng.MatchAdvisory(ctx, adv, cands)
		if err != nil {
			return written, err
		}
		for _, mt := range matches {
			if err := m.persist(ws, mt); err != nil {
				return written, err
			}
			written++
		}
	}
	return written, nil
}

// MatchNode is the node-change direction: a node's inventory changed, so re-match
// that one node's stored components against the feed and upsert the verdicts.
// Returns the number of node_cve rows written.
func (m *affectedMatcher) MatchNode(ctx context.Context, feed vulnfeed.Feed, ws, nodeID string) (int, error) {
	comps, err := m.store.ListNodeComponents(ws, nodeID)
	if err != nil {
		return 0, err
	}
	cs := make([]affected.Component, len(comps))
	for i := range comps {
		cs[i] = componentFromRecord(comps[i])
	}
	eng := engine.New(ws, m.vex)
	matches, err := eng.MatchNode(ctx, feed, nodeID, cs)
	if err != nil {
		return 0, err
	}
	// The node's components were re-derived as a replace-set, so its verdicts are too:
	// clear the prior rows before writing the fresh set, or a component that changed
	// version (new purl) or dropped out would leave a stale verdict keyed on the old
	// purl that the headline queries would keep returning.
	if err := m.store.ClearNodeCVEs(ws, nodeID); err != nil {
		return 0, err
	}
	written := 0
	for _, mt := range matches {
		if err := m.persist(ws, mt); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

// MatchAdvisoryAllWorkspaces fans the new-CVE direction across every workspace,
// so a single feed-sync change is reflected fleet-wide while each workspace's
// candidate selection and writes stay scoped to that workspace. Returns the total
// rows written.
func (m *affectedMatcher) MatchAdvisoryAllWorkspaces(ctx context.Context, adv vulnfeed.Vulnerability) (int, error) {
	wss, err := m.store.ListWorkspaces()
	if err != nil {
		return 0, err
	}
	total := 0
	for _, ws := range wss {
		n, err := m.MatchAdvisory(ctx, ws.ID, adv)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// advisoryStore adapts a controller Store to the feed's narrow vulnfeed.AdvisoryStore
// surface, translating between the seam's advisory record and the store's, so a
// feed writes/reads advisories without importing the store package.
type advisoryStore struct{ s Store }

// FeedStore wraps a controller Store as the advisory surface an osv (or any) feed
// writes to and reads from.
func FeedStore(s Store) vulnfeed.AdvisoryStore { return advisoryStore{s: s} }

func (a advisoryStore) PutAdvisories(recs []vulnfeed.AdvisoryRecord) error {
	out := make([]AdvisoryRecord, len(recs))
	for i, r := range recs {
		out[i] = AdvisoryRecord{
			ID:           r.ID,
			Source:       r.Source,
			Ecosystem:    r.Ecosystem,
			PackageName:  r.PackageName,
			Doc:          r.Doc,
			ModifiedUnix: r.ModifiedUnix,
		}
	}
	return a.s.PutAdvisories(out)
}

func (a advisoryStore) AdvisoriesForPackage(ecosystem, name string) ([]vulnfeed.AdvisoryRecord, error) {
	rows, err := a.s.AdvisoriesForPackage(ecosystem, name)
	if err != nil {
		return nil, err
	}
	out := make([]vulnfeed.AdvisoryRecord, len(rows))
	for i, r := range rows {
		out[i] = vulnfeed.AdvisoryRecord{
			ID:           r.ID,
			Source:       r.Source,
			Ecosystem:    r.Ecosystem,
			PackageName:  r.PackageName,
			Doc:          r.Doc,
			ModifiedUnix: r.ModifiedUnix,
		}
	}
	return out, nil
}
