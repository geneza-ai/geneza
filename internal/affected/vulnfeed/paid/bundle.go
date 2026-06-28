// Package paid is a vulnfeed.Feed backed by a curated, signed advisory bundle the
// vendor serves over HTTP — the drop-in upgrade behind the same seam the open OSV
// feeds use. The client authenticates with a license key, fetches a bundle, and
// verifies the vendor's signature against a PINNED public key before ingesting a
// single advisory: so a man-in-the-middle can neither suppress an advisory by
// dropping it (suppression-by-omission, the threat for a vuln feed) nor inject a
// forged one without invalidating the signature. The bundle is monotonically
// versioned and the client rejects any bundle at or below the last version it
// ingested, so a captured older bundle cannot be replayed to roll the feed back.
//
// The matcher cannot tell this feed from the open one: it writes advisories
// through the same PutAdvisories path and serves by-package reads from the same
// store. The only additions over the open feed are the auth, the signature/version
// trust check, and the curated per-CVE enrichment the bundle carries.
package paid

import (
	"geneza.io/internal/affected/vulnfeed"
)

// signContext domain-separates the bundle signature from every other signed
// document in the system, so a signature lifted from one envelope can never be
// replayed as a bundle (and vice versa).
const signContext = "vulnfeed-bundle"

// Bundle is the unit the curated feed serves and the client verifies as a whole:
// a monotonically increasing Version plus the advisories that make up the feed's
// current view. The signature is over the whole bundle, so a man-in-the-middle can
// neither drop an advisory (suppression-by-omission) nor inject a forged one
// without invalidating it; the Version is the rollback guard — a client rejects a
// bundle whose Version is not strictly greater than the last it ingested, so a
// captured older bundle cannot be replayed to roll the feed back.
type Bundle struct {
	// Version is the bundle's monotonic sequence number. The client tracks the
	// highest it has ingested and rejects any bundle at or below that watermark.
	Version int64 `json:"version"`
	// Advisories is the feed's current curated set. Each ships the OSV-shaped
	// vulnerability the matcher consumes plus the curated prioritization signal.
	Advisories []CuratedAdvisory `json:"advisories"`
}

// CuratedAdvisory is one advisory in a bundle: the OSV-shaped vulnerability the
// matcher resolves against, the verbatim curated document retained as the stored
// advisory's Doc, and the per-CVE enrichment the curated feed authored (KEV/EPSS/
// severity). The Doc is what the open feed would call the source advisory; here it
// is the vendor's curated record.
type CuratedAdvisory struct {
	// Vuln is the matcher-facing advisory: identifiers and affected-package ranges.
	Vuln vulnfeed.Vulnerability `json:"vuln"`
	// Doc is the verbatim curated record stored as the advisory's Doc, so a future
	// reader recovers the full curated fields the minimal Vuln does not model. When
	// empty the feed stores the canonical JSON of Vuln instead.
	Doc []byte `json:"doc,omitempty"`
	// Enrichment is the curated prioritization signal for this advisory's CVE. A
	// zero value means the feed carries no signal for it (not "no risk").
	Enrichment vulnfeed.Enrichment `json:"enrichment,omitempty"`
}
