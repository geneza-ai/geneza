// Package enrich fetches the two public prioritization feeds Geneza overlays on a
// CVE verdict — CISA's Known Exploited Vulnerabilities catalog and FIRST's EPSS
// exploit-prediction scores — and exposes them as a lookup the matcher and the
// sync chore consult. Both feeds are fetched over an injectable HTTP surface, so a
// test serves them from fixtures and the live CISA/FIRST endpoints are never a
// test dependency. The data is advisory: a zero value means "no signal", never
// "no risk".
package enrich

import (
	"net/http"
)

// DefaultKEVURL is the CISA Known Exploited Vulnerabilities catalog feed.
const DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// DefaultEPSSURL is the FIRST EPSS daily scores export (gzip CSV of every CVE's
// current score).
const DefaultEPSSURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

// httpDoer is the injectable HTTP surface the feeds fetch through. *http.Client
// satisfies it; a test serves a fixture body so the live endpoints are never hit.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Enricher holds the most recently fetched KEV set and EPSS scores and answers the
// per-CVE prioritization lookup. It is safe to build empty (every lookup returns
// no signal) and to Refresh repeatedly; a Refresh replaces the snapshot wholesale.
type Enricher struct {
	kevURL  string
	epssURL string
	http    httpDoer

	snap *snapshot
}

// snapshot is one immutable fetch result: the KEV membership set and the EPSS
// score map. Refresh swaps a new one in atomically (a single pointer store under
// the caller's serialization), so a lookup never observes a half-built map.
type snapshot struct {
	kev  map[string]struct{}
	epss map[string]float64
}

// Options configure an Enricher. Empty URLs fall back to the live CISA/FIRST
// endpoints; a nil HTTP client falls back to http.DefaultClient. KEVURL or EPSSURL
// may be left empty independently to disable just that feed.
type Options struct {
	KEVURL  string
	EPSSURL string
	HTTP    httpDoer
}

// New builds an Enricher from options. It does not fetch — call Refresh.
func New(opts Options) *Enricher {
	doer := opts.HTTP
	if doer == nil {
		doer = http.DefaultClient
	}
	return &Enricher{
		kevURL:  opts.KEVURL,
		epssURL: opts.EPSSURL,
		http:    doer,
		snap:    &snapshot{kev: map[string]struct{}{}, epss: map[string]float64{}},
	}
}

// Enabled reports whether either feed is configured, so a caller can skip the
// refresh chore entirely when no enrichment source is set.
func (e *Enricher) Enabled() bool { return e.kevURL != "" || e.epssURL != "" }

// Lookup returns the prioritization signal for one CVE from the last refresh: KEV
// membership and the EPSS score. Both default to their zero value when the CVE is
// absent or the feed was never refreshed.
func (e *Enricher) Lookup(cve string) (kev bool, epss float64) {
	s := e.snap
	if s == nil {
		return false, 0
	}
	_, kev = s.kev[cve]
	epss = s.epss[cve]
	return kev, epss
}
