package enrich

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Refresh fetches whichever feeds are configured and replaces the snapshot. It is
// all-or-nothing per refresh: a configured feed that fails fails the whole refresh
// so the prior snapshot is kept rather than half-updated. A feed left unconfigured
// (empty URL) contributes an empty set without a fetch. The caller serializes
// Refresh against itself (the sync chore's debounce already does).
func (e *Enricher) Refresh(ctx context.Context) error {
	next := &snapshot{kev: map[string]struct{}{}, epss: map[string]float64{}}

	if e.kevURL != "" {
		kev, err := e.fetchKEV(ctx)
		if err != nil {
			return err
		}
		next.kev = kev
	}
	if e.epssURL != "" {
		epss, err := e.fetchEPSS(ctx)
		if err != nil {
			return err
		}
		next.epss = epss
	}

	e.snap = next
	return nil
}

// fetchKEV GETs the CISA catalog and returns the set of CVE ids it lists. The
// catalog is a JSON object with a "vulnerabilities" array, each entry carrying a
// "cveID"; only that field is needed for the membership set.
func (e *Enricher) fetchKEV(ctx context.Context) (map[string]struct{}, error) {
	body, err := e.get(ctx, e.kevURL)
	if err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	defer body.Close()

	var cat struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(body).Decode(&cat); err != nil {
		return nil, fmt.Errorf("kev: decode: %w", err)
	}
	set := make(map[string]struct{}, len(cat.Vulnerabilities))
	for _, v := range cat.Vulnerabilities {
		if id := strings.TrimSpace(v.CveID); id != "" {
			set[id] = struct{}{}
		}
	}
	return set, nil
}

// fetchEPSS GETs the FIRST daily scores export and returns a CVE→score map. The
// export is a gzip CSV whose first line is a "#model_version,..." comment, then a
// "cve,epss,percentile" header, then one row per CVE. A non-gzip body (the API
// JSON form, or a plain CSV in a test) is read directly, so the parser tolerates
// either transport.
func (e *Enricher) fetchEPSS(ctx context.Context) (map[string]float64, error) {
	body, err := e.get(ctx, e.epssURL)
	if err != nil {
		return nil, fmt.Errorf("epss: %w", err)
	}
	defer body.Close()

	r, err := maybeGunzip(body)
	if err != nil {
		return nil, fmt.Errorf("epss: %w", err)
	}
	return parseEPSSCSV(r)
}

// parseEPSSCSV reads the FIRST scores CSV: it skips the leading "#"-prefixed
// comment line(s) and the column header, then maps each cve to its epss score.
// Malformed rows are skipped rather than failing the whole feed.
func parseEPSSCSV(r io.Reader) (map[string]float64, error) {
	br := bufio.NewReader(r)
	// Skip leading comment lines (the FIRST export opens with "#model_version,...").
	for {
		b, err := br.Peek(1)
		if err != nil {
			if err == io.EOF {
				return map[string]float64{}, nil
			}
			return nil, fmt.Errorf("epss: read: %w", err)
		}
		if b[0] != '#' {
			break
		}
		if _, err := br.ReadString('\n'); err != nil && err != io.EOF {
			return nil, fmt.Errorf("epss: read comment: %w", err)
		}
	}

	cr := csv.NewReader(br)
	cr.FieldsPerRecord = -1 // tolerate ragged rows rather than erroring
	out := map[string]float64{}
	header := true
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("epss: csv: %w", err)
		}
		if len(rec) < 2 {
			continue
		}
		if header {
			// The first data line is the "cve,epss,percentile" header; skip it.
			header = false
			if strings.EqualFold(strings.TrimSpace(rec[0]), "cve") {
				continue
			}
		}
		cve := strings.TrimSpace(rec[0])
		if !strings.HasPrefix(cve, "CVE-") {
			continue
		}
		score, err := strconv.ParseFloat(strings.TrimSpace(rec[1]), 64)
		if err != nil {
			continue
		}
		out[cve] = score
	}
	return out, nil
}

// maybeGunzip wraps a body in a gzip reader when it starts with the gzip magic, so
// the .csv.gz export and a plain-CSV test fixture both parse. The peeked bytes are
// preserved via the buffered reader.
func maybeGunzip(body io.Reader) (io.Reader, error) {
	br := bufio.NewReader(body)
	magic, err := br.Peek(2)
	if err != nil {
		if err == io.EOF {
			return br, nil
		}
		return nil, err
	}
	if magic[0] == 0x1f && magic[1] == 0x8b {
		return gzip.NewReader(br)
	}
	return br, nil
}

// get issues a GET through the injectable client and returns the body on a 200,
// erroring on any other status so a refresh never folds an error page into a feed.
func (e *Enricher) get(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request %s: %w", url, err)
	}
	resp, err := e.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}
	return resp.Body, nil
}
