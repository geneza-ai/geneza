package osv

import (
	"encoding/json"
	"time"

	"geneza.io/internal/affected/vulnfeed"
)

// osvRecord is the subset of the OSV schema a source parses out of each document.
// The whole document is also retained verbatim (as the advisory Doc) so no field
// is lost — including the per-source license/attribution OSV carries per advisory.
type osvRecord struct {
	ID       string              `json:"id"`
	Modified time.Time           `json:"modified"`
	Aliases  []string            `json:"aliases"`
	Affected []osvAffectedRecord `json:"affected"`
}

type osvAffectedRecord struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		Purl      string `json:"purl"`
	} `json:"package"`
}

// advisoryRecordsFromDoc parses one OSV JSON document and emits one
// vulnfeed.AdvisoryRecord per distinct (ecosystem, name) the record names. The
// by-package index is keyed (ecosystem, name), so a record affecting several
// packages must resolve from each; the Doc is the same verbatim bytes on each
// row, so each advisory's own upstream license travels with every row. A record
// with no id, or whose `modified` is strictly before `since` when since is
// non-zero, contributes no rows (skipped=true). The returned modified is the
// record's own `modified` timestamp so a source can advance its watermark even
// past records it skips.
func advisoryRecordsFromDoc(doc []byte, since time.Time) (recs []vulnfeed.AdvisoryRecord, modified time.Time, skipped bool, err error) {
	var rec osvRecord
	if err := json.Unmarshal(doc, &rec); err != nil {
		return nil, time.Time{}, false, err
	}
	if rec.ID == "" {
		return nil, rec.Modified, true, nil
	}
	if !since.IsZero() && rec.Modified.Before(since) {
		return nil, rec.Modified, true, nil
	}
	seen := map[string]bool{}
	for _, a := range rec.Affected {
		eco, name := a.Package.Ecosystem, a.Package.Name
		if eco == "" || name == "" {
			continue
		}
		key := eco + "\x00" + name
		if seen[key] {
			continue
		}
		seen[key] = true
		recs = append(recs, vulnfeed.AdvisoryRecord{
			ID:           advisoryID(rec.ID, eco, name),
			Source:       "osv",
			Ecosystem:    eco,
			PackageName:  name,
			Doc:          doc,
			ModifiedUnix: rec.Modified.Unix(),
		})
	}
	return recs, rec.Modified, false, nil
}

// advisoryID keys an advisory row by its OSV id plus the package it was filed
// against, so a record affecting multiple ecosystems/packages stores one
// resolvable row each instead of colliding on the bare OSV id.
func advisoryID(osvID, ecosystem, name string) string {
	return osvID + "/" + ecosystem + "/" + name
}

// parseVulnerability maps an OSV JSON document onto the seam's Vulnerability,
// keeping the raw bytes so no source field (including the per-source license) is
// dropped.
func parseVulnerability(doc json.RawMessage) (vulnfeed.Vulnerability, error) {
	var v vulnfeed.Vulnerability
	if len(doc) == 0 {
		return v, nil
	}
	if err := json.Unmarshal(doc, &v); err != nil {
		return v, err
	}
	v.Raw = append([]byte(nil), doc...)
	return v, nil
}
