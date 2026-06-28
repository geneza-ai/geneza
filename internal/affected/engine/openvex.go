package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	openvex "github.com/openvex/go-vex/pkg/vex"
)

// DocVEX is a VEXSource backed by real OpenVEX documents on disk. It loads a
// directory of OpenVEX JSON (the openvex/spec shape: a document with statements,
// each naming a vulnerability, a set of products by purl, and a status), and
// answers the engine's per-(cve, purl) suppression lookup from the not_affected
// statements it parsed.
//
// Layout: documents directly under the configured root apply to every workspace
// (vendor / platform-wide VEX); documents in a "<root>/<workspace>" subdirectory
// apply only to that workspace. A Suppressed(ws, ...) lookup consults both the
// workspace's own statements and the global ones, so a global vendor assertion and
// a workspace-local one compose.
//
// Only not_affected statements suppress. An affected/fixed/under_investigation
// statement never upgrades a verdict — the engine asks DocVEX solely to downgrade
// an otherwise-affected component, so non-suppressing statuses are simply not
// indexed.
type DocVEX struct {
	mu sync.RWMutex
	// global holds statements that apply to every workspace; perWS[ws] holds the
	// statements scoped to one workspace. Each maps a vulnerability id to its
	// not_affected assertions, so a lookup is a vuln-keyed scan over a small set.
	global suppressionIndex
	perWS  map[string]suppressionIndex
}

// suppressionEntry is one not_affected product assertion: the products the
// statement listed (matched with OpenVEX's own purl matching) and the recorded
// justification.
type suppressionEntry struct {
	products      []openvex.Product
	justification string
}

// suppressionIndex maps a vulnerability identifier (CVE or alias) to the
// not_affected assertions filed against it.
type suppressionIndex map[string][]suppressionEntry

// NewDocVEX builds an empty OpenVEX source. Load or LoadDir populate it.
func NewDocVEX() *DocVEX {
	return &DocVEX{global: suppressionIndex{}, perWS: map[string]suppressionIndex{}}
}

var _ VEXSource = (*DocVEX)(nil)

// LoadDir replaces the source's contents from a directory tree: *.json directly
// under root are global documents; *.json one level down under "root/<ws>" are
// scoped to workspace <ws>. A missing root is not an error (no statements). It
// returns how many statements were indexed so a caller can log/verify a load.
func (d *DocVEX) LoadDir(root string) (int, error) {
	global := suppressionIndex{}
	perWS := map[string]suppressionIndex{}

	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			d.swap(global, perWS)
			return 0, nil
		}
		return 0, fmt.Errorf("openvex: read dir %s: %w", root, err)
	}

	indexed := 0
	for _, ent := range entries {
		if ent.IsDir() {
			idx := suppressionIndex{}
			n, err := loadInto(filepath.Join(root, ent.Name()), idx)
			if err != nil {
				return 0, err
			}
			if n > 0 {
				perWS[ent.Name()] = idx
			}
			indexed += n
			continue
		}
		if !isJSON(ent.Name()) {
			continue
		}
		n, err := indexDoc(filepath.Join(root, ent.Name()), global)
		if err != nil {
			return 0, err
		}
		indexed += n
	}

	d.swap(global, perWS)
	return indexed, nil
}

// Load parses a set of OpenVEX documents already in memory into the global scope,
// replacing any prior contents. It is the in-test / programmatic counterpart to
// LoadDir and shares the same indexing.
func (d *DocVEX) Load(docs ...*openvex.VEX) {
	global := suppressionIndex{}
	for _, doc := range docs {
		indexVEX(doc, global)
	}
	d.swap(global, map[string]suppressionIndex{})
}

// swap installs a freshly-built index under the write lock, so a concurrent
// Suppressed never observes a half-loaded set.
func (d *DocVEX) swap(global suppressionIndex, perWS map[string]suppressionIndex) {
	d.mu.Lock()
	d.global = global
	d.perWS = perWS
	d.mu.Unlock()
}

// loadInto indexes every *.json document directly under dir into idx, returning
// the count. A missing dir is not an error.
func loadInto(dir string, idx suppressionIndex) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("openvex: read dir %s: %w", dir, err)
	}
	indexed := 0
	for _, ent := range entries {
		if ent.IsDir() || !isJSON(ent.Name()) {
			continue
		}
		n, err := indexDoc(filepath.Join(dir, ent.Name()), idx)
		if err != nil {
			return 0, err
		}
		indexed += n
	}
	return indexed, nil
}

// indexDoc parses one OpenVEX JSON file and folds its not_affected statements into
// idx, returning how many it added.
func indexDoc(path string, idx suppressionIndex) (int, error) {
	doc, err := openvex.Open(path)
	if err != nil {
		return 0, fmt.Errorf("openvex: load %s: %w", path, err)
	}
	return indexVEX(doc, idx), nil
}

// indexVEX folds a parsed document's not_affected statements into idx, keyed by
// the statement's vulnerability name and each of its aliases, so a lookup by
// either the CVE or an alias resolves it. Returns how many statements it indexed.
func indexVEX(doc *openvex.VEX, idx suppressionIndex) int {
	if doc == nil {
		return 0
	}
	indexed := 0
	for i := range doc.Statements {
		st := doc.Statements[i]
		if st.Status != openvex.StatusNotAffected {
			continue
		}
		if len(st.Products) == 0 {
			continue
		}
		entry := suppressionEntry{
			products:      st.Products,
			justification: string(st.Justification),
		}
		for _, key := range vulnKeys(st.Vulnerability) {
			idx[key] = append(idx[key], entry)
		}
		indexed++
	}
	return indexed
}

// vulnKeys returns every identifier a statement's vulnerability can be looked up
// by: its primary name plus any aliases, so a document that files under an
// advisory alias still resolves when the engine asks by the CVE (and vice versa).
func vulnKeys(v openvex.Vulnerability) []string {
	keys := make([]string, 0, 1+len(v.Aliases))
	if v.Name != "" {
		keys = append(keys, string(v.Name))
	}
	for _, a := range v.Aliases {
		if a != "" {
			keys = append(keys, string(a))
		}
	}
	return keys
}

// Suppressed reports whether a not_affected statement clears (cve, purl) for the
// workspace, consulting the workspace's own statements then the global ones. The
// purl is matched with OpenVEX's purl-aware product matching, so a statement that
// lists a versionless or qualifier-light purl still clears the concrete component
// purl. The recorded justification is returned on a hit.
func (d *DocVEX) Suppressed(ws, cve, purl string) (string, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if idx, ok := d.perWS[ws]; ok {
		if j, ok := matchPurl(idx, cve, purl); ok {
			return j, true
		}
	}
	return matchPurl(d.global, cve, purl)
}

// matchPurl scans the not_affected entries filed against the vulnerability for one
// whose product set matches the purl, returning its justification.
func matchPurl(idx suppressionIndex, cve, purl string) (string, bool) {
	for _, e := range idx[cve] {
		for i := range e.products {
			if e.products[i].Matches(purl, "") {
				return e.justification, true
			}
		}
	}
	return "", false
}

func isJSON(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".json")
}
