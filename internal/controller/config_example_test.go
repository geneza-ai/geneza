package controller

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// The example config is the only place most operators ever learn a key exists.
// It had drifted badly: vuln_feed, console, store, install_dir and metrics_url
// were all absent, so a deployment built from it collected SBOMs and matched them
// against nothing, and served no console at all. Keeping it in sync by hand does
// not work — this asserts it.
//
// A key belongs here whether it is live or commented out; what must not happen is
// a key existing in the struct and appearing nowhere in the file.
var exampleConfigUndocumented = map[string]string{
	"metrics_retention":   "accepted but ignored; retention lives on the metrics backend",
	"session_p2p":         "staging flag for the unfinished p2p session transport",
	"require_split_trust": "one-way migration flip, documented in docs/update-trust.md",
	"relay_secrets":       "multi-region TURN secrets; relay_shared_secret is the documented form",
	"reauth_interval":     "continuous-authz sweep period; tuning knob, not a deployment choice",
}

func TestExampleConfigDocumentsEveryKey(t *testing.T) {
	raw, err := os.ReadFile("testdata/controller.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// A key counts as documented when it appears at the start of a line, live or
	// commented: "vuln_feed:" or "# vuln_feed:".
	present := func(key string) bool {
		re := regexp.MustCompile(`(?m)^\s*#?\s*` + regexp.QuoteMeta(key) + `:`)
		return re.Match(raw)
	}

	var missing []string
	rt := reflect.TypeOf(Config{})
	for i := range rt.NumField() {
		tag := rt.Field(i).Tag.Get("yaml")
		key, _, _ := strings.Cut(tag, ",")
		if key == "" || key == "-" {
			continue
		}
		if _, ok := exampleConfigUndocumented[key]; ok {
			continue
		}
		if !present(key) {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("controller.example.yaml documents no %v — add them (commented is fine), "+
			"or record why not in exampleConfigUndocumented", missing)
	}
}

// The reported symptom was a fresh deployment showing a full SBOM inventory and
// zero CVEs. The example must not be a config that reproduces it.
func TestExampleConfigEnablesAVulnFeed(t *testing.T) {
	cfg, err := LoadConfig("testdata/controller.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VulnFeed.Source == "" {
		t.Fatal("the example config collects SBOMs but matches them against nothing")
	}
}
