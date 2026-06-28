package vulnfeed

import (
	"encoding/json"
	"testing"
)

// TestSeverityFromDatabaseSpecific proves the advisory's own database_specific
// severity is surfaced as the offline default, with no enrichment feed involved.
func TestSeverityFromDatabaseSpecific(t *testing.T) {
	doc := `{
		"id": "GHSA-x",
		"aliases": ["CVE-2025-1"],
		"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}],
		"database_specific": {"severity": "CRITICAL"},
		"affected": [{"package": {"ecosystem": "npm", "name": "next"}}]
	}`
	var v Vulnerability
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v.Severity != "CRITICAL" {
		t.Fatalf("database_specific severity: want CRITICAL, got %q", v.Severity)
	}
}

// TestSeverityFromCVSSVector proves the qualitative band is derived from the CVSS
// vector when the record carries no database_specific.severity label.
func TestSeverityFromCVSSVector(t *testing.T) {
	cases := []struct {
		vector string
		want   string
	}{
		// AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N -> base 9.1 -> CRITICAL.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "CRITICAL"},
		// A lower-impact vector lands in a lower band.
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", "LOW"},
	}
	for _, tc := range cases {
		doc := `{"id":"x","severity":[{"type":"CVSS_V3","score":"` + tc.vector + `"}]}`
		var v Vulnerability
		if err := json.Unmarshal([]byte(doc), &v); err != nil {
			t.Fatalf("unmarshal %s: %v", tc.vector, err)
		}
		if v.Severity != tc.want {
			t.Fatalf("vector %s: want band %q, got %q", tc.vector, tc.want, v.Severity)
		}
	}
}

// TestSeverityAbsent proves an advisory carrying neither a label nor a scorable
// vector yields an empty severity (not a guess).
func TestSeverityAbsent(t *testing.T) {
	var v Vulnerability
	if err := json.Unmarshal([]byte(`{"id":"x","affected":[]}`), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v.Severity != "" {
		t.Fatalf("absent severity: want empty, got %q", v.Severity)
	}
}
