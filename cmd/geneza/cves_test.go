package main

import (
	"testing"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// TestCvesNodeRow proves `geneza cves --node` formats a CVE row the way the
// table expects: CVE / package / status / severity(+KEV/EPSS triage hint) /
// fixed-in, with a dash where a fixed version is unknown.
func TestCvesNodeRow(t *testing.T) {
	row := nodeCVERow(&genezav1.NodeCVEInfo{
		Cve: "CVE-2021-1", Purl: "pkg:deb/debian/openssl@1.1.1f", Status: "affected",
		Severity: "high", Kev: true, Epss: 0.91, FixedVersion: "1.1.1f-1+deb11u1",
	})
	want := []string{"CVE-2021-1", "pkg:deb/debian/openssl@1.1.1f", "affected", "high KEV epss=0.91", "1.1.1f-1+deb11u1"}
	for i := range want {
		if row[i] != want[i] {
			t.Fatalf("col %d = %q, want %q (row=%v)", i, row[i], want[i], row)
		}
	}

	// No fixed version, no exploit signals: a clean low-noise row.
	row = nodeCVERow(&genezav1.NodeCVEInfo{Cve: "CVE-2021-2", Purl: "p", Status: "fixed", Severity: "medium"})
	if row[3] != "medium" || row[4] != "-" {
		t.Fatalf("low-noise row wrong: %v", row)
	}
}

// TestCvesAffectedRow proves `geneza cves --cve` formats a node row: node /
// package / status / fixed-in.
func TestCvesAffectedRow(t *testing.T) {
	row := affectedNodeRow(&genezav1.NodeCVEInfo{
		NodeId: "n1", Purl: "pkg:deb/debian/curl@7.74.0", Status: "affected", FixedVersion: "",
	})
	want := []string{"n1", "pkg:deb/debian/curl@7.74.0", "affected", "-"}
	for i := range want {
		if row[i] != want[i] {
			t.Fatalf("col %d = %q, want %q (row=%v)", i, row[i], want[i], row)
		}
	}
}

// TestCvesCmdWiring proves the single `cves` verb carries the flags the three
// lenses rely on, so the CLI actually reaches ListWorkspaceCVEs / ListNodeCVEs /
// ListNodesAffectedByCVE.
func TestCvesCmdWiring(t *testing.T) {
	cmd := newCvesCmd()
	if cmd.Use != "cves" {
		t.Fatalf("use = %q", cmd.Use)
	}
	for _, f := range []string{"node", "cve", "filter", "affected-only"} {
		if cmd.Flags().Lookup(f) == nil {
			t.Fatalf("cves missing --%s flag", f)
		}
	}
}
