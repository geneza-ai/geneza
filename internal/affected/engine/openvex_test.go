package engine

import (
	"os"
	"path/filepath"
	"testing"

	"geneza.io/internal/affected"
	"geneza.io/internal/affected/vulnfeed"
)

// openvexDoc is a minimal OpenVEX document literal: a vulnerability, a product
// purl, a status, and (for not_affected) a justification — the openvex/spec shape
// the real go-vex parser reads.
func openvexDoc(vuln, purl, status, justification string) string {
	just := ""
	if justification != "" {
		just = `, "justification": "` + justification + `"`
	}
	return `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "https://example.com/vex/test",
		"author": "test",
		"timestamp": "2024-01-01T00:00:00Z",
		"version": 1,
		"statements": [{
			"vulnerability": {"name": "` + vuln + `"},
			"products": [{"@id": "` + purl + `"}],
			"status": "` + status + `"` + just + `
		}]
	}`
}

// writeVEX writes one OpenVEX document into dir, creating dir as needed.
func writeVEX(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// opensslComp + opensslAdv are the affected pair the VEX tests suppress: an
// openssl build inside the vulnerable window, so with no VEX it is affected.
func opensslComp() affected.Component {
	return affected.Component{
		NodeID: "n1", Purl: "pkg:deb/debian/openssl@3.0.5-1",
		Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.5-1", Distro: "debian:12",
	}
}

func opensslAdv(t *testing.T) vulnfeed.Vulnerability {
	t.Helper()
	return vuln(t, `{
		"id": "OSV-OPENSSL-1",
		"aliases": ["CVE-2022-0778"],
		"affected": [{
			"package": {"ecosystem": "Debian:12", "name": "openssl"},
			"ranges": [{"type": "ECOSYSTEM", "events": [
				{"introduced": "0"},
				{"fixed": "3.0.7-1"}
			]}]
		}]
	}`)
}

// TestDocVEXSuppressesAffected is the headline: a not_affected OpenVEX statement
// for (CVE, purl) flips that component's engine verdict from affected to
// not_affected and records the justification.
func TestDocVEXSuppressesAffected(t *testing.T) {
	dir := t.TempDir()
	writeVEX(t, dir, "openssl.json", openvexDoc(
		"CVE-2022-0778", "pkg:deb/debian/openssl@3.0.5-1",
		"not_affected", "vulnerable_code_not_present"))

	v := NewDocVEX()
	n, err := v.LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 indexed statement, got %d", n)
	}

	// Baseline: with no VEX the component is affected.
	if base := matchOne(t, New("ws", nil), opensslComp(), opensslAdv(t)); base.Status != affected.StatusAffected {
		t.Fatalf("baseline: want affected, got %q", base.Status)
	}

	// With the not_affected VEX the verdict is downgraded with the justification.
	got := matchOne(t, New("ws", v), opensslComp(), opensslAdv(t))
	if got.Status != affected.StatusNotAffected {
		t.Fatalf("vex suppression: want not_affected, got %q", got.Status)
	}
	if got.VEXJustification != "vulnerable_code_not_present" {
		t.Errorf("want justification recorded, got %q", got.VEXJustification)
	}
}

// TestDocVEXAliasLookup proves a statement filed under the OSV advisory id resolves
// when the engine asks by the CVE the advisory aliases, via the statement's
// vulnerability aliases.
func TestDocVEXAliasLookup(t *testing.T) {
	dir := t.TempDir()
	// Statement names the OSV id but lists CVE-2022-0778 as an alias; the engine
	// keys suppression by the advisory's CVE alias.
	body := `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "https://example.com/vex/alias",
		"author": "test", "timestamp": "2024-01-01T00:00:00Z", "version": 1,
		"statements": [{
			"vulnerability": {"name": "OSV-OPENSSL-1", "aliases": ["CVE-2022-0778"]},
			"products": [{"@id": "pkg:deb/debian/openssl@3.0.5-1"}],
			"status": "not_affected",
			"justification": "inline_mitigations_already_exist"
		}]
	}`
	writeVEX(t, dir, "alias.json", body)
	v := NewDocVEX()
	if _, err := v.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	got := matchOne(t, New("ws", v), opensslComp(), opensslAdv(t))
	if got.Status != affected.StatusNotAffected || got.VEXJustification != "inline_mitigations_already_exist" {
		t.Fatalf("alias suppression: got status=%q just=%q", got.Status, got.VEXJustification)
	}
}

// TestDocVEXNonSuppressingStatuses proves an affected or fixed VEX statement never
// upgrades or changes the verdict — only not_affected suppresses.
func TestDocVEXNonSuppressingStatuses(t *testing.T) {
	for _, status := range []string{"affected", "fixed", "under_investigation"} {
		dir := t.TempDir()
		writeVEX(t, dir, "doc.json", openvexDoc("CVE-2022-0778", "pkg:deb/debian/openssl@3.0.5-1", status, ""))
		v := NewDocVEX()
		if _, err := v.LoadDir(dir); err != nil {
			t.Fatalf("LoadDir: %v", err)
		}
		got := matchOne(t, New("ws", v), opensslComp(), opensslAdv(t))
		if got.Status != affected.StatusAffected {
			t.Errorf("status=%s: want verdict unchanged (affected), got %q", status, got.Status)
		}
		if got.VEXJustification != "" {
			t.Errorf("status=%s: non-suppressing statement set a justification %q", status, got.VEXJustification)
		}
	}
}

// TestDocVEXWrongPurlNoSuppress proves a not_affected statement for a different
// component's purl does not suppress the matched component.
func TestDocVEXWrongPurlNoSuppress(t *testing.T) {
	dir := t.TempDir()
	writeVEX(t, dir, "doc.json", openvexDoc(
		"CVE-2022-0778", "pkg:deb/debian/curl@7.88.0", "not_affected", "vulnerable_code_not_present"))
	v := NewDocVEX()
	if _, err := v.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if got := matchOne(t, New("ws", v), opensslComp(), opensslAdv(t)); got.Status != affected.StatusAffected {
		t.Fatalf("wrong-purl VEX must not suppress: got %q", got.Status)
	}
}

// TestDocVEXWorkspaceScoping proves a workspace-scoped document only suppresses for
// its own workspace, while a global document suppresses for every workspace.
func TestDocVEXWorkspaceScoping(t *testing.T) {
	root := t.TempDir()
	// Workspace-scoped statement under <root>/wsA only.
	writeVEX(t, filepath.Join(root, "wsA"), "scoped.json", openvexDoc(
		"CVE-2022-0778", "pkg:deb/debian/openssl@3.0.5-1", "not_affected", "component_not_present"))
	v := NewDocVEX()
	if _, err := v.LoadDir(root); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if got := matchOne(t, New("wsA", v), opensslComp(), opensslAdv(t)); got.Status != affected.StatusNotAffected {
		t.Fatalf("wsA scoped VEX must suppress in wsA: got %q", got.Status)
	}
	if got := matchOne(t, New("wsB", v), opensslComp(), opensslAdv(t)); got.Status != affected.StatusAffected {
		t.Fatalf("wsA scoped VEX must NOT suppress in wsB: got %q", got.Status)
	}

	// A global document (directly under root) suppresses in any workspace.
	writeVEX(t, root, "global.json", openvexDoc(
		"CVE-2022-0778", "pkg:deb/debian/openssl@3.0.5-1", "not_affected", "vulnerable_code_not_present"))
	if _, err := v.LoadDir(root); err != nil {
		t.Fatalf("LoadDir reload: %v", err)
	}
	if got := matchOne(t, New("wsB", v), opensslComp(), opensslAdv(t)); got.Status != affected.StatusNotAffected {
		t.Fatalf("global VEX must suppress in wsB: got %q", got.Status)
	}
}

// TestDocVEXMissingDir proves a missing root is not an error (no statements).
func TestDocVEXMissingDir(t *testing.T) {
	v := NewDocVEX()
	n, err := v.LoadDir(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil || n != 0 {
		t.Fatalf("missing dir: want (0,nil), got (%d,%v)", n, err)
	}
}
