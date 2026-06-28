//go:build linux

package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseOSRelease(t *testing.T) {
	const sample = `# a comment line
NAME="Ubuntu"
ID=ubuntu
ID_LIKE=debian
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04.4 LTS"

VERSION='22.04.4 LTS (Jammy Jellyfish)'
`
	dir := t.TempDir()
	p := filepath.Join(dir, "os-release")
	if err := os.WriteFile(p, []byte(sample), 0o644); err != nil {
		t.Fatal(err)
	}

	got, ok := parseOSRelease(p)
	if !ok {
		t.Fatal("parseOSRelease returned ok=false for valid file")
	}
	if got.Distro != "ubuntu" {
		t.Errorf("Distro = %q, want ubuntu", got.Distro)
	}
	if got.Version != "22.04" {
		t.Errorf("Version = %q, want 22.04 (quotes must be stripped)", got.Version)
	}
	if got.Pretty != "Ubuntu 22.04.4 LTS" {
		t.Errorf("Pretty = %q, want Ubuntu 22.04.4 LTS", got.Pretty)
	}
}

func TestParseOSReleaseMissing(t *testing.T) {
	if _, ok := parseOSRelease(filepath.Join(t.TempDir(), "nope")); ok {
		t.Error("parseOSRelease returned ok=true for a missing file")
	}
}

func TestParseOSReleaseNoID(t *testing.T) {
	// A file without an ID= key can't identify a distro and must be rejected so
	// Detect falls through to the next candidate path.
	dir := t.TempDir()
	p := filepath.Join(dir, "os-release")
	if err := os.WriteFile(p, []byte("NAME=\"Weird\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := parseOSRelease(p); ok {
		t.Error("parseOSRelease returned ok=true for a file with no ID=")
	}
}
