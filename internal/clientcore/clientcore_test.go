package clientcore

import (
	"testing"
)

// TestOpenNoProfile: Open against an empty home returns a clear error rather
// than dialing or panicking (the no-profile / not-logged-in path).
func TestOpenNoProfile(t *testing.T) {
	t.Setenv("GENEZA_HOME", t.TempDir())
	if _, err := Open("default"); err == nil {
		t.Fatal("expected an error opening a client with no profile, got nil")
	}
}

// TestOpenDefaultsProfile: an empty profile name is treated as "default" (no
// panic, same no-profile error path).
func TestOpenDefaultsProfile(t *testing.T) {
	t.Setenv("GENEZA_HOME", t.TempDir())
	if _, err := Open(""); err == nil {
		t.Fatal("expected an error opening the default profile with no profile present")
	}
}
