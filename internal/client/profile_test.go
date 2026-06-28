package client

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func testStore(t *testing.T, profile string) *Store {
	t.Helper()
	t.Setenv("GENEZA_HOME", t.TempDir())
	st, err := NewStore(profile)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestProfileRoundTrip(t *testing.T) {
	st := testStore(t, "default")
	want := &Profile{
		ControllerGRPC: "gw.example:7401",
		ControllerHTTP: "https://gw.example:7402",
		User:        "alice",
		Provider:    "oidc",
		CASHA256:    "abc123",
	}
	if err := st.SaveProfile(want); err != nil {
		t.Fatal(err)
	}
	got, err := st.LoadProfile()
	if err != nil {
		t.Fatal(err)
	}
	if *got != *want {
		t.Fatalf("round trip: got %+v, want %+v", got, want)
	}
	// profile.json may carry credentials-adjacent data: must be 0600.
	fi, err := os.Stat(st.ProfilePath())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("profile.json mode = %o, want 0600", fi.Mode().Perm())
	}
}

func TestLoadProfileMissing(t *testing.T) {
	st := testStore(t, "default")
	if _, err := st.LoadProfile(); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("err = %v, want ErrNoProfile", err)
	}
}

func TestStoreRejectsPathEscape(t *testing.T) {
	t.Setenv("GENEZA_HOME", t.TempDir())
	for _, bad := range []string{"../evil", "a/b", ".", ".."} {
		if _, err := NewStore(bad); err == nil {
			t.Errorf("NewStore(%q): expected error", bad)
		}
	}
}

func TestCAPinning(t *testing.T) {
	st := testStore(t, "default")
	pemBytes := []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
	pin, err := st.SaveCA(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if pin != CAFingerprint(pemBytes) {
		t.Fatal("SaveCA pin mismatch")
	}
	if _, err := st.LoadCA(pin); err != nil {
		t.Fatalf("LoadCA with correct pin: %v", err)
	}
	// A swapped bundle must fail closed.
	if err := os.WriteFile(filepath.Join(st.Dir(), "ca.pem"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := st.LoadCA(pin); err == nil {
		t.Fatal("LoadCA accepted a tampered bundle")
	}
	// Empty pin (pre-pin bootstrap) skips the check.
	if _, err := st.LoadCA(""); err != nil {
		t.Fatalf("LoadCA without pin: %v", err)
	}
}
