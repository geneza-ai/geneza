package update

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	// Missing file is a fresh node, not an error.
	st, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState(missing): %v", err)
	}
	if st.Current != "" || st.Previous != "" || len(st.Bad) != 0 {
		t.Fatalf("expected empty state, got %+v", st)
	}

	st.Current = "0.2.0"
	st.Previous = "0.1.0"
	st.MarkBad("0.1.9")
	if err := st.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Atomic write must not leave the temp file behind.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file left behind after Save")
	}

	got, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if got.Current != "0.2.0" || got.Previous != "0.1.0" || !got.IsBad("0.1.9") {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestStateCorruptFileIsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(path); err == nil {
		t.Fatal("expected error for corrupt state file")
	}
}

func TestMarkBadDedup(t *testing.T) {
	st := &State{}
	st.MarkBad("v2")
	st.MarkBad("v2")
	if len(st.Bad) != 1 {
		t.Fatalf("expected 1 bad entry, got %v", st.Bad)
	}
	if st.IsBad("v3") {
		t.Fatal("v3 should not be bad")
	}
}

func TestResetBadOnChange(t *testing.T) {
	cases := []struct {
		name                 string
		bad                  []string
		desired, lastDesired string
		wantReset            bool
	}{
		{"first observation never resets", []string{"v2"}, "v3", "", false},
		{"unchanged desired keeps bad", []string{"v2"}, "v2", "v2", false},
		{"changed desired resets", []string{"v2"}, "v3", "v2", true},
		{"changed back to current also resets", []string{"v2"}, "v1", "v2", true},
		{"empty bad list is a no-op", nil, "v3", "v2", false},
	}
	for _, tc := range cases {
		st := &State{Bad: tc.bad}
		got := st.ResetBadOnChange(tc.desired, tc.lastDesired)
		if got != tc.wantReset {
			t.Errorf("%s: ResetBadOnChange(%q,%q)=%v want %v", tc.name, tc.desired, tc.lastDesired, got, tc.wantReset)
		}
		if tc.wantReset && len(st.Bad) != 0 {
			t.Errorf("%s: bad list not cleared: %v", tc.name, st.Bad)
		}
		if !tc.wantReset && len(st.Bad) != len(tc.bad) {
			t.Errorf("%s: bad list changed unexpectedly: %v", tc.name, st.Bad)
		}
	}
}

// TestBadVersionSkipFlow exercises the skip+reset sequence the bootstrap's
// reconcile loop performs, as pure state transitions.
func TestBadVersionSkipFlow(t *testing.T) {
	st := &State{Current: "v1"}
	lastDesired := ""

	// v2 desired, fails its health gate.
	st.ResetBadOnChange("v2", lastDesired)
	lastDesired = "v2"
	st.MarkBad("v2")

	// v2 still desired: must be skipped, no reset.
	if st.ResetBadOnChange("v2", lastDesired) {
		t.Fatal("unchanged desired must not reset")
	}
	if !st.IsBad("v2") {
		t.Fatal("v2 must remain bad while desired is unchanged")
	}

	// Operator moves desired to v3: v2's failure is forgiven.
	if !st.ResetBadOnChange("v3", lastDesired) {
		t.Fatal("changed desired must reset bad list")
	}
	lastDesired = "v3"
	if st.IsBad("v2") {
		t.Fatal("bad list should be clear after desired changed")
	}

	// Operator flips back to v2: retry is allowed.
	if st.IsBad("v2") {
		t.Fatal("v2 must be retryable after the desired version moved")
	}
}
