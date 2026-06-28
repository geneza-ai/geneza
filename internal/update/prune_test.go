package update

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrune(t *testing.T) {
	dir := t.TempDir()
	for _, v := range []string{"1.0.0", "1.1.0", "1.2.0"} {
		if err := os.MkdirAll(filepath.Join(dir, v), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, v, "geneza-agent"), []byte("bin"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Stray top-level file must survive pruning.
	stray := filepath.Join(dir, "README")
	if err := os.WriteFile(stray, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// keep includes an empty Previous slot — must be harmless.
	if err := Prune(dir, []string{"1.2.0", "1.1.0", ""}); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "1.0.0")); !os.IsNotExist(err) {
		t.Fatal("1.0.0 should have been pruned")
	}
	for _, want := range []string{"1.1.0", "1.2.0"} {
		if _, err := os.Stat(filepath.Join(dir, want, "geneza-agent")); err != nil {
			t.Fatalf("%s should have been kept: %v", want, err)
		}
	}
	if _, err := os.Stat(stray); err != nil {
		t.Fatalf("stray file should be untouched: %v", err)
	}
}

func TestPruneMissingDirIsNoop(t *testing.T) {
	if err := Prune(filepath.Join(t.TempDir(), "nope"), []string{"x"}); err != nil {
		t.Fatalf("Prune on missing dir: %v", err)
	}
}
