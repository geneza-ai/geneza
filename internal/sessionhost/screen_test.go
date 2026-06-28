package sessionhost

import (
	"strings"
	"testing"

	"github.com/hinshun/vt10x"
)

func TestRenderSnapshotBasicColors(t *testing.T) {
	term := vt10x.New(vt10x.WithSize(20, 5))
	if _, err := term.Write([]byte("\x1b[1;31mRED\x1b[0m ok")); err != nil {
		t.Fatal(err)
	}
	snap := string(renderSnapshot(term))

	for _, want := range []string{
		"\x1b[2J", // clear
		"\x1b[H",  // home
		// vt10x brightens bold ANSI colors when storing the cell (red 1 ->
		// light red 9), which we repaint via 38;5: still bold red.
		"\x1b[0;1;38;5;9mRED",
		"\x1b[0m ok", // attrs reset for the default-attr run
		"\x1b[1;7H",  // cursor parked after "RED ok"
		"\x1b[?25h",  // cursor visible
	} {
		if !strings.Contains(snap, want) {
			t.Errorf("snapshot missing %q in %q", want, snap)
		}
	}
}

func TestRenderSnapshot256ColorsAndHiddenCursor(t *testing.T) {
	term := vt10x.New(vt10x.WithSize(20, 5))
	if _, err := term.Write([]byte("\x1b[38;5;200mP\x1b[48;5;100mQ\x1b[?25l")); err != nil {
		t.Fatal(err)
	}
	snap := string(renderSnapshot(term))
	for _, want := range []string{
		"\x1b[0;38;5;200mP",          // 256-color fg via 38;5
		"\x1b[0;38;5;200;48;5;100mQ", // fg+bg run
		"\x1b[?25l",                  // hidden cursor preserved
	} {
		if !strings.Contains(snap, want) {
			t.Errorf("snapshot missing %q in %q", want, snap)
		}
	}
}
