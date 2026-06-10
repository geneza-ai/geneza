package client

import (
	"bytes"
	"testing"
)

// feedAll feeds p one chunk at a time and returns concatenated forwards plus
// the first action seen.
func feedAll(d *EscapeDetector, chunks ...[]byte) ([]byte, EscapeAction) {
	var out bytes.Buffer
	for _, c := range chunks {
		f, a := d.Feed(c)
		out.Write(f)
		if a != EscNone {
			return out.Bytes(), a
		}
	}
	return out.Bytes(), EscNone
}

func TestEscapeDetachAtStart(t *testing.T) {
	var d EscapeDetector
	fwd, act := feedAll(&d, []byte("~d"))
	if act != EscDetach {
		t.Fatalf("act = %v, want detach", act)
	}
	if len(fwd) != 0 {
		t.Fatalf("forwarded %q, want nothing", fwd)
	}
}

func TestEscapeCloseAfterNewline(t *testing.T) {
	var d EscapeDetector
	fwd, act := feedAll(&d, []byte("ls\r~."))
	if act != EscClose {
		t.Fatalf("act = %v, want close", act)
	}
	if string(fwd) != "ls\r" {
		t.Fatalf("forwarded %q, want %q", fwd, "ls\r")
	}
}

// The critical property: bytes split across reads must behave identically.
func TestEscapeSplitAcrossReads(t *testing.T) {
	cases := []struct {
		name   string
		chunks []string
		fwd    string
		act    EscapeAction
	}{
		{"tilde-then-d", []string{"~", "d"}, "", EscDetach},
		{"newline-tilde-dot-split", []string{"echo hi\r", "~", "."}, "echo hi\r", EscClose},
		{"split-mid-word", []string{"a", "~", "d"}, "a~d", EscNone},
		{"tilde-tilde-split", []string{"~", "~"}, "~", EscNone},
		{"tilde-then-other", []string{"~", "x"}, "~x", EscNone},
		{"lf-line-start", []string{"abc\n", "~", "d"}, "abc\n", EscDetach},
		{"one-byte-at-a-time", []string{"l", "s", "\r", "~", "d"}, "ls\r", EscDetach},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var d EscapeDetector
			chunks := make([][]byte, len(tc.chunks))
			for i, c := range tc.chunks {
				chunks[i] = []byte(c)
			}
			fwd, act := feedAll(&d, chunks...)
			if act != tc.act {
				t.Fatalf("act = %v, want %v", act, tc.act)
			}
			if string(fwd) != tc.fwd {
				t.Fatalf("forwarded %q, want %q", fwd, tc.fwd)
			}
		})
	}
}

func TestEscapeLiteralTildeMidLine(t *testing.T) {
	var d EscapeDetector
	fwd, act := feedAll(&d, []byte("a~d~.b"))
	if act != EscNone {
		t.Fatalf("act = %v, want none", act)
	}
	if string(fwd) != "a~d~.b" {
		t.Fatalf("forwarded %q", fwd)
	}
}

func TestEscapeDoubleTildeSendsOne(t *testing.T) {
	var d EscapeDetector
	fwd, act := feedAll(&d, []byte("~~d"))
	if act != EscNone {
		t.Fatalf("act = %v, want none", act)
	}
	if string(fwd) != "~d" {
		t.Fatalf("forwarded %q, want %q", fwd, "~d")
	}
}

func TestEscapeTildeNewlineReleased(t *testing.T) {
	var d EscapeDetector
	// '~' followed by Enter: the tilde plus newline are forwarded and the
	// next '~d' is again a valid escape (newline resets line start).
	fwd, act := feedAll(&d, []byte("~\r"), []byte("~d"))
	if act != EscDetach {
		t.Fatalf("act = %v, want detach", act)
	}
	if string(fwd) != "~\r" {
		t.Fatalf("forwarded %q, want %q", fwd, "~\r")
	}
}

func TestEscapeStatePersistsAcrossActions(t *testing.T) {
	var d EscapeDetector
	_, act := d.Feed([]byte("~d"))
	if act != EscDetach {
		t.Fatal("first detach not detected")
	}
	// Detector remains usable (e.g. detach refused on non-detachable session).
	fwd, act := d.Feed([]byte("ok"))
	if act != EscNone || string(fwd) != "ok" {
		t.Fatalf("after action: fwd=%q act=%v", fwd, act)
	}
}
