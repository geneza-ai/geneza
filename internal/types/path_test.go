package types

import "testing"

// PathSupportsICE is the single source of truth for the session transport: the
// broker offers ICE iff it is true. Native hole-punches; the web-shell proxy uses
// the relay floor only; an unknown path defaults to the relay floor (always
// correct) rather than to an ICE offer its peer would wait out.
func TestPathSupportsICE(t *testing.T) {
	if !PathSupportsICE(PathNative) {
		t.Fatal("native client must support ICE")
	}
	if PathSupportsICE(PathWeb) {
		t.Fatal("web-shell proxy must NOT be offered ICE (relay floor only)")
	}
	for _, p := range []string{"", "desktop", "future-path"} {
		if PathSupportsICE(p) {
			t.Fatalf("unknown path %q must default to no ICE (whitelist)", p)
		}
	}
}
