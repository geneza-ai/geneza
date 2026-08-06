package types

import (
	"encoding/hex"
	"testing"
)

// The digest is computed in TWO languages: here, and again in the browser by
// manifestPreimage() in web/apps/console/src/lib/recording.ts, which re-verifies
// the node's signature for the auditor. A change to the field order, the domain
// tag or the length-prefix framing on either side silently breaks every
// verification — it does not error, it just returns "signature invalid" forever.
//
// So this pins the wire format to a fixed vector. If it fails, the browser mirror
// has to change with it (and old recordings become unverifiable, which is a
// deliberate decision, not a refactor).
func TestRecordingManifestDigestIsAPinnedWireFormat(t *testing.T) {
	got := hex.EncodeToString(RecordingManifestDigest(
		"sess-abc123",
		"9f2c1d4e5b6a7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708",
		4242,
		1770000000,
	))
	const want = "7ca45ebdb5fcc6d4deb7e0fa89f5d0d8076c2a73f2290766a3a545aad8131496"
	if got != want {
		t.Fatalf("manifest digest format changed:\n got  %s\n want %s\n"+
			"update manifestPreimage() in web/apps/console/src/lib/recording.ts to match, "+
			"or recordings signed under the old format can no longer be verified", got, want)
	}
}

// Each field must actually bind: a signature minted for one cast must not carry
// over to a different blob, a resized truncation, or a replay.
func TestRecordingManifestDigestBindsEveryField(t *testing.T) {
	base := RecordingManifestDigest("s", "aa", 1, 2)
	cases := []struct {
		name   string
		digest []byte
	}{
		{"session", RecordingManifestDigest("s2", "aa", 1, 2)},
		{"sha256", RecordingManifestDigest("s", "ab", 1, 2)},
		{"size", RecordingManifestDigest("s", "aa", 2, 2)},
		{"finished", RecordingManifestDigest("s", "aa", 1, 3)},
	}
	for _, c := range cases {
		if string(c.digest) == string(base) {
			t.Errorf("%s does not affect the digest, so a signature transfers across it", c.name)
		}
	}
	// Length-prefixing must stop a field boundary from sliding: ("ab","c") and
	// ("a","bc") are different manifests and must not collide.
	if string(RecordingManifestDigest("ab", "c", 1, 2)) == string(RecordingManifestDigest("a", "bc", 1, 2)) {
		t.Error("field boundaries are not framed; distinct manifests collide")
	}
}
