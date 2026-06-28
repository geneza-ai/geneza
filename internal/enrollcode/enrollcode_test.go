package enrollcode

import "testing"

func TestRoundTrip(t *testing.T) {
	for _, in := range []Fields{
		{Token: "gz-deadbeef", RootFP: "sha256:abc123"},
		{Token: "gz-1", RootFP: "sha256:ff", HTTP: "https://geneza.example.com",
			Runtime: "https://geneza.example.com:7402", GRPC: "geneza.example.com:7401"},
	} {
		code := Encode(in)
		if code[:len(Prefix)] != Prefix {
			t.Fatalf("missing %q prefix: %q", Prefix, code)
		}
		out, ok := Decode(code)
		if !ok {
			t.Fatalf("decode failed: %q", code)
		}
		if out != in {
			t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
		}
	}
	if _, ok := Decode("gz-rawtoken"); ok {
		t.Fatal("decoded a non-gzk_ value")
	}
	if _, ok := Decode("gzk_!!!not-base64!!!"); ok {
		t.Fatal("decoded invalid base64")
	}
}
