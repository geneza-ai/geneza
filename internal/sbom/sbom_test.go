package sbom

import (
	"testing"
)

// knownCycloneDX is a fixture CycloneDX JSON with a distro deb component carrying
// the geneza ecosystem/distro properties, a deb component WITHOUT properties (so
// the PURL-derivation fallback is exercised), and two language PURLs. It is the
// load-bearing bridge the controller's matcher is built on.
const knownCycloneDX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "openssl",
      "version": "1.1.1f-1ubuntu2.16",
      "purl": "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.16?distro=ubuntu-22.04",
      "properties": [
        {"name": "geneza:osv:ecosystem", "value": "Ubuntu:22.04"},
        {"name": "geneza:os:distro", "value": "ubuntu:22.04"},
        {"name": "geneza:source", "value": "os"}
      ]
    },
    {
      "type": "library",
      "name": "bash",
      "version": "5.1-6ubuntu1",
      "purl": "pkg:deb/ubuntu/bash@5.1-6ubuntu1?distro=ubuntu-22.04"
    },
    {
      "type": "library",
      "name": "ansi-regex",
      "version": "5.0.0",
      "purl": "pkg:npm/ansi-regex@5.0.0"
    },
    {
      "type": "library",
      "name": "django",
      "version": "4.2.1",
      "purl": "pkg:pypi/django@4.2.1"
    },
    {
      "type": "operating-system",
      "name": "ubuntu"
    }
  ]
}`

func TestExtractKnownCycloneDX(t *testing.T) {
	comps, err := Extract([]byte(knownCycloneDX))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	byName := map[string]Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	// The operating-system node has no PURL and must be dropped.
	if len(comps) != 4 {
		t.Fatalf("want 4 keyable components, got %d (%+v)", len(comps), comps)
	}

	// openssl: ecosystem/distro/source come from the explicit properties.
	ossl := byName["openssl"]
	if ossl.Ecosystem != "Ubuntu:22.04" || ossl.Version != "1.1.1f-1ubuntu2.16" || ossl.Distro != "ubuntu:22.04" {
		t.Errorf("openssl wrong: %+v", ossl)
	}
	if ossl.Source != "os" {
		t.Errorf("openssl source: got %q want os", ossl.Source)
	}
	if ossl.Purl != "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.16?distro=ubuntu-22.04" {
		t.Errorf("openssl purl: %q", ossl.Purl)
	}

	// bash: no geneza properties -> ecosystem/distro DERIVED from the PURL.
	bash := byName["bash"]
	if bash.Ecosystem != "Ubuntu:22.04" {
		t.Errorf("bash ecosystem (PURL-derived): got %q want Ubuntu:22.04", bash.Ecosystem)
	}
	if bash.Distro != "ubuntu:22.04" {
		t.Errorf("bash distro (PURL-derived): got %q want ubuntu:22.04", bash.Distro)
	}
	if bash.Version != "5.1-6ubuntu1" {
		t.Errorf("bash version: %q", bash.Version)
	}
	if bash.Source != "os" {
		t.Errorf("bash source default: got %q want os", bash.Source)
	}

	// language PURLs map to their OSV ecosystems and carry no distro.
	ansi := byName["ansi-regex"]
	if ansi.Ecosystem != "npm" || ansi.Version != "5.0.0" || ansi.Distro != "" {
		t.Errorf("ansi-regex wrong: %+v", ansi)
	}
	dj := byName["django"]
	if dj.Ecosystem != "PyPI" || dj.Version != "4.2.1" {
		t.Errorf("django wrong: %+v", dj)
	}
}

// TestEncodeExtractRoundTrip proves the agent's encode and the controller's extract
// agree on the wire shape: components in == components out, including the OSV
// ecosystem/distro/source the matcher needs.
func TestEncodeExtractRoundTrip(t *testing.T) {
	in := []Component{
		{Purl: "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.16", Name: "openssl", Version: "1.1.1f-1ubuntu2.16", Ecosystem: "Ubuntu:22.04", Distro: "ubuntu:22.04", Source: "os"},
		{Purl: "pkg:npm/ansi-regex@5.0.0", Name: "ansi-regex", Version: "5.0.0", Ecosystem: "npm", Source: "lang"},
	}
	doc, err := Encode("n1", in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out, err := Extract(doc)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("round trip count: got %d want %d", len(out), len(in))
	}
	byName := map[string]Component{}
	for _, c := range out {
		byName[c.Name] = c
	}
	ossl := byName["openssl"]
	if ossl.Ecosystem != "Ubuntu:22.04" || ossl.Distro != "ubuntu:22.04" || ossl.Source != "os" {
		t.Errorf("openssl round trip: %+v", ossl)
	}
	ansi := byName["ansi-regex"]
	if ansi.Ecosystem != "npm" || ansi.Source != "lang" {
		t.Errorf("ansi-regex round trip: %+v", ansi)
	}
}

// TestEncodeOrderIndependent proves the content hash is a function of the component
// SET, not the collector's emission order — the property the delta path relies on so
// the controller can re-derive the same hash from the set it reconstructs.
func TestEncodeOrderIndependent(t *testing.T) {
	a := []Component{
		{Purl: "pkg:npm/a@1.0.0", Name: "a", Version: "1.0.0", Ecosystem: "npm", Source: "lang"},
		{Purl: "pkg:npm/b@2.0.0", Name: "b", Version: "2.0.0", Ecosystem: "npm", Source: "lang"},
	}
	b := []Component{a[1], a[0]} // reversed
	da, err := Encode("n", a)
	if err != nil {
		t.Fatalf("encode a: %v", err)
	}
	db, err := Encode("n", b)
	if err != nil {
		t.Fatalf("encode b: %v", err)
	}
	if Hash(da) != Hash(db) {
		t.Fatal("encoding must be order-independent so the hash is set-defined")
	}
}

// TestDiffApplyRoundTrip proves Apply(base, Diff(base, next)) == next as a set,
// including a version bump (the same purl at a new version) and a source-distinct
// member (the same purl from two origins is two members).
func TestDiffApplyRoundTrip(t *testing.T) {
	base := []Component{
		{Purl: "pkg:npm/keep@1.0.0", Name: "keep", Version: "1.0.0", Ecosystem: "npm", Source: "lang"},
		{Purl: "pkg:npm/bump@1.0.0", Name: "bump", Version: "1.0.0", Ecosystem: "npm", Source: "lang"},
		{Purl: "pkg:npm/gone@1.0.0", Name: "gone", Version: "1.0.0", Ecosystem: "npm", Source: "lang"},
		{Purl: "pkg:generic/dup@1", Name: "dup", Version: "1", Ecosystem: "generic", Source: "os"},
	}
	next := []Component{
		base[0], // keep unchanged
		{Purl: "pkg:npm/bump@2.0.0", Name: "bump", Version: "2.0.0", Ecosystem: "npm", Source: "lang"}, // version bump
		{Purl: "pkg:npm/new@1.0.0", Name: "new", Version: "1.0.0", Ecosystem: "npm", Source: "lang"},   // added
		base[3], // same purl/source kept
		{Purl: "pkg:generic/dup@1", Name: "dup", Version: "1", Ecosystem: "generic", Source: "lang"}, // same purl, DIFFERENT source -> distinct member
	}
	added, removed := Diff(base, next)
	got := Apply(base, added, removed)
	if Hash(mustEncode(t, got)) != Hash(mustEncode(t, next)) {
		t.Fatalf("Apply(base, Diff(base,next)) != next\n got=%+v\nwant=%+v", got, next)
	}
	// The version bump rides as both a removal (old) and an addition (new).
	if !containsPurlVer(added, "pkg:npm/bump@2.0.0", "2.0.0") || !containsPurlVer(removed, "pkg:npm/bump@1.0.0", "1.0.0") {
		t.Errorf("version bump must appear in both added and removed: added=%+v removed=%+v", added, removed)
	}
}

func mustEncode(t *testing.T, comps []Component) []byte {
	t.Helper()
	doc, err := Encode("n", comps)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return doc
}

func containsPurlVer(cs []Component, purl, ver string) bool {
	for _, c := range cs {
		if c.Purl == purl && c.Version == ver {
			return true
		}
	}
	return false
}

// TestCompressHashRoundTrip proves the transport encoding is lossless and the hash
// is stable over the canonical (uncompressed) document.
func TestCompressHashRoundTrip(t *testing.T) {
	doc, err := Encode("n1", []Component{{Purl: "pkg:npm/x@1.0.0", Name: "x", Version: "1.0.0", Ecosystem: "npm"}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	h1 := Hash(doc)
	blob, err := Compress(doc)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}
	back, err := Decompress(blob)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if string(back) != string(doc) {
		t.Fatal("decompress did not recover the document")
	}
	if Hash(back) != h1 {
		t.Fatal("hash not stable across compress round trip")
	}
}

// TestExtractClampsNewerSpecVersion proves a document declaring a spec version
// newer than the bundled decoder supports (e.g. a scanner that has moved to 1.7)
// is still read for its stable component fields rather than rejected outright.
func TestExtractClampsNewerSpecVersion(t *testing.T) {
	doc := `{
		"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
		"components": [
			{"type": "library", "name": "next", "version": "14.1.0", "purl": "pkg:npm/next@14.1.0"}
		]
	}`
	comps, err := Extract([]byte(doc))
	if err != nil {
		t.Fatalf("Extract on spec 1.7: %v", err)
	}
	if len(comps) != 1 || comps[0].Purl != "pkg:npm/next@14.1.0" {
		t.Fatalf("want next@14.1.0 from a 1.7 doc, got %+v", comps)
	}
}
