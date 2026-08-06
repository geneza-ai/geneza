package affected

import "testing"

// The ecosystem strings below are the REAL ones, taken from api.osv.dev and from
// osv-scalibr's extractors — not invented. Every fixture in this repo used to
// hand-write "Ubuntu:22.04" on the advisory side, a string OSV does not publish,
// which is exactly why the OS-package matcher passed its tests and matched nothing
// in production.
func TestEcosystemKeyJoinsTheTwoSidesOfTheRealFeed(t *testing.T) {
	for _, tc := range []struct {
		name      string
		advisory  string // as published by OSV
		component string // as emitted by osv-scalibr on the node
		wantKey   string
	}{
		{"ubuntu LTS", "Ubuntu:22.04:LTS", "Ubuntu:22.04", "Ubuntu:22.04"},
		{"ubuntu pro", "Ubuntu:Pro:22.04:LTS", "Ubuntu:22.04", "Ubuntu:22.04"},
		{"ubuntu fips", "Ubuntu:Pro:FIPS-updates:22.04:LTS", "Ubuntu:22.04", "Ubuntu:22.04"},
		{"debian", "Debian:12", "Debian:12", "Debian:12"},
		{"alpine", "Alpine:v3.19", "Alpine:v3.19", "Alpine:v3.19"},
		{
			"red hat across repos",
			"Red Hat:enterprise_linux:9::appstream",
			"Red Hat:enterprise_linux:9::baseos",
			"Red Hat:9",
		},
		{"language ecosystem", "npm", "npm", "npm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ak, ck := EcosystemKey(tc.advisory), EcosystemKey(tc.component)
			if ak != tc.wantKey || ck != tc.wantKey {
				t.Fatalf("keys must collide so one indexed lookup finds the advisory: advisory %q -> %q, component %q -> %q, want %q",
					tc.advisory, ak, tc.component, ck, tc.wantKey)
			}
		})
	}
}

// Collapsing to a shared key is only half the job: the precise test must then keep
// a variant-scoped advisory off a host that is not that variant. Getting this wrong
// turns silent false negatives into silent false positives.
func TestEcosystemApplies(t *testing.T) {
	for _, tc := range []struct {
		name      string
		advisory  string
		component string
		want      bool
	}{
		{"same release", "Ubuntu:22.04:LTS", "Ubuntu:22.04", true},
		{"different release", "Ubuntu:20.04:LTS", "Ubuntu:22.04", false},
		{"pro advisory on a plain host", "Ubuntu:Pro:22.04:LTS", "Ubuntu:22.04", false},
		{"fips advisory on a plain host", "Ubuntu:Pro:FIPS-updates:22.04:LTS", "Ubuntu:22.04", false},
		{"different family", "Debian:12", "Ubuntu:22.04", false},
		{"debian exact", "Debian:12", "Debian:12", true},
		{"debian other release", "Debian:11", "Debian:12", false},
		{"alpine exact", "Alpine:v3.19", "Alpine:v3.19", true},
		{
			"red hat: the repo an advisory was filed under does not scope the host",
			"Red Hat:enterprise_linux:9::appstream", "Red Hat:enterprise_linux:9::baseos", true,
		},
		{
			"red hat: a different major release does not apply",
			"Red Hat:enterprise_linux:8::baseos", "Red Hat:enterprise_linux:9::baseos", false,
		},
		{"language ecosystem", "npm", "npm", true},
		{"language mismatch", "PyPI", "npm", false},
		{"unscoped advisory applies across releases", "Ubuntu", "Ubuntu:22.04", true},
		{"empty advisory ecosystem inherits the component's", "", "Ubuntu:22.04", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := EcosystemApplies(tc.advisory, tc.component); got != tc.want {
				t.Fatalf("EcosystemApplies(%q, %q) = %v, want %v", tc.advisory, tc.component, got, tc.want)
			}
		})
	}
}

func TestParseEcosystem(t *testing.T) {
	for _, tc := range []struct {
		in       string
		family   string
		variants []string
		release  string
	}{
		{"Ubuntu:22.04:LTS", "Ubuntu", nil, "22.04"},
		{"Ubuntu:Pro:FIPS-updates:22.04:LTS", "Ubuntu", []string{"Pro", "FIPS-updates"}, "22.04"},
		{"Red Hat:enterprise_linux:9::baseos", "Red Hat", []string{"enterprise_linux"}, "9"},
		{"Alpine:v3.19", "Alpine", nil, "v3.19"},
		{"npm", "npm", nil, ""},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got := ParseEcosystem(tc.in)
			if got.Family != tc.family || got.Release != tc.release {
				t.Fatalf("ParseEcosystem(%q) = %+v, want family %q release %q", tc.in, got, tc.family, tc.release)
			}
			if len(got.Variants) != len(tc.variants) {
				t.Fatalf("variants = %v, want %v", got.Variants, tc.variants)
			}
			for i := range tc.variants {
				if got.Variants[i] != tc.variants[i] {
					t.Fatalf("variants = %v, want %v", got.Variants, tc.variants)
				}
			}
		})
	}
}
