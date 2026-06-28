package purl

import "testing"

func TestParseDistroPackages(t *testing.T) {
	cases := []struct {
		name       string
		purl       string
		wantName   string
		wantVer    string
		wantEco    string
		wantDistro string
	}{
		{
			name:       "ubuntu deb with distro qualifier",
			purl:       "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.16?arch=amd64&distro=ubuntu-22.04",
			wantName:   "openssl",
			wantVer:    "1.1.1f-1ubuntu2.16",
			wantEco:    "Ubuntu:22.04",
			wantDistro: "ubuntu:22.04",
		},
		{
			name:       "debian deb from namespace, distro release",
			purl:       "pkg:deb/debian/bash@5.2.15-2?distro=debian-12",
			wantName:   "bash",
			wantVer:    "5.2.15-2",
			wantEco:    "Debian:12",
			wantDistro: "debian:12",
		},
		{
			name:       "rhel rpm",
			purl:       "pkg:rpm/redhat/curl@7.76.1-26.el9?distro=rhel-9",
			wantName:   "curl",
			wantVer:    "7.76.1-26.el9",
			wantEco:    "Red Hat:9",
			wantDistro: "redhat:9",
		},
		{
			name:       "alpine apk",
			purl:       "pkg:apk/alpine/musl@1.2.4-r2?distro=alpine-3.18",
			wantName:   "musl",
			wantVer:    "1.2.4-r2",
			wantEco:    "Alpine:3.18",
			wantDistro: "alpine:3.18",
		},
		{
			name:       "deb without distro qualifier falls back to namespace vendor",
			purl:       "pkg:deb/ubuntu/zlib1g@1.2.11",
			wantName:   "zlib1g",
			wantVer:    "1.2.11",
			wantEco:    "Ubuntu",
			wantDistro: "ubuntu",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(tc.purl)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.purl, err)
			}
			if p.Name != tc.wantName {
				t.Errorf("name: got %q want %q", p.Name, tc.wantName)
			}
			if p.Version != tc.wantVer {
				t.Errorf("version: got %q want %q", p.Version, tc.wantVer)
			}
			if p.Ecosystem != tc.wantEco {
				t.Errorf("ecosystem: got %q want %q", p.Ecosystem, tc.wantEco)
			}
			if p.Distro != tc.wantDistro {
				t.Errorf("distro: got %q want %q", p.Distro, tc.wantDistro)
			}
		})
	}
}

func TestParseLanguagePackages(t *testing.T) {
	cases := []struct {
		purl    string
		name    string
		version string
		eco     string
	}{
		{"pkg:npm/ansi-regex@5.0.0", "ansi-regex", "5.0.0", "npm"},
		{"pkg:npm/%40scope/pkg@1.0.0", "pkg", "1.0.0", "npm"},
		{"pkg:pypi/django@4.2.1", "django", "4.2.1", "PyPI"},
		{"pkg:golang/github.com/foo/bar@1.2.3", "bar", "1.2.3", "Go"},
		{"pkg:cargo/serde@1.0.0", "serde", "1.0.0", "crates.io"},
	}
	for _, tc := range cases {
		p, err := Parse(tc.purl)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.purl, err)
		}
		if p.Name != tc.name || p.Version != tc.version || p.Ecosystem != tc.eco {
			t.Errorf("Parse(%q) = name=%q ver=%q eco=%q; want %q %q %q",
				tc.purl, p.Name, p.Version, p.Ecosystem, tc.name, tc.version, tc.eco)
		}
		if p.Distro != "" {
			t.Errorf("Parse(%q): language pkg should have no distro, got %q", tc.purl, p.Distro)
		}
	}
}

func TestParseNotAPurl(t *testing.T) {
	for _, s := range []string{"", "openssl", "deb/ubuntu/openssl", "pkg:no-slash"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q): want error", s)
		}
	}
}
