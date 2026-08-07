package controller

import (
	"path/filepath"
	"testing"
)

// Agents pin the release root and refuse every update until the controller serves
// them the signing SET that root authorizes — the failure reads "node pins a root
// key but the controller served no root-keys doc", and the node then sits on its
// installed version forever. The agent pull already mirrors the verified doc into
// InstallDir, so the controller should serve it without the operator wiring a path
// by hand; leaving it unset silently disables fleet self-update.
func TestRootKeysFileDefaultsToTheMirroredPull(t *testing.T) {
	for _, tc := range []struct {
		name       string
		installDir string
		pull       bool
		configured string
		want       string
	}{
		{"defaults into install_dir when pulling", "/var/lib/geneza/install", true, "", "/var/lib/geneza/install/root-keys.json"},
		{"an explicit path always wins", "/var/lib/geneza/install", true, "/etc/geneza/mine.json", "/etc/geneza/mine.json"},
		// Nothing mirrors the doc when the pull is off, so pointing at a path that
		// will never exist would only make loadSignedRootKeys fail on every request.
		{"no default without the pull", "/var/lib/geneza/install", false, "", ""},
		{"no default without an install_dir", "", true, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{InstallDir: tc.installDir, RootKeysFile: tc.configured}
			c.AgentRelease.Pull = tc.pull
			c.applyRootKeysDefault()
			if c.RootKeysFile != tc.want {
				t.Fatalf("RootKeysFile = %q, want %q", c.RootKeysFile, tc.want)
			}
		})
	}
}

// The default is only worth anything if applyDefaults actually runs it — a config
// loaded normally must come out with the path set, not just a directly-called helper.
func TestApplyDefaultsWiresTheRootKeysDefault(t *testing.T) {
	c := &Config{InstallDir: "/var/lib/geneza/install"}
	c.AgentRelease.Pull = true
	c.applyDefaults()
	if want := filepath.Join("/var/lib/geneza/install", rootKeysFile); c.RootKeysFile != want {
		t.Fatalf("applyDefaults left RootKeysFile = %q, want %q — the default is not wired in, "+
			"so every deployment silently serves no root-keys doc and self-update never runs",
			c.RootKeysFile, want)
	}
}

// The mirrored path must be the one the pull actually writes, or the default points
// at a file that never appears.
func TestRootKeysDefaultMatchesThePullPath(t *testing.T) {
	c := &Config{InstallDir: "/srv/install"}
	c.AgentRelease.Pull = true
	c.applyRootKeysDefault()
	if got, want := c.RootKeysFile, filepath.Join("/srv/install", rootKeysFile); got != want {
		t.Fatalf("default %q does not match the pull's write path %q", got, want)
	}
}
