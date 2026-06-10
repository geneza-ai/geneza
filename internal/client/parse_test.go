package client

import "testing"

func TestSplitRemote(t *testing.T) {
	cases := []struct {
		spec   string
		node   string
		path   string
		remote bool
	}{
		{"web1:/etc/hosts", "web1", "/etc/hosts", true},
		{"web1:relative/file", "web1", "relative/file", true},
		{"web1:", "web1", "", true},
		{"/tmp/local", "", "/tmp/local", false},
		{"./dir/file", "", "./dir/file", false},
		{"plainfile", "", "plainfile", false},
		// '/' before the first ':' means local path, not node.
		{"/tmp/odd:name", "", "/tmp/odd:name", false},
		{"./odd:name", "", "./odd:name", false},
		// Leading ':' has an empty node: local.
		{":/etc/hosts", "", ":/etc/hosts", false},
		{"node-1:file with spaces", "node-1", "file with spaces", true},
	}
	for _, tc := range cases {
		node, path, remote := SplitRemote(tc.spec)
		if node != tc.node || path != tc.path || remote != tc.remote {
			t.Errorf("SplitRemote(%q) = (%q,%q,%v), want (%q,%q,%v)",
				tc.spec, node, path, remote, tc.node, tc.path, tc.remote)
		}
	}
}

func TestParseForwardSpec(t *testing.T) {
	lp, target, err := ParseForwardSpec("8080:localhost:80")
	if err != nil {
		t.Fatal(err)
	}
	if lp != 8080 || target != "localhost:80" {
		t.Fatalf("got %d %q", lp, target)
	}

	lp, target, err = ParseForwardSpec("5432:[::1]:5432")
	if err != nil {
		t.Fatal(err)
	}
	if lp != 5432 || target != "[::1]:5432" {
		t.Fatalf("got %d %q", lp, target)
	}

	for _, bad := range []string{
		"", "8080", "notaport:host:80", "8080:host", "8080::80",
		"0:host:80", "70000:host:80", "8080:host:0", "8080:host:notaport",
	} {
		if _, _, err := ParseForwardSpec(bad); err == nil {
			t.Errorf("ParseForwardSpec(%q): expected error", bad)
		}
	}
}

func TestShellJoin(t *testing.T) {
	cases := []struct {
		argv []string
		want string
	}{
		{[]string{"ls", "-la"}, "ls -la"},
		{[]string{"echo", "hello world"}, "echo 'hello world'"},
		{[]string{"echo", "it's"}, `echo 'it'\''s'`},
		{[]string{"cat", "/etc/hosts"}, "cat /etc/hosts"},
		{[]string{"sh", "-c", "a && b"}, "sh -c 'a && b'"},
		{[]string{"echo", ""}, "echo ''"},
		{[]string{"grep", "$HOME"}, "grep '$HOME'"},
		{[]string{"tar", "-czf", "x.tgz", "dir name"}, "tar -czf x.tgz 'dir name'"},
	}
	for _, tc := range cases {
		if got := ShellJoin(tc.argv); got != tc.want {
			t.Errorf("ShellJoin(%q) = %q, want %q", tc.argv, got, tc.want)
		}
	}
}
