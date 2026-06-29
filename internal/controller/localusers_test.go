package controller

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadLocalUsersFile pins local_users_file: the controller reads credentials
// from a separate file (absolute or relative to the config dir) and appends them to
// any inline ones — the seam that lets an installer keep local_users in a write-once
// file instead of clobbering them in controller.yaml on every run.
func TestLoadLocalUsersFile(t *testing.T) {
	dir := t.TempDir()
	luf := filepath.Join(dir, "local_users.yml")
	body := "local_users:\n" +
		"  - username: admin\n" +
		"    password_bcrypt: \"$2a$10$abcdefghijklmnopqrstuv\"\n" +
		"    groups: [geneza-admins]\n"
	if err := os.WriteFile(luf, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// Absolute path, bcrypt with '$' preserved verbatim.
	c := &Config{LocalUsersFile: luf}
	if err := c.loadLocalUsersFile(dir); err != nil {
		t.Fatalf("absolute load: %v", err)
	}
	if len(c.LocalUsers) != 1 || c.LocalUsers[0].Username != "admin" ||
		c.LocalUsers[0].PasswordBcrypt != "$2a$10$abcdefghijklmnopqrstuv" {
		t.Fatalf("unexpected users: %+v", c.LocalUsers)
	}

	// Relative path resolves against the config dir.
	c2 := &Config{LocalUsersFile: "local_users.yml"}
	if err := c2.loadLocalUsersFile(dir); err != nil {
		t.Fatalf("relative load: %v", err)
	}
	if len(c2.LocalUsers) != 1 {
		t.Fatalf("relative path did not resolve: %+v", c2.LocalUsers)
	}

	// File entries append to inline ones.
	c3 := &Config{LocalUsers: []LocalUser{{Username: "ops"}}, LocalUsersFile: luf}
	if err := c3.loadLocalUsersFile(dir); err != nil {
		t.Fatal(err)
	}
	if len(c3.LocalUsers) != 2 {
		t.Fatalf("want inline+file = 2 users, got %d", len(c3.LocalUsers))
	}

	// A missing file is a clear error, not a silent empty merge.
	c4 := &Config{LocalUsersFile: filepath.Join(dir, "nope.yml")}
	if err := c4.loadLocalUsersFile(dir); err == nil {
		t.Fatal("expected an error for a missing local_users_file")
	}
}
