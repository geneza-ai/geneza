package controller

import (
	"testing"

	"golang.org/x/crypto/bcrypt"

	"geneza.io/internal/policy"
)

func TestLocalLoginBcryptAndRoleMapping(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	ia := newIdentityAuth(&Config{
		LocalUsers: []LocalUser{
			{Username: "admin", PasswordBcrypt: string(hash), Groups: []string{"admins"}},
		},
	})

	user, groups, err := ia.authenticateLocal("admin", "hunter2")
	if err != nil {
		t.Fatalf("good password rejected: %v", err)
	}
	if user != "admin" || len(groups) != 1 || groups[0] != "admins" {
		t.Fatalf("identity wrong: %q %v", user, groups)
	}
	if _, _, err := ia.authenticateLocal("admin", "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, _, err := ia.authenticateLocal("ghost", "hunter2"); err == nil {
		t.Fatal("unknown user accepted")
	}

	// Group -> role mapping via the policy engine (the broker trusts roles
	// from the cert, so login is where this binding happens).
	engine, err := policy.Parse([]byte(testPolicyDoc))
	if err != nil {
		t.Fatal(err)
	}
	roles := engine.RolesFor(user, groups)
	if len(roles) != 1 || roles[0] != "ops" {
		t.Fatalf("RolesFor(%q, %v) = %v, want [ops]", user, groups, roles)
	}
	if got := engine.RolesFor("nobody", nil); len(got) != 0 {
		t.Fatalf("unbound user got roles: %v", got)
	}
}

func TestLocalLoginDisabled(t *testing.T) {
	ia := newIdentityAuth(&Config{})
	if _, _, err := ia.authenticateLocal("admin", "x"); err == nil {
		t.Fatal("local login must fail when no local_users configured")
	}
	if len(ia.local) != 0 {
		t.Fatal("identityAuth must have no local users")
	}
}
