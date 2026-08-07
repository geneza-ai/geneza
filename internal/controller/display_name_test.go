package controller

import "testing"

// A portal that provisions Keystone users per customer commonly names them by its
// own subject id — Cloudify uses the Keycloak sub — so the username is a UUID that
// identifies nobody. The console, the member list and every audit row would show
// that. Prefer the address when Keystone has one.
//
// Display only: authorization is keyed on UserID, and the service-account guards
// match on UserName, so neither moves with this.
func TestCallerDisplayNamePrefersEmail(t *testing.T) {
	for _, tc := range []struct {
		name  string
		email string
		user  string
		want  string
	}{
		{"a uuid username is replaced by the address", "ana@example.com",
			"210e50db-7628-478a-966a-2e2440733fe4", "ana@example.com"},
		// Keystone need not hold one, and a deployment may refuse to share it.
		{"no email falls back to the username", "", "alice", "alice"},
		// A service account has no address; the name is what identifies it, and the
		// denylist matches on that same string.
		{"service accounts keep their name", "", "nova", "nova"},
		{"neither", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := osCaller{Email: tc.email, UserName: tc.user}
			if got := c.displayName(); got != tc.want {
				t.Fatalf("displayName() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The guards must keep reading UserName: an address is not what "is this nova?" is
// asking, and swapping it would let a service account past by having an email set.
func TestServiceGuardStillMatchesTheUsername(t *testing.T) {
	cl := CloudConfig{}
	caller := osCaller{
		UserName: "nova", Email: "ops@example.com",
		ProjectName: "service", ScopeProject: true, ProjectID: "p",
	}
	if err := validateHumanKeystoneToken(caller, cl); err == nil {
		t.Fatal("a service account with an email address was admitted to the access plane")
	}
}
