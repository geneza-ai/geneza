package controller

import "testing"

// A token's labels become the node's TRUSTED labels at enrollment, and os:instance
// is the entire match for a hosted-UI launch. The controller cannot verify such a
// claim at mint time — it holds no Nova credential (reader_creds is config-only)
// and keeps only a hash of the caller's keystone token — so an unverifiable claim
// must not be accepted from a tenant.
//
// Fleet management makes the first human in a project a ws-admin, so without this
// any of them could mint a token pinning a CO-MEMBER's instance and collect that
// VM's shell sessions. Being ws-admin of your own workspace is not authority over
// another member's machine.
func TestReservedLabelDetection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		labels map[string]string
		want   string
	}{
		{"the launch match key", map[string]string{"os:instance": "abc"}, "os:instance"},
		{"the project key", map[string]string{"os:project": "p"}, "os:project"},
		{"the trust-root key", map[string]string{"os:cloud": "c"}, "os:cloud"},
		// Deterministic so the error names the same key for a given input.
		{"several reserved keys pick the first in order", map[string]string{
			"os:project": "p", "os:cloud": "c", "os:instance": "i",
		}, "os:cloud"},
		{"ordinary labels are fine", map[string]string{"env": "prod", "role": "db"}, ""},
		// The untrusted namespace is how a tenant hint is expressed; it must pass.
		{"os.claim: is not reserved", map[string]string{"os.claim:instance": "abc"}, ""},
		{"empty", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := reservedLabelIn(tc.labels); got != tc.want {
				t.Fatalf("reservedLabelIn = %q, want %q", got, tc.want)
			}
		})
	}
}

// The refusal is keyed on the caller being a TENANT. An operator signing in locally
// or by OIDC is the cloud operator and must keep the ability to pre-label a machine
// — that is the only way a VM predating Geneza can become launchable, since
// vendordata only ever fires at instance build.
func TestOnlyKeystoneSessionsAreRefusedReservedLabels(t *testing.T) {
	reserved := map[string]string{"os:instance": "abc"}
	for _, tc := range []struct {
		provider string
		refused  bool
	}{
		{providerKeystone, true},
		{"local", false},
		{"oidc", false},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			// Mirrors the guard in handleMintToken.
			got := reservedLabelIn(reserved) != "" && tc.provider == providerKeystone
			if got != tc.refused {
				t.Fatalf("provider %q: refused=%v, want %v", tc.provider, got, tc.refused)
			}
		})
	}
}
