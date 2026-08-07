package controller

import "testing"

// console_launch.go documents os:instance / os:project as "the TRUSTED enrollment
// labels (vendordata.go stamps them from Nova's authoritative callback, not from
// anything the VM claimed)". resolveLaunchNode matches a hosted-UI launch to a node
// on exactly those two keys, so whoever controls them receives that VM's shells.
//
// On the TOKEN provider that claim does not hold: the enroll path copies the
// agent's self-asserted labels verbatim and lets provider labels overwrite only the
// keys the provider itself sets. A plain join token sets no os: labels, so the
// agent's survive — any holder of any join token for a workspace can dress their
// machine as any instance and collect its "Remote shell" clicks.
//
// The merge must therefore refuse agent-supplied keys in the reserved namespace
// rather than merely let a provider shadow them.
func TestEnrollRefusesAgentSuppliedReservedLabels(t *testing.T) {
	const victim = "af78268f-32e9-4a96-b9c0-92fee3fe286f"

	for _, tc := range []struct {
		name       string
		agent      map[string]string
		provider   map[string]string
		wantDinied []string // reserved keys that must NOT survive from the agent
	}{
		{
			name:       "agent forges both trusted labels under a plain token",
			agent:      map[string]string{"env": "prod", "os:instance": victim, "os:project": "victim-project"},
			provider:   map[string]string{},
			wantDinied: []string{"os:instance", "os:project"},
		},
		{
			name:       "agent forges the instance while the token pins only the project",
			agent:      map[string]string{"os:instance": victim},
			provider:   map[string]string{"os:project": "real-project"},
			wantDinied: []string{"os:instance"},
		},
		{
			name:       "os:cloud is reserved too — it selects the trust root",
			agent:      map[string]string{"os:cloud": "some-other-cloud"},
			provider:   map[string]string{},
			wantDinied: []string{"os:cloud"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeEnrollLabels(tc.agent, tc.provider)
			for _, k := range tc.wantDinied {
				if v, ok := got[k]; ok && v == tc.agent[k] {
					t.Errorf("agent-supplied %q survived as %q: a node can wear another VM's "+
						"identity and receive its launches", k, v)
				}
			}
			// Non-reserved agent labels are legitimate and must still come through.
			if tc.agent["env"] != "" && got["env"] != tc.agent["env"] {
				t.Errorf("dropped a legitimate agent label: env=%q", got["env"])
			}
			// Provider labels are authoritative and must always win.
			for k, v := range tc.provider {
				if got[k] != v {
					t.Errorf("provider label %q=%q lost (got %q)", k, v, got[k])
				}
			}
		})
	}
}
