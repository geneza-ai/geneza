package controller

import "testing"

// The vendordata path mints a single-use token keyed to one instance and hands it
// to Nova, which delivers it into that one VM's metadata — so holding that token is
// evidence of BEING that VM. If the machine redeeming it reports a different
// instance, the token has moved somewhere it was not issued for.
//
// This only ever narrows. The trusted os:instance still comes solely from
// enrollment evidence; a claim can never create or change it.
func TestCrossCheckInstanceClaim(t *testing.T) {
	const (
		pinned = "af78268f-32e9-4a96-b9c0-92fee3fe286f"
		other  = "11111111-2222-3333-4444-555555555555"
	)
	for _, tc := range []struct {
		name     string
		agent    map[string]string
		provider map[string]string
		wantErr  bool
	}{
		{
			name:     "agreement passes",
			agent:    map[string]string{claimedInstanceLabel: pinned},
			provider: map[string]string{launchInstanceLabel: pinned},
		},
		{
			name:     "token redeemed on a different machine is refused",
			agent:    map[string]string{claimedInstanceLabel: other},
			provider: map[string]string{launchInstanceLabel: pinned},
			wantErr:  true,
		},
		// Silence on the absent cases is deliberate: requiring a claim would break
		// every bare-metal and non-OpenStack enrollment, and requiring a pin would
		// break every ordinary operator-minted token.
		{
			name:     "operator token pins no instance",
			agent:    map[string]string{claimedInstanceLabel: pinned},
			provider: map[string]string{},
		},
		{
			name:     "non-OpenStack machine claims nothing",
			agent:    map[string]string{},
			provider: map[string]string{launchInstanceLabel: pinned},
		},
		{
			name:     "neither side says anything",
			agent:    map[string]string{},
			provider: map[string]string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := crossCheckInstanceClaim(tc.agent, tc.provider)
			if tc.wantErr && err == nil {
				t.Fatal("a token minted for another instance was accepted: it can be moved to any machine")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
		})
	}
}

// The claim rides the untrusted namespace, so the reserved-label filter must let it
// through — otherwise the cross-check silently never fires and looks like it passes.
func TestClaimLabelSurvivesTheReservedFilter(t *testing.T) {
	got := mergeEnrollLabels(map[string]string{
		claimedInstanceLabel: "abc",
		launchInstanceLabel:  "forged",
	}, nil)
	if got[claimedInstanceLabel] != "abc" {
		t.Errorf("%s was dropped; the cross-check would never fire", claimedInstanceLabel)
	}
	if _, ok := got[launchInstanceLabel]; ok {
		t.Errorf("%s survived from the agent", launchInstanceLabel)
	}
}
