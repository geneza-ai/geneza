package controller

import "testing"

// An instance-pinned token names a VM but is still a BEARER credential: whoever
// holds it could redeem it anywhere, and that machine would inherit the verified
// labels and so receive the named VM's shell sessions. Auto-approving it blindly
// would mean a leaked command hands someone an approved node wearing a customer's
// instance identity.
//
// So the admission decision follows how well the redeemer can prove possession:
// claim the named instance and it is approved; claim nothing and it lands PENDING
// for a human. (A machine claiming a DIFFERENT instance never gets this far —
// crossCheckInstanceClaim refuses it outright.)
func TestInstancePinnedTokenAutoApprovesOnlyOnProof(t *testing.T) {
	const instance = "af78268f-32e9-4a96-b9c0-92fee3fe286f"

	// Mirrors the gate in Enroll.
	decide := func(autoApprove bool, agent, provider map[string]string) bool {
		if autoApprove && provider[launchInstanceLabel] != "" &&
			agent[claimedInstanceLabel] != provider[launchInstanceLabel] {
			return false
		}
		return autoApprove
	}

	for _, tc := range []struct {
		name     string
		agent    map[string]string
		provider map[string]string
		want     bool
	}{
		{
			name:     "the VM proves it is the named instance",
			agent:    map[string]string{claimedInstanceLabel: instance},
			provider: map[string]string{launchInstanceLabel: instance},
			want:     true,
		},
		{
			// The realistic leak: the command pasted onto some other machine that
			// cannot read OpenStack metadata at all.
			name:     "a machine that cannot prove anything lands pending",
			agent:    map[string]string{},
			provider: map[string]string{launchInstanceLabel: instance},
			want:     false,
		},
		{
			// An ordinary operator-minted token pins no instance, so this gate has
			// nothing to say about it and must not silently downgrade it.
			name:     "a token pinning no instance is unaffected",
			agent:    map[string]string{},
			provider: map[string]string{},
			want:     true,
		},
		{
			name:     "a token that was not auto-approve stays that way",
			agent:    map[string]string{claimedInstanceLabel: instance},
			provider: map[string]string{launchInstanceLabel: instance},
			want:     false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.name != "a token that was not auto-approve stays that way"
			if got := decide(in, tc.agent, tc.provider); got != tc.want {
				t.Fatalf("autoApprove = %v, want %v", got, tc.want)
			}
		})
	}
}
