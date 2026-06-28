package types

import "testing"

func TestVerifyDowngrade(t *testing.T) {
	shell := &SessionGrant{Action: ActionShell, AllowPTY: true}
	exec := &SessionGrant{Action: ActionExec, AllowPTY: false}
	fwd := &SessionGrant{Action: ActionForward, ForwardTarget: "10.0.0.5:5432"}

	cases := []struct {
		name  string
		grant *SessionGrant
		caps  *CapsPayload
		ok    bool
	}{
		{"full cut always ok", shell, &CapsPayload{Allow: false}, true},
		{"read-only downgrade ok", shell, &CapsPayload{Allow: true, AllowPTY: true, AllowInput: false, AllowNewChannels: true}, true},
		{"input on a pty shell ok", shell, &CapsPayload{Allow: true, AllowPTY: true, AllowInput: true, AllowNewChannels: true}, true},
		{"grant pty when withheld rejected", exec, &CapsPayload{Allow: true, AllowPTY: true}, false},
		{"grant input when withheld rejected", exec, &CapsPayload{Allow: true, AllowInput: true}, false},
		{"keep forward target ok", fwd, &CapsPayload{Allow: true, ForwardTargets: []string{"10.0.0.5:5432"}, AllowNewChannels: true}, true},
		{"remove forward target ok", fwd, &CapsPayload{Allow: true, ForwardTargets: nil, AllowNewChannels: true}, true},
		{"add new forward target rejected", fwd, &CapsPayload{Allow: true, ForwardTargets: []string{"10.0.0.9:22"}, AllowNewChannels: true}, false},
		{"sftp-write when not an sftp grant rejected", shell, &CapsPayload{Allow: true, AllowSFTPWrite: true}, false},
		{"nil caps rejected", shell, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyDowngrade(tc.grant, tc.caps)
			if tc.ok && err != nil {
				t.Fatalf("expected downgrade accepted, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("expected downgrade rejected, got nil")
			}
		})
	}
}
