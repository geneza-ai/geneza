package vpn

import (
	"testing"

	"github.com/pion/ice/v4"
)

// TestParseEndpointRoundtrip: DstToString <-> ParseEndpoint round-trips the
// gz:<hex> peer-identity token, and non-gz endpoints are rejected.
func TestParseEndpointRoundtrip(t *testing.T) {
	b := NewICEBind(1, true, nil)
	var pub [32]byte
	pub[0], pub[31] = 0x12, 0x34
	orig := &genezaEndpoint{wgPub: pub}
	ep, err := b.ParseEndpoint(orig.DstToString())
	if err != nil {
		t.Fatal(err)
	}
	if ge := ep.(*genezaEndpoint); ge.wgPub != pub {
		t.Fatalf("round-trip mismatch: %x", ge.wgPub)
	}
	if _, err := b.ParseEndpoint("1.2.3.4:51820"); err == nil {
		t.Fatal("expected non-gz endpoint to be rejected")
	}
}

// TestCandidateMarshalRoundtrip verifies that every ICE candidate type we signal
// over the control stream survives Marshal -> UnmarshalCandidate intact —
// especially the RELAY candidate, which carries a related address (raddr/rport)
// that the proto path must not silently drop.
func TestCandidateMarshalRoundtrip(t *testing.T) {
	host, err := ice.NewCandidateHost(&ice.CandidateHostConfig{
		Network: "udp", Address: "10.70.70.21", Port: 51820, Component: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	srflx, err := ice.NewCandidateServerReflexive(&ice.CandidateServerReflexiveConfig{
		Network: "udp", Address: "203.0.113.7", Port: 55000, Component: 1,
		RelAddr: "10.70.70.21", RelPort: 51820,
	})
	if err != nil {
		t.Fatal(err)
	}
	relay, err := ice.NewCandidateRelay(&ice.CandidateRelayConfig{
		Network: "udp", Address: "10.70.70.10", Port: 49160, Component: 1,
		RelAddr: "203.0.113.7", RelPort: 55000,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []ice.Candidate{host, srflx, relay} {
		marshaled := c.Marshal()
		back, err := ice.UnmarshalCandidate(marshaled)
		if err != nil {
			t.Fatalf("%s: unmarshal: %v", c.Type(), err)
		}
		if got := back.Marshal(); got != marshaled {
			t.Fatalf("%s round-trip mismatch:\n  in:  %q\n  out: %q", c.Type(), marshaled, got)
		}
	}
}
