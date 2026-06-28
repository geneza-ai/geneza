package controller

import (
	"bytes"
	"testing"
	"time"

	"geneza.io/internal/types"
)

// The presence-row version must survive a round trip through Upsert/List on every
// store engine, and it must live ONLY on the unsigned presence row — never on the
// embedded RelayNode / ControllerEndpoint that the signed map is built from.
func TestPresenceRowVersionRoundTrips(t *testing.T) {
	for name, st := range affinityStores(t) {
		st := st
		t.Run(name, func(t *testing.T) {
			now := time.Now().Unix()
			rl := &RelayRecord{
				RelayNode:    types.RelayNode{RegionID: "eu", RelayID: "r1", Addrs: []string{"eu:7404"}},
				LastSeenUnix: now, Version: "1.4.2",
			}
			if err := st.UpsertRelay(rl); err != nil {
				t.Fatal(err)
			}
			got, err := st.ListRelays("")
			if err != nil || len(got) != 1 {
				t.Fatalf("ListRelays = %d %v (want 1)", len(got), err)
			}
			if got[0].Version != "1.4.2" {
				t.Fatalf("relay version round trip = %q, want 1.4.2", got[0].Version)
			}

			gw := &ControllerRecord{
				ControllerEndpoint: types.ControllerEndpoint{ControllerID: "gw-a", Addrs: []string{"a:7401"}, RegionID: "eu"},
				LastSeenUnix:    now, Version: "1.4.3",
			}
			if err := st.UpsertController(gw); err != nil {
				t.Fatal(err)
			}
			gws, err := st.ListControllers()
			if err != nil || len(gws) != 1 {
				t.Fatalf("ListControllers = %d %v (want 1)", len(gws), err)
			}
			if gws[0].Version != "1.4.3" {
				t.Fatalf("controller version round trip = %q, want 1.4.3", gws[0].Version)
			}
		})
	}
}

// Adding the presence-row version must not change the bytes of the SIGNED cluster
// config: the version lives on the presence-row JSON doc, not on the RelayNode /
// ControllerEndpoint embedded in the signed ClusterConfig. So two presence rows that
// differ ONLY in Version assemble to byte-identical signed-map inputs.
func TestPresenceVersionNotInSignedMapInputs(t *testing.T) {
	// The signed map is built from the EMBEDDED RelayNode / ControllerEndpoint, so two
	// presence rows differing only in Version must yield byte-identical embedded
	// types — the version rides the outer presence row, never the signed input.
	rbase := types.RelayNode{RegionID: "eu", RelayID: "r1", Addrs: []string{"eu:7404"}, RelayCertPub: []byte{1, 2, 3}}
	ra := RelayRecord{RelayNode: rbase, LastSeenUnix: 100, Version: "1.0.0"}
	rb := RelayRecord{RelayNode: rbase, LastSeenUnix: 100, Version: "9.9.9"}
	if !bytes.Equal(mustJSON(ra.RelayNode), mustJSON(rb.RelayNode)) {
		t.Fatal("relay version leaked into the signed RelayNode")
	}

	gbase := types.ControllerEndpoint{ControllerID: "gw-a", Addrs: []string{"a:7401"}, RegionID: "eu"}
	ga := ControllerRecord{ControllerEndpoint: gbase, LastSeenUnix: 100, Version: "1.0.0"}
	gb := ControllerRecord{ControllerEndpoint: gbase, LastSeenUnix: 100, Version: "9.9.9"}
	if !bytes.Equal(mustJSON(ga.ControllerEndpoint), mustJSON(gb.ControllerEndpoint)) {
		t.Fatal("controller version leaked into the signed ControllerEndpoint")
	}
}
