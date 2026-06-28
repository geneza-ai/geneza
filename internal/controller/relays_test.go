package controller

import (
	"testing"
	"time"

	"geneza.io/internal/types"
)

func TestRelayStoreUpsertListExpire(t *testing.T) {
	for name, st := range affinityStores(t) {
		st := st
		t.Run(name, func(t *testing.T) {
			now := time.Now().Unix()
			eu := &RelayRecord{RelayNode: types.RelayNode{RegionID: "eu", RelayID: "r1", Addrs: []string{"eu:7404"}}, LastSeenUnix: now}
			us := &RelayRecord{RelayNode: types.RelayNode{RegionID: "us", RelayID: "r2", Addrs: []string{"us:7404"}}, LastSeenUnix: now}
			old := &RelayRecord{RelayNode: types.RelayNode{RegionID: "eu", RelayID: "r3"}, LastSeenUnix: now - 3600}
			for _, r := range []*RelayRecord{eu, us, old} {
				if err := st.UpsertRelay(r); err != nil {
					t.Fatal(err)
				}
			}
			// Per-region list.
			if rs, err := st.ListRelays("eu"); err != nil || len(rs) != 2 {
				t.Fatalf("ListRelays(eu) = %d %v (want 2)", len(rs), err)
			}
			// Global list.
			if rs, err := st.ListRelays(""); err != nil || len(rs) != 3 {
				t.Fatalf("ListRelays(all) = %d %v (want 3)", len(rs), err)
			}
			// Upsert refreshes lastseen.
			eu.LastSeenUnix = now + 5
			if err := st.UpsertRelay(eu); err != nil {
				t.Fatal(err)
			}
			// Expire drops only the stale one (r3, 1h old) at a 30-min TTL.
			n, err := st.ExpireStaleRelays(30 * time.Minute)
			if err != nil || n != 1 {
				t.Fatalf("ExpireStaleRelays dropped %d %v (want 1)", n, err)
			}
			if rs, _ := st.ListRelays(""); len(rs) != 2 {
				t.Fatalf("after expire = %d relays (want 2)", len(rs))
			}
		})
	}
}
