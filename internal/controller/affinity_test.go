package controller

import (
	"os"
	"testing"
	"time"

	"geneza.io/internal/types"
)

// affinityStores returns the store backends to run the affinity contract against:
// always bbolt, plus each SQL engine whose test DSN is configured.
func affinityStores(t *testing.T) map[string]Store {
	t.Helper()
	stores := map[string]Store{"bbolt": testStore(t)}
	if dsn := os.Getenv("GENEZA_TEST_PG_DSN"); dsn != "" {
		stores["postgres"] = newTestSQLStore(t, sqlEngine{backend: "postgres", dsn: dsn})
	}
	if dsn := os.Getenv("GENEZA_TEST_MYSQL_DSN"); dsn != "" {
		stores["mariadb"] = newTestSQLStore(t, sqlEngine{backend: "mariadb", dsn: dsn})
	}
	return stores
}

func TestAffinityEpochMonotonicAndCompareAndDelete(t *testing.T) {
	for name, st := range affinityStores(t) {
		st := st
		t.Run(name, func(t *testing.T) {
			now := time.Now()
			e1, err := st.ClaimAgentAffinity("n1", "gw-A", now)
			if err != nil || e1 != 1 {
				t.Fatalf("first claim epoch=%d err=%v (want 1)", e1, err)
			}
			e2, _ := st.ClaimAgentAffinity("n1", "gw-A", now)
			e3, _ := st.ClaimAgentAffinity("n1", "gw-B", now)
			if e2 != 2 || e3 != 3 {
				t.Fatalf("epochs not monotonic: %d %d (want 2 3)", e2, e3)
			}
			if gw, ep, ok := st.AgentAffinity("n1"); !ok || gw != "gw-B" || ep != 3 {
				t.Fatalf("current owner = %q/%d/%v (want gw-B/3/true)", gw, ep, ok)
			}
			// A superseded release (stale controller+epoch) must NOT evict the live owner.
			if err := st.ReleaseAgentAffinity("n1", "gw-A", 2); err != nil {
				t.Fatal(err)
			}
			if gw, ep, ok := st.AgentAffinity("n1"); !ok || gw != "gw-B" || ep != 3 {
				t.Fatalf("stale release evicted live owner: %q/%d/%v", gw, ep, ok)
			}
			// The current owner's release deletes the row.
			if err := st.ReleaseAgentAffinity("n1", "gw-B", 3); err != nil {
				t.Fatal(err)
			}
			if _, _, ok := st.AgentAffinity("n1"); ok {
				t.Fatal("row should be gone after the current owner releases")
			}
		})
	}
}

func TestAffinityAdvertisedServicesEpochGated(t *testing.T) {
	for name, st := range affinityStores(t) {
		st := st
		t.Run(name, func(t *testing.T) {
			if svcs, err := st.AdvertisedServices("ws1", "n1"); err != nil || svcs != nil {
				t.Fatalf("never-connected node should be (nil,nil): %v %v", svcs, err)
			}
			good := []types.Service{{Name: "db", Kind: types.KindTCP, NodeID: "n1"}}
			if err := st.PutAdvertisedServices("ws1", "n1", 2, good); err != nil {
				t.Fatal(err)
			}
			// An older-epoch write loses.
			stale := []types.Service{{Name: "stale", Kind: types.KindTCP, NodeID: "n1"}}
			if err := st.PutAdvertisedServices("ws1", "n1", 1, stale); err != nil {
				t.Fatal(err)
			}
			if svcs, _ := st.AdvertisedServices("ws1", "n1"); len(svcs) != 1 || svcs[0].Name != "db" {
				t.Fatalf("older-epoch write should not overwrite: %+v", svcs)
			}
			// A newer-epoch write wins.
			if err := st.PutAdvertisedServices("ws1", "n1", 3, stale); err != nil {
				t.Fatal(err)
			}
			if svcs, _ := st.AdvertisedServices("ws1", "n1"); len(svcs) != 1 || svcs[0].Name != "stale" {
				t.Fatalf("newer-epoch write should win: %+v", svcs)
			}
			// A stale clear (wrong epoch) is a no-op; the matching epoch drops it.
			if err := st.ClearAdvertisedServices("ws1", "n1", 1); err != nil {
				t.Fatal(err)
			}
			if svcs, _ := st.AdvertisedServices("ws1", "n1"); len(svcs) != 1 {
				t.Fatalf("stale clear should be a no-op: %+v", svcs)
			}
			if err := st.ClearAdvertisedServices("ws1", "n1", 3); err != nil {
				t.Fatal(err)
			}
			if svcs, _ := st.AdvertisedServices("ws1", "n1"); svcs != nil {
				t.Fatalf("matching-epoch clear should drop: %+v", svcs)
			}
		})
	}
}
