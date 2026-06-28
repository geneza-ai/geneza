package controller

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// exercises the split-mode store writer's cross-binding invariant + anchor CAS on
// any Store impl, so both the SQL engines and the bbolt single-node store are held
// to the same rules.
func runFleetStateStoreChecks(t *testing.T, s Store) {
	t.Helper()

	// Genesis: a routine map bound to anchor v1 + the anchor itself, one txn.
	if err := s.SetSignedFleetState(1, []byte("map-v1"), 1, 1, []byte("anchor-v1")); err != nil {
		t.Fatalf("genesis split write: %v", err)
	}
	mv, ms, av, as, err := s.FleetStateSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if mv != 1 || string(ms) != "map-v1" || av != 1 || string(as) != "anchor-v1" {
		t.Fatalf("snapshot after genesis = (%d,%s,%d,%s)", mv, ms, av, as)
	}

	// Cross-binding: a routine map advance whose declared anchor (v2) is neither the
	// row's current anchor (v1) nor advanced this call is rejected.
	if err := s.SetSignedFleetState(2, []byte("map-v2"), 2 /*claims anchor v2*/, 1, nil); err == nil {
		t.Fatal("a routine map referencing an anchor the row does not hold must be rejected")
	}
	// ...and the rejected write left the row untouched.
	if mv, _, av, _, _ := s.FleetStateSnapshot(); mv != 1 || av != 1 {
		t.Fatalf("rejected cross-binding write mutated the row: map=%d anchor=%d", mv, av)
	}

	// A routine-map-only advance bound to the CURRENT anchor (v1) is fine.
	if err := s.SetSignedFleetState(2, []byte("map-v2"), 1, 1, nil); err != nil {
		t.Fatalf("map-only advance bound to current anchor: %v", err)
	}

	// Advancing BOTH the map and the anchor in one txn, the map bound to the new
	// anchor (v2).
	if err := s.SetSignedFleetState(3, []byte("map-v3"), 2, 2, []byte("anchor-v2")); err != nil {
		t.Fatalf("combined map+anchor advance: %v", err)
	}
	mv, _, av, as, _ = s.FleetStateSnapshot()
	if mv != 3 || av != 2 || string(as) != "anchor-v2" {
		t.Fatalf("after combined advance = map %d anchor %d/%s", mv, av, as)
	}

	// A combined advance whose map binds to the OLD anchor (v2) while the anchor
	// moves to v3 is rejected — neither stale-map/new-anchor nor new-map/stale-anchor
	// can persist.
	if err := s.SetSignedFleetState(4, []byte("map-v4"), 2 /*old*/, 3, []byte("anchor-v3")); err == nil {
		t.Fatal("a combined advance whose map binds to the pre-advance anchor must be rejected")
	}
}

func TestBboltFleetStateCrossBinding(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	runFleetStateStoreChecks(t, st)
}

func TestSQLFleetStateCrossBinding(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		runFleetStateStoreChecks(t, s)
	})
}

// A legacy (un-split) write must leave the anchor columns at their zero/NULL
// defaults — the row is byte-for-byte what it was before the split existed.
func TestSQLLegacyWriteLeavesAnchorColumnsDefault(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		if err := s.SetSignedClusterConfig(1, []byte("legacy-v1")); err != nil {
			t.Fatal(err)
		}
		mv, ms, av, as, err := s.FleetStateSnapshot()
		if err != nil {
			t.Fatal(err)
		}
		if mv != 1 || string(ms) != "legacy-v1" {
			t.Fatalf("map cols wrong: %d %s", mv, ms)
		}
		if av != 0 || as != nil {
			t.Fatalf("legacy write must leave anchors empty, got version=%d signed=%v", av, as)
		}
	})
}

// The split-mode anchor advance must be linearized: concurrent officers
// submitting the SAME next anchor version, exactly one wins, on each SQL engine.
func TestSQLFleetStateAnchorCAS(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		if err := s.SetSignedFleetState(1, []byte("map-v1"), 1, 1, []byte("anchor-v1")); err != nil {
			t.Fatalf("genesis: %v", err)
		}
		// 8 writers race to publish anchor v2 (each pairs a new map bound to v2).
		var wins, conflicts int64
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				err := s.SetSignedFleetState(2, []byte(fmt.Sprintf("map-v2-%d", idx)), 2, 2, []byte(fmt.Sprintf("anchor-v2-%d", idx)))
				switch {
				case err == nil:
					atomic.AddInt64(&wins, 1)
				case errors.Is(err, errClusterConfigConflict):
					atomic.AddInt64(&conflicts, 1)
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}(i)
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("concurrent anchor bump: %d winners, want 1 (conflicts=%d)", wins, conflicts)
		}
		if _, _, av, _, _ := s.FleetStateSnapshot(); av != 2 {
			t.Fatalf("final anchor version = %d, want 2", av)
		}
	})
}
