package controller

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"geneza.io/internal/types"
)

// decodeRelays parses a handleRelays body into a relayId -> row map.
func decodeRelays(t *testing.T, body []byte) map[string]map[string]any {
	t.Helper()
	var out struct {
		Relays []map[string]any `json:"relays"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode relays: %v", err)
	}
	m := make(map[string]map[string]any, len(out.Relays))
	for _, r := range out.Relays {
		if id, ok := r["relayId"].(string); ok {
			m[id] = r
		}
	}
	return m
}

// fleetServer builds a Server backed by a SQL store with the dynamic relay-fleet
// path active (usesSQLStore() true), so the relay presence rows drive selection.
func fleetServer(t *testing.T, s *sqlStore) *Server {
	t.Helper()
	cfg := &Config{
		StoreBackend: "postgres", // any SQL backend flips usesSQLStore(); the store itself is `s`
		SessionP2P:   true,
		RelayRealm:   "geneza",
		GrantTTL:     Duration(time.Hour),
		RelaySecrets: map[string]RegionSecret{defaultRegion: {Current: "topsecret"}},
		RelayAddrs:   []string{"10.0.0.99:7403"}, // static config floor (the fallback)
	}
	return &Server{cfg: cfg, store: s}
}

func relayRow(region, id, dataAddr, ctrlAddr string, lastSeen int64, draining bool) *RelayRecord {
	return &RelayRecord{
		RelayNode: types.RelayNode{
			RegionID: region, RelayID: id,
			Addrs: []string{dataAddr}, TURNPort: 7404,
			ControlAddr: ctrlAddr, Draining: draining,
		},
		LastSeenUnix: lastSeen,
	}
}

// A healthy relay is selectable; a draining one and a stale one are excluded from
// the selectable set, the candidate list, and the TCP-floor pick — while the
// draining one stays VISIBLE in the full fleet (assembleRelays).
func TestSelectableRelaysExcludesDrainingAndStale(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		srv := fleetServer(t, s)
		now := time.Now().Unix()
		stale := now - int64(relayStaleTTL.Seconds()) - 5
		if err := s.UpsertRelay(relayRow(defaultRegion, "r-healthy", "h.relay:7404", "h.relay:7403", now, false)); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertRelay(relayRow(defaultRegion, "r-drain", "d.relay:7404", "d.relay:7403", now, true)); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertRelay(relayRow(defaultRegion, "r-stale", "s.relay:7404", "s.relay:7403", stale, false)); err != nil {
			t.Fatal(err)
		}

		sel := srv.selectableRelays()
		if len(sel) != 1 || sel[0].RelayID != "r-healthy" {
			t.Fatalf("selectableRelays = %+v, want only r-healthy", sel)
		}

		// Candidate set excludes draining + stale.
		cands := srv.selectRelayCandidates("sid", "", "")
		if len(cands) != 1 || cands[0].RelayID != "r-healthy" {
			t.Fatalf("candidates = %+v, want only r-healthy", cands)
		}

		// TCP floor pick is the healthy relay's TCP rendezvous addr, not a draining one
		// nor the static relay_addrs config.
		floor := srv.relayFloorAddrs()
		if len(floor) != 1 || floor[0] != "h.relay:7403" {
			t.Fatalf("relayFloorAddrs = %+v, want [h.relay:7403]", floor)
		}

		// assembleRelays keeps the draining relay VISIBLE (only the stale one ages out
		// of the signed map via the expiry sweep — here it is just past TTL but still a
		// row until ExpireStaleRelays runs, so the map carries all three rows).
		full := srv.assembleRelays()
		var sawDrain bool
		for _, r := range full {
			if r.RelayID == "r-drain" && r.Draining {
				sawDrain = true
			}
		}
		if !sawDrain {
			t.Fatalf("draining relay must stay visible in the signed map: %+v", full)
		}
	})
}

// With two healthy relays, draining one steers BOTH the candidate set and the
// TCP-floor pick to the other.
func TestDrainingOneSteersToOther(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		srv := fleetServer(t, s)
		now := time.Now().Unix()
		if err := s.UpsertRelay(relayRow(defaultRegion, "r-a", "a.relay:7404", "a.relay:7403", now, false)); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertRelay(relayRow(defaultRegion, "r-b", "b.relay:7404", "b.relay:7403", now, false)); err != nil {
			t.Fatal(err)
		}
		// Both healthy: both selectable.
		if got := len(srv.selectableRelays()); got != 2 {
			t.Fatalf("both healthy: selectable = %d, want 2", got)
		}

		// Drain r-a: r-b is the only pick now.
		if err := s.UpsertRelay(relayRow(defaultRegion, "r-a", "a.relay:7404", "a.relay:7403", now, true)); err != nil {
			t.Fatal(err)
		}
		sel := srv.selectableRelays()
		if len(sel) != 1 || sel[0].RelayID != "r-b" {
			t.Fatalf("after draining r-a, selectable = %+v, want only r-b", sel)
		}
		cands := srv.selectRelayCandidates("sid", "", "")
		if len(cands) != 1 || cands[0].RelayID != "r-b" {
			t.Fatalf("after draining r-a, candidates = %+v, want only r-b", cands)
		}
		floor := srv.relayFloorAddrs()
		if len(floor) != 1 || floor[0] != "b.relay:7403" {
			t.Fatalf("after draining r-a, floor = %+v, want [b.relay:7403]", floor)
		}
	})
}

// When EVERY relay is draining (a whole-fleet swap), selection falls back to the
// least-bad set rather than returning nothing — a degraded floor beats none.
func TestAllDrainingFallsBackToLeastBad(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		srv := fleetServer(t, s)
		now := time.Now().Unix()
		if err := s.UpsertRelay(relayRow(defaultRegion, "r-a", "a.relay:7404", "a.relay:7403", now, true)); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertRelay(relayRow(defaultRegion, "r-b", "b.relay:7404", "b.relay:7403", now, true)); err != nil {
			t.Fatal(err)
		}
		sel := srv.selectableRelays()
		if len(sel) != 2 {
			t.Fatalf("all-draining fallback: selectable = %+v, want both (least-bad)", sel)
		}
		if floor := srv.relayFloorAddrs(); len(floor) != 2 {
			t.Fatalf("all-draining fallback: floor = %+v, want both", floor)
		}
	})
}

// The broker's floor pick is a HEALTHY fleet relay, NOT the static relay_addrs[0]:
// with the fleet hook wired, the grant's RelayAddr/RelayFloor come from the live
// fleet; without a fleet it falls back to the configured relay_addrs.
func TestBrokerFloorIsFleetPickNotConfig(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		srv := fleetServer(t, s)
		now := time.Now().Unix()
		if err := s.UpsertRelay(relayRow(defaultRegion, "r-fleet", "f.relay:7404", "f.relay:7403", now, false)); err != nil {
			t.Fatal(err)
		}
		b := &Broker{relayAddrs: srv.cfg.RelayAddrs}
		b.SetRelayFloor(srv.relayFloorAddrs)

		floor := b.floorAddrs()
		if len(floor) != 1 || floor[0] != "f.relay:7403" {
			t.Fatalf("broker floor = %+v, want the fleet pick [f.relay:7403], not relay_addrs", floor)
		}
		if floor[0] == srv.cfg.RelayAddrs[0] {
			t.Fatalf("broker floor must not be the static relay_addrs[0] %q", srv.cfg.RelayAddrs[0])
		}

		// Empty the fleet entirely (age the row out): relayFloorAddrs returns nothing,
		// so the broker falls back to the static relay_addrs config floor.
		if err := s.UpsertRelay(relayRow(defaultRegion, "r-fleet", "f.relay:7404", "f.relay:7403", now-3600, false)); err != nil {
			t.Fatal(err)
		}
		if n, err := s.ExpireStaleRelays(time.Minute); err != nil || n != 1 {
			t.Fatalf("ExpireStaleRelays dropped %d %v (want 1)", n, err)
		}
		fb := b.floorAddrs()
		if len(fb) != 1 || fb[0] != srv.cfg.RelayAddrs[0] {
			t.Fatalf("empty fleet: floor = %+v, want config fallback %q", fb, srv.cfg.RelayAddrs[0])
		}
	})
}

// The cluster console reports draining=true / healthy=false for a drained relay and
// the complement for a healthy one.
func TestHandleRelaysReportsDraining(t *testing.T) {
	forEachSQLEngine(t, func(t *testing.T, s *sqlStore) {
		srv := fleetServer(t, s)
		now := time.Now().Unix()
		if err := s.UpsertRelay(relayRow(defaultRegion, "r-ok", "ok.relay:7404", "ok.relay:7403", now, false)); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertRelay(relayRow(defaultRegion, "r-dr", "dr.relay:7404", "dr.relay:7403", now, true)); err != nil {
			t.Fatal(err)
		}
		c := &clusterConsoleAPI{s: srv}
		rec := httptest.NewRecorder()
		c.handleRelays(rec, httptest.NewRequest("GET", "/clusterconsole/v1/topology/relays", nil))
		if rec.Code != 200 {
			t.Fatalf("handleRelays status = %d, body=%s", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		// crude shape assertions: the drained relay row carries draining:true, the
		// healthy one draining:false. (Full JSON decode below for precision.)
		got := decodeRelays(t, rec.Body.Bytes())
		for _, want := range []struct {
			id       string
			draining bool
		}{{"r-ok", false}, {"r-dr", true}} {
			r, ok := got[want.id]
			if !ok {
				t.Fatalf("relay %q missing from handleRelays output: %s", want.id, body)
			}
			if r["draining"] != want.draining {
				t.Fatalf("relay %q draining = %v, want %v", want.id, r["draining"], want.draining)
			}
			if r["healthy"] != !want.draining {
				t.Fatalf("relay %q healthy = %v, want %v", want.id, r["healthy"], !want.draining)
			}
		}
	})
}
