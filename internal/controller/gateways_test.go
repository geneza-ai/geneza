package controller

import (
	"testing"
	"time"

	"geneza.io/internal/types"
)

func TestControllerStoreUpsertListExpire(t *testing.T) {
	for name, st := range affinityStores(t) {
		st := st
		t.Run(name, func(t *testing.T) {
			now := time.Now().Unix()
			a := &ControllerRecord{ControllerEndpoint: types.ControllerEndpoint{ControllerID: "gw-a", Addrs: []string{"a:7401"}, RegionID: "eu"}, LastSeenUnix: now}
			b := &ControllerRecord{ControllerEndpoint: types.ControllerEndpoint{ControllerID: "gw-b", Addrs: []string{"b:7401"}, RegionID: "us"}, LastSeenUnix: now}
			old := &ControllerRecord{ControllerEndpoint: types.ControllerEndpoint{ControllerID: "gw-old", Addrs: []string{"o:7401"}}, LastSeenUnix: now - 3600}
			for _, g := range []*ControllerRecord{a, b, old} {
				if err := st.UpsertController(g); err != nil {
					t.Fatal(err)
				}
			}
			if gs, err := st.ListControllers(); err != nil || len(gs) != 3 {
				t.Fatalf("ListControllers = %d %v (want 3)", len(gs), err)
			}
			// Upsert refreshes presence (idempotent, keyed by controller_id).
			a.LastSeenUnix = now + 5
			if err := st.UpsertController(a); err != nil {
				t.Fatal(err)
			}
			if gs, _ := st.ListControllers(); len(gs) != 3 {
				t.Fatalf("upsert must not add a row: %d", len(gs))
			}
			// Expire drops only the stale gw-old at a 30-min TTL.
			n, err := st.ExpireStaleControllers(30 * time.Minute)
			if err != nil || n != 1 {
				t.Fatalf("ExpireStaleControllers dropped %d %v (want 1)", n, err)
			}
			if gs, _ := st.ListControllers(); len(gs) != 2 {
				t.Fatalf("after expire = %d controllers (want 2)", len(gs))
			}
		})
	}
}

// controllerEndpoint advertises ControlAddrs on the cluster-control port only when an
// operator splits that listener off, so a relay's discovery dials where the
// registrar actually answers; Addrs (the client/agent redirect target) stays gRPC.
func TestControllerEndpointControlAddrs(t *testing.T) {
	base := &Config{GRPCListen: ":7401", Advertise: Advertise{IPs: []string{"10.0.0.1"}}}

	// Shared listener: ControlAddrs is nil (relays fall back to Addrs).
	s := &Server{controllerID: "gw1", cfg: base}
	if ep := s.controllerEndpoint(); len(ep.Addrs) != 1 || ep.Addrs[0] != "10.0.0.1:7401" || ep.ControlAddrs != nil {
		t.Fatalf("shared listener: addrs=%v control=%v", ep.Addrs, ep.ControlAddrs)
	}

	// Split control listener: ControlAddrs uses the control port, Addrs stays gRPC.
	split := *base
	split.ClusterControlListen = ":7405"
	ep := (&Server{controllerID: "gw1", cfg: &split}).controllerEndpoint()
	if len(ep.Addrs) != 1 || ep.Addrs[0] != "10.0.0.1:7401" {
		t.Fatalf("addrs must stay the gRPC port: %v", ep.Addrs)
	}
	if len(ep.ControlAddrs) != 1 || ep.ControlAddrs[0] != "10.0.0.1:7405" {
		t.Fatalf("control addrs must use the control port: %v", ep.ControlAddrs)
	}
}
