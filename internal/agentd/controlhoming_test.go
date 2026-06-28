package agentd

import (
	"testing"

	"geneza.io/internal/types"
)

func TestControlMuxRelaySelection(t *testing.T) {
	relays := []types.RelayNode{
		{RegionID: "us", ControlMux: false, ControlAddr: "us-nomux:7403"}, // not control-mux
		{RegionID: "eu", ControlMux: true, ControlAddr: ""},               // no control addr
		{RegionID: "ap", ControlMux: true, ControlAddr: "ap:7403"},        // usable, wrong region
		{RegionID: "eu", ControlMux: true, ControlAddr: "eu:7403"},        // usable, home region
	}
	// Home-region match wins.
	if r, ok := controlMuxRelay(relays, "eu"); !ok || r.ControlAddr != "eu:7403" {
		t.Fatalf("home-region select = %+v ok=%v", r, ok)
	}
	// No home-region match => any usable control-mux relay.
	if r, ok := controlMuxRelay(relays, "za"); !ok || r.ControlAddr != "ap:7403" {
		t.Fatalf("fallback select = %+v ok=%v", r, ok)
	}
	// No usable control-mux relay at all => none.
	if _, ok := controlMuxRelay([]types.RelayNode{{ControlMux: false}, {ControlMux: true}}, "eu"); ok {
		t.Fatal("no usable control-mux relay should select none")
	}
}

func relayHomingWorker() *Worker {
	return &Worker{
		cfg: &Config{},
		st:  &State{},
		cluster: &types.ClusterConfig{
			ControllerEndpoints: []types.ControllerEndpoint{{ControllerID: "gw-a", Addrs: []string{"gw-a.example:7401"}}},
			Relays:           []types.RelayNode{{RegionID: "eu", ControlMux: true, ControlAddr: "relay-eu:7403", RelayCertPub: []byte("pin")}},
		},
	}
}

func TestControlHomePlanViaRelay(t *testing.T) {
	w := relayHomingWorker()
	p := w.controlHomePlan("eu")
	if !p.viaRelay {
		t.Fatal("expected relay-homed plan")
	}
	if p.controllerID != "gw-a" || p.controllerName != "gw-a.example" || p.relayControlAddr != "relay-eu:7403" {
		t.Fatalf("plan fields wrong: %+v", p)
	}
	if len(p.relayCertPins) != 1 {
		t.Fatalf("expected the relay leaf pin to be carried, got %d", len(p.relayCertPins))
	}
}

// The gates that keep a single-node / un-fleeted / opted-out / flapping agent on
// the direct controller dial — the byte-for-byte invariant.
func TestControlHomePlanGatesToDirect(t *testing.T) {
	// Single-node: no controller discovery set.
	if p := (&Worker{cfg: &Config{}, cluster: &types.ClusterConfig{}}).controlHomePlan("eu"); p.viaRelay {
		t.Fatal("single-node (no ControllerEndpoints) must be direct")
	}
	// No control-mux relay advertised.
	noRelay := &Worker{cfg: &Config{}, st: &State{}, cluster: &types.ClusterConfig{
		ControllerEndpoints: []types.ControllerEndpoint{{ControllerID: "gw-a", Addrs: []string{"gw-a:7401"}}},
		Relays:           []types.RelayNode{{RegionID: "eu", ControlMux: false, ControlAddr: "x:7403"}},
	}}
	if p := noRelay.controlHomePlan("eu"); p.viaRelay {
		t.Fatal("no control-mux relay must be direct")
	}
	// Kill-switch off.
	off := false
	w := relayHomingWorker()
	w.cfg.RelayHomedControl = &off
	if p := w.controlHomePlan("eu"); p.viaRelay {
		t.Fatal("kill-switch off must be direct")
	}
	// Post-failure cooldown.
	w2 := relayHomingWorker()
	w2.startDirectCooldown()
	if !w2.inDirectCooldown() {
		t.Fatal("cooldown should be active")
	}
	if p := w2.controlHomePlan("eu"); p.viaRelay {
		t.Fatal("cooldown must force direct")
	}
}
