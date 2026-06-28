package controller

import (
	"crypto/ed25519"
	"reflect"
	"testing"
)

// The single-node relay map must be byte-identical whether it is built at genesis
// or when a later reconcile rebuilds a drift candidate — otherwise the first
// restart would rebuild a config without the map, see "drift", bump the version,
// and silently drop the relays.
func TestSynthesizeRelaysGenesisEqualsReconcile(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	cfg := &Config{RelayAddrs: []string{"relay.example:7403"}, RelayDataAddrs: []string{"relay.example:7404"}}

	genesis := buildClusterConfig(1, []byte("roots"), "k1", pub, cfg, synthesizeRelays(cfg), nil, nil)
	candidate := buildClusterConfig(0, []byte("roots"), "k1", pub, cfg, synthesizeRelays(cfg), nil, nil)

	if !reflect.DeepEqual(genesis.Relays, candidate.Relays) {
		t.Fatalf("genesis vs reconcile relay maps differ:\n  genesis=%+v\n  candidate=%+v", genesis.Relays, candidate.Relays)
	}
	if len(genesis.Relays) != 1 {
		t.Fatalf("want one synthesized relay, got %d", len(genesis.Relays))
	}
	r := genesis.Relays[0]
	if r.RegionID != "default" || r.RelayID != "relay.example" {
		t.Fatalf("synth relay = %+v (want default / relay.example)", r)
	}
	if r.TURNPort != 7404 || r.STUNPort != 7404 {
		t.Fatalf("synth relay ports = stun:%d turn:%d (want 7404)", r.STUNPort, r.TURNPort)
	}
	if len(r.Addrs) != 1 || r.Addrs[0] != "relay.example:7404" {
		t.Fatalf("synth relay addrs = %v (want the data endpoint)", r.Addrs)
	}
}

// A region controller tags its synthesized relays with that region.
func TestSynthesizeRelaysUsesRegion(t *testing.T) {
	cfg := &Config{Region: "eu", RelayAddrs: []string{"eu.relay:7403"}}
	relays := synthesizeRelays(cfg)
	if len(relays) != 1 || relays[0].RegionID != "eu" {
		t.Fatalf("region synth = %+v", relays)
	}
}
