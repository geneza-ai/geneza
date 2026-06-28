package relay

import (
	"crypto/ed25519"
	"testing"

	"geneza.io/internal/types"
)

// The dial set always leads with the operator seed (so a fully-stale discovered set
// still recovers), drops the empty/duplicate entries, and keeps the rest.
func TestRelayCandidatesSeedFirstDeduped(t *testing.T) {
	got := relayCandidates("seed:7405", []string{"b:7405", "seed:7405", "", "c:7405"})
	if len(got) == 0 || got[0] != "seed:7405" {
		t.Fatalf("seed must lead: %v", got)
	}
	if len(got) != 3 {
		t.Fatalf("want seed + 2 deduped discovered, got %v", got)
	}
	seen := map[string]bool{}
	for _, a := range got {
		if a == "" || seen[a] {
			t.Fatalf("empty or duplicate candidate in %v", got)
		}
		seen[a] = true
	}
}

// Discovery reads a controller's control addresses, falling back to its gRPC addresses
// when the registrar shares the gRPC listener, and never verifies the signature
// (the relay only uses these to choose a dial address; the dial is mTLS-verified).
func TestRelayDiscoverControllersPrefersControlAddrs(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	cc := types.ClusterConfig{ControllerEndpoints: []types.ControllerEndpoint{
		{ControllerID: "gw1", Addrs: []string{"gw1:7401"}, ControlAddrs: []string{"gw1:7405"}},
		{ControllerID: "gw2", Addrs: []string{"gw2:7401"}}, // no control addrs → fall back to Addrs
	}}
	sig, err := types.Sign(priv, "k1", "test", cc)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := sig.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got := relayDiscoverControllers(blob)
	want := map[string]bool{"gw1:7405": true, "gw2:7401": true}
	if len(got) != 2 || !want[got[0]] || !want[got[1]] {
		t.Fatalf("want gw1 control-addr + gw2 grpc fallback, got %v", got)
	}
	// A blob that is not a valid signed config decodes to nothing rather than erroring.
	if relayDiscoverControllers([]byte("not-a-signed-config")) != nil {
		t.Fatal("garbage config must yield nil")
	}
	if relayDiscoverControllers(nil) != nil {
		t.Fatal("empty config must yield nil")
	}
}
