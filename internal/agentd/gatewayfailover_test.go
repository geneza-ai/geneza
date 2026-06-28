package agentd

import (
	"testing"

	"geneza.io/internal/types"
)

// The agent's candidate controllers are its seed plus the controllers discovered from the
// signed cluster config (deduped, seed first), and advanceController rotates through
// them so a dead controller is left for the next candidate, wrapping back to the seed.
func TestAgentControllerFailoverRotation(t *testing.T) {
	w := &Worker{cfg: &Config{ControllerGRPCAddr: "seed:7401"}, st: &State{}}
	w.cluster = &types.ClusterConfig{ControllerEndpoints: []types.ControllerEndpoint{
		{ControllerID: "gw1", Addrs: []string{"seed:7401"}}, // duplicate of the seed → deduped
		{ControllerID: "gw2", Addrs: []string{"b:7401"}},
	}}

	cands := w.controllerCandidates()
	if len(cands) != 2 || cands[0] != "seed:7401" || cands[1] != "b:7401" {
		t.Fatalf("candidates = %v (want [seed:7401 b:7401])", cands)
	}
	if got := w.controllerAddr(); got != "seed:7401" {
		t.Fatalf("initial controller = %q (want seed)", got)
	}
	w.advanceController()
	if got := w.controllerAddr(); got != "b:7401" {
		t.Fatalf("after one advance = %q (want b)", got)
	}
	w.advanceController()
	if got := w.controllerAddr(); got != "seed:7401" {
		t.Fatalf("after wrap = %q (want seed)", got)
	}

	// With no discovered controllers, the agent stays on its seed (single-node behavior).
	solo := &Worker{cfg: &Config{ControllerGRPCAddr: "only:7401"}, st: &State{}}
	if got := solo.controllerAddr(); got != "only:7401" {
		t.Fatalf("solo controller = %q", got)
	}
	solo.advanceController()
	if got := solo.controllerAddr(); got != "only:7401" {
		t.Fatalf("solo advance must stay on seed, got %q", got)
	}
}
