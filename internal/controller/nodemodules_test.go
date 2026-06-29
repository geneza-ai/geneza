package controller

import "testing"

// TestEffectiveNodeModulesDefaultOn proves inventory is on by default, that a
// stored entry (enabled or disabled) overrides the default, and that other
// modules are preserved alongside it.
func TestEffectiveNodeModulesDefaultOn(t *testing.T) {
	get := func(ms []NodeModule, name string) (NodeModule, bool) {
		for _, m := range ms {
			if m.Name == name {
				return m, true
			}
		}
		return NodeModule{}, false
	}

	// nil record -> the defaults, inventory enabled.
	eff := effectiveNodeModules(nil)
	if inv, ok := get(eff, "inventory"); !ok || !inv.Enabled {
		t.Fatalf("nil record: inventory should default on, got %+v", eff)
	}

	// node-exporter stored, no inventory entry -> inventory still on (default),
	// node-exporter preserved.
	eff = effectiveNodeModules(&NodeModulesRecord{Modules: []NodeModule{{Name: "node-exporter", Enabled: true}}})
	if inv, ok := get(eff, "inventory"); !ok || !inv.Enabled {
		t.Fatalf("inventory should stay default-on next to node-exporter, got %+v", eff)
	}
	if ne, ok := get(eff, "node-exporter"); !ok || !ne.Enabled {
		t.Fatalf("node-exporter should be preserved, got %+v", eff)
	}

	// explicit inventory:disabled overrides the default.
	eff = effectiveNodeModules(&NodeModulesRecord{Modules: []NodeModule{{Name: "inventory", Enabled: false}}})
	if inv, ok := get(eff, "inventory"); !ok || inv.Enabled {
		t.Fatalf("explicit disable should win over the default, got %+v", eff)
	}

	// moduleConfigProto (what the agent is told) carries the default too, even
	// from a nil record, without panicking.
	cfg := moduleConfigProto(nil)
	var hasInv bool
	for _, m := range cfg.GetModules() {
		if m.GetName() == "inventory" && m.GetEnabled() {
			hasInv = true
		}
	}
	if !hasInv {
		t.Fatal("moduleConfigProto(nil) must push inventory enabled by default")
	}
}
