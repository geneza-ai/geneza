package policy

import "testing"

func TestLabelsMatch(t *testing.T) {
	cases := []struct {
		name     string
		selector map[string]string
		labels   map[string]string
		want     bool
	}{
		{"empty selector = default open", nil, map[string]string{"env": "prod"}, true},
		{"empty selector matches empty labels", map[string]string{}, map[string]string{}, true},
		{"star key = any node", map[string]string{"*": "*"}, map[string]string{"team": "x"}, true},
		{"exact match", map[string]string{"env": "prod"}, map[string]string{"env": "prod", "team": "x"}, true},
		{"value mismatch", map[string]string{"env": "prod"}, map[string]string{"env": "dev"}, false},
		{"missing key", map[string]string{"env": "prod"}, map[string]string{"team": "x"}, false},
		{"star value = key present, any value", map[string]string{"env": "*"}, map[string]string{"env": "anything"}, true},
		{"star value but key absent", map[string]string{"env": "*"}, map[string]string{"team": "x"}, false},
		{"all keys must match", map[string]string{"env": "prod", "team": "x"}, map[string]string{"env": "prod"}, false},
		{"all keys match", map[string]string{"env": "prod", "team": "x"}, map[string]string{"env": "prod", "team": "x", "z": "1"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := LabelsMatch(c.selector, c.labels); got != c.want {
				t.Fatalf("LabelsMatch(%v, %v) = %v, want %v", c.selector, c.labels, got, c.want)
			}
		})
	}
}

// A tenant Network's membership is exactly LabelsMatch(network.Selector,
// node.Labels): default-open, tag-gated, instant-revoke when a tag is removed.
func TestNetworkMembershipSemantics(t *testing.T) {
	netA := map[string]string{}              // allow-all
	netB := map[string]string{"env": "prod"} // tagged
	laptop := map[string]string{}            // no tags initially

	if !LabelsMatch(netA, laptop) {
		t.Fatal("laptop should be a member of allow-all Network A")
	}
	if LabelsMatch(netB, laptop) {
		t.Fatal("untagged laptop must NOT be in prod Network B")
	}
	// admin grants the prod tag (realtime) -> membership flips on
	laptop["env"] = "prod"
	if !LabelsMatch(netB, laptop) {
		t.Fatal("after prod tag, laptop should join Network B")
	}
	// tag removed -> membership flips off (continuous authz tears down the WG)
	delete(laptop, "env")
	if LabelsMatch(netB, laptop) {
		t.Fatal("after tag removal, laptop must lose Network B")
	}
}
