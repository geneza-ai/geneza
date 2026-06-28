package icewire

import "testing"

func TestURLsMultiSingleCredParity(t *testing.T) {
	a, at, err1 := URLs("turn:h:7404?transport=udp", "u", "p", false)
	b, bt, err2 := URLsMulti([]RelayCred{{TurnURL: "turn:h:7404?transport=udp", TurnUser: "u", TurnPass: "p"}}, false)
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	if len(a) != len(b) || len(at) != len(bt) {
		t.Fatalf("len mismatch: %d/%d %d/%d", len(a), len(b), len(at), len(bt))
	}
	for i := range a {
		if a[i].Scheme != b[i].Scheme || a[i].Host != b[i].Host || a[i].Port != b[i].Port || a[i].Username != b[i].Username {
			t.Fatalf("uri %d differs: %+v vs %+v", i, a[i], b[i])
		}
	}
}
