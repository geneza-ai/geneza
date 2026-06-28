package icewire

import (
	"testing"

	"github.com/pion/ice/v4"
)

func TestURLs(t *testing.T) {
	// Host-only (no TURN configured): host candidates, no servers.
	urls, types, err := URLs("", "", "", false)
	if err != nil {
		t.Fatalf("host-only: %v", err)
	}
	if len(urls) != 0 || len(types) != 1 || types[0] != ice.CandidateTypeHost {
		t.Fatalf("host-only: urls=%d types=%v", len(urls), types)
	}

	// Full: TURN + STUN servers, all three candidate types (direct + relay floor).
	urls, types, err = URLs("turn:relay.example:7404?transport=udp", "u", "p", false)
	if err != nil {
		t.Fatalf("full: %v", err)
	}
	if len(urls) != 2 { // turn + stun (same host:port)
		t.Fatalf("full: want 2 urls, got %d", len(urls))
	}
	if urls[0].Username != "u" || urls[0].Password != "p" {
		t.Fatalf("full: turn cred not set: %q/%q", urls[0].Username, urls[0].Password)
	}
	want := map[ice.CandidateType]bool{ice.CandidateTypeHost: true, ice.CandidateTypeServerReflexive: true, ice.CandidateTypeRelay: true}
	if len(types) != 3 {
		t.Fatalf("full: want 3 candidate types, got %v", types)
	}
	for _, ct := range types {
		if !want[ct] {
			t.Fatalf("full: unexpected candidate type %v", ct)
		}
	}

	// require_relay: the blind TURN floor only — no host/srflx IP disclosure.
	urls, types, err = URLs("turn:relay.example:7404?transport=udp", "u", "p", true)
	if err != nil {
		t.Fatalf("relay-only: %v", err)
	}
	if len(urls) != 1 || len(types) != 1 || types[0] != ice.CandidateTypeRelay {
		t.Fatalf("relay-only: urls=%d types=%v", len(urls), types)
	}

	if _, _, err := URLs("::not a url::", "", "", false); err == nil {
		t.Fatal("a malformed turn url must error")
	}
}
