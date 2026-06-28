package controller

import (
	"strings"
	"testing"
	"time"

	"geneza.io/internal/types"
)

// On single node the per-session candidate list is exactly one default-region
// relay, and its TURN credential matches the scalar session credential (same
// region tag, same data endpoint, same session binding) — proving parity with
// the pre-fleet path.
func TestSelectRelayCandidatesSingleNodeParity(t *testing.T) {
	cfg := &Config{
		SessionP2P:     true,
		RelaySecrets:   map[string]RegionSecret{"default": {Current: "topsecret"}},
		RelayDataAddrs: []string{"10.0.0.1:7404"},
		RelayRealm:     "geneza",
		GrantTTL:       Duration(time.Hour),
	}
	s := &Server{cfg: cfg}
	s.ccRelays = synthesizeRelays(cfg)

	cands := s.selectRelayCandidates("sid1", "", "")
	if len(cands) != 1 {
		t.Fatalf("want exactly one default-region candidate, got %d: %+v", len(cands), cands)
	}
	c := cands[0]
	if c.RegionID != "default" {
		t.Fatalf("candidate region = %q, want default", c.RegionID)
	}
	scalar, err := s.sessionTurnCreds("sid1", true)
	if err != nil {
		t.Fatal(err)
	}
	if c.TurnURL != scalar.TurnUrl {
		t.Fatalf("candidate URL %q != scalar %q", c.TurnURL, scalar.TurnUrl)
	}
	// Usernames embed a mint-time expiry, so compare the stable region+session tag.
	if !strings.HasSuffix(c.TurnUser, ":default:sess-sid1") || !strings.HasSuffix(scalar.Username, ":default:sess-sid1") {
		t.Fatalf("usernames not region+session tagged: cand=%q scalar=%q", c.TurnUser, scalar.Username)
	}
}

// Cross-region peers get one candidate per region; an unknown region falls back
// to the default region only.
func TestSelectRelayCandidatesCrossRegion(t *testing.T) {
	cfg := &Config{
		SessionP2P: true,
		RelaySecrets: map[string]RegionSecret{
			"eu":      {Current: "eu-secret"},
			"us":      {Current: "us-secret"},
			"default": {Current: "def-secret"},
		},
		RelayRealm: "geneza",
		GrantTTL:   Duration(time.Hour),
	}
	s := &Server{cfg: cfg}
	s.ccRelays = []types.RelayNode{
		{RegionID: "eu", RelayID: "r-eu", Addrs: []string{"eu.relay:7404"}, TURNPort: 7404},
		{RegionID: "us", RelayID: "r-us", Addrs: []string{"us.relay:7404"}, TURNPort: 7404},
		{RegionID: "default", RelayID: "r-def", Addrs: []string{"def.relay:7404"}, TURNPort: 7404},
	}
	cands := s.selectRelayCandidates("sid2", "eu", "us")
	regions := map[string]bool{}
	for _, c := range cands {
		regions[c.RegionID] = true
	}
	if !regions["eu"] || !regions["us"] || len(cands) != 2 {
		t.Fatalf("cross-region eu/us should yield one eu + one us candidate, got %+v", cands)
	}
	// An unknown client region falls back to default (not eu/us).
	fb := s.selectRelayCandidates("sid3", "antarctica", "us")
	got := map[string]bool{}
	for _, c := range fb {
		got[c.RegionID] = true
	}
	if !got["default"] || !got["us"] || got["eu"] {
		t.Fatalf("unknown region should fall back to default + us, got %+v", fb)
	}
}

// With session-p2p OFF, no candidate list is produced regardless of the fleet —
// so the signed grant stays byte-identical to the pre-fleet default and every
// session stays on the relay floor.
func TestSelectRelayCandidatesP2POffYieldsNone(t *testing.T) {
	cfg := &Config{
		SessionP2P:     false,
		RelaySecrets:   map[string]RegionSecret{"default": {Current: "topsecret"}},
		RelayDataAddrs: []string{"10.0.0.1:7404"},
		RelayRealm:     "geneza",
		GrantTTL:       Duration(time.Hour),
	}
	s := &Server{cfg: cfg}
	s.ccRelays = synthesizeRelays(cfg)
	if cands := s.selectRelayCandidates("sid1", "", ""); cands != nil {
		t.Fatalf("session-p2p off must yield no candidates, got %+v", cands)
	}
}
