package types

import (
	"crypto/ed25519"
	"net"
	"testing"
)

// The signed relay fleet rides the same envelope as the rest of the cluster
// config: it round-trips through Sign/Verify, and tampering with a relay entry
// breaks verification exactly like a forged config.
func TestClusterConfigRelaysSignedAndTamperEvident(t *testing.T) {
	pub, priv, keyID, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	trusted := map[string]ed25519.PublicKey{keyID: pub}

	cc := &ClusterConfig{
		ConfigVersion: 3,
		GrantKeys:     []GrantKey{{KeyID: keyID, PublicKey: pub}},
		Relays: []RelayNode{
			{RegionID: "eu", RelayID: "r-eu-1", Addrs: []string{"eu.relay:7404"}, STUNPort: 7405, TURNPort: 7404},
			{RegionID: "us", RelayID: "r-us-1", Addrs: []string{"us.relay:7404"}},
		},
	}
	signed, err := Sign(priv, keyID, "cluster-config", cc)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyClusterConfig(trusted, signed, 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(got.Relays) != 2 {
		t.Fatalf("relays not round-tripped: %+v", got.Relays)
	}
	if eus := got.RelaysByRegion()["eu"]; len(eus) != 1 || eus[0].RelayID != "r-eu-1" {
		t.Fatalf("RelaysByRegion: %+v", eus)
	}
	if r, ok := got.RelayByID("r-us-1"); !ok || r.RegionID != "us" {
		t.Fatalf("RelayByID: %+v %v", r, ok)
	}

	// Flip one byte of a relay address inside the signed payload: verification must fail.
	for i := range signed.Payload {
		if signed.Payload[i] == 'u' {
			signed.Payload[i] = 'x'
			break
		}
	}
	if _, err := VerifyClusterConfig(trusted, signed, 0); err == nil {
		t.Fatal("a tampered relay list must fail signature verification")
	}
}

// The signed controller discovery set rides the same envelope: it round-trips and a
// tampered endpoint breaks verification like a forged config.
func TestClusterConfigControllerEndpointsSigned(t *testing.T) {
	pub, priv, keyID, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	trusted := map[string]ed25519.PublicKey{keyID: pub}
	cc := &ClusterConfig{
		ConfigVersion: 2,
		GrantKeys:     []GrantKey{{KeyID: keyID, PublicKey: pub}},
		ControllerEndpoints: []ControllerEndpoint{
			{ControllerID: "gw-a", Addrs: []string{"a.gw:7401"}, RegionID: "eu"},
			{ControllerID: "gw-b", Addrs: []string{"b.gw:7401"}},
		},
	}
	signed, err := Sign(priv, keyID, "cluster-config", cc)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyClusterConfig(trusted, signed, 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(got.ControllerEndpoints) != 2 || got.ControllerEndpoints[0].ControllerID != "gw-a" {
		t.Fatalf("controller endpoints not round-tripped: %+v", got.ControllerEndpoints)
	}
	for i := range signed.Payload {
		if signed.Payload[i] == 'a' {
			signed.Payload[i] = 'z'
			break
		}
	}
	if _, err := VerifyClusterConfig(trusted, signed, 0); err == nil {
		t.Fatal("a tampered controller endpoint must fail verification")
	}
}

// FailoverAddrs interleaves across controllers (consecutive entries are DIFFERENT
// controllers, so a hung controller costs one failover step not one per address) and puts
// IP addresses before hostnames (an unresolvable name never stalls reaching a live
// controller). control=true prefers a controller's ControlAddrs.
func TestFailoverAddrsInterleavedIPFirst(t *testing.T) {
	gws := []ControllerEndpoint{
		{ControllerID: "gw1", Addrs: []string{"gw1.example:7401", "10.0.0.1:7401"}},
		{ControllerID: "gw2", Addrs: []string{"gw2.example:7401", "10.0.0.2:7401"}},
	}
	got := FailoverAddrs(gws, false)
	want := []string{"10.0.0.1:7401", "10.0.0.2:7401", "gw1.example:7401", "gw2.example:7401"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("at %d got %q want %q (full %v)", i, got[i], want[i], got)
		}
	}
	// The failover-speed property: the first two candidates are different controllers.
	g0, _, _ := net.SplitHostPort(got[0])
	g1, _, _ := net.SplitHostPort(got[1])
	if g0 == "10.0.0.1" && g1 == "10.0.0.1" {
		t.Fatal("first two candidates are the same controller — interleaving lost")
	}

	// control=true prefers ControlAddrs, per controller, still IP-first + interleaved.
	gws[0].ControlAddrs = []string{"ctl.gw1:7405", "10.0.0.1:7405"}
	gc := FailoverAddrs(gws, true)
	if gc[0] != "10.0.0.1:7405" {
		t.Fatalf("control addr (IP) not first: %v", gc)
	}
	// gw2 has no ControlAddrs → falls back to its Addrs.
	found := false
	for _, a := range gc {
		if a == "10.0.0.2:7401" {
			found = true
		}
	}
	if !found {
		t.Fatalf("gw2 should fall back to its gRPC addrs: %v", gc)
	}
}

// TestEffectiveAuditRecipients covers the (single, list) collapse: the explicit
// list wins, the legacy single stands alone as a one-element set, an empty config
// yields no recipients, and blank entries in a list are dropped.
func TestEffectiveAuditRecipients(t *testing.T) {
	cases := []struct {
		name   string
		single string
		list   []string
		want   []string
	}{
		{"none", "", nil, nil},
		{"legacy single", "age1aaa", nil, []string{"age1aaa"}},
		{"list supersedes single", "age1single", []string{"age1a", "age1b"}, []string{"age1a", "age1b"}},
		{"list only", "", []string{"age1a", "age1b"}, []string{"age1a", "age1b"}},
		{"blank entries dropped", "", []string{"age1a", "", "age1b"}, []string{"age1a", "age1b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cc := &ClusterConfig{AuditRecipient: tc.single, AuditRecipients: tc.list}
			got := cc.EffectiveAuditRecipients()
			if !equalStrings(got, tc.want) {
				t.Fatalf("ClusterConfig = %v, want %v", got, tc.want)
			}
			// TrustAnchors carries the identical rule.
			ta := &TrustAnchors{AuditRecipient: tc.single, AuditRecipients: tc.list}
			if got := ta.EffectiveAuditRecipients(); !equalStrings(got, tc.want) {
				t.Fatalf("TrustAnchors = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAuditKeyID proves the set id is order-independent, distinguishes the
// single-key case from a set, and keeps a single recipient's id byte-for-byte
// stable (the pre-set "age-sha256:" form) for backward compatibility.
func TestAuditKeyID(t *testing.T) {
	if id := AuditKeyID(nil); id != "" {
		t.Fatalf("empty set id = %q, want empty", id)
	}

	single := AuditKeyID([]string{"age1aaa"})
	if single == "" || single[:11] != "age-sha256:" {
		t.Fatalf("single id = %q, want age-sha256: prefix", single)
	}
	// A one-element set must equal the single-recipient id, so existing rows keep
	// the exact label they had before sets existed.
	if got := AuditKeyID([]string{"age1aaa"}); got != single {
		t.Fatalf("one-element set id %q != single id %q", got, single)
	}

	ab := AuditKeyID([]string{"age1a", "age1b"})
	ba := AuditKeyID([]string{"age1b", "age1a"})
	if ab != ba {
		t.Fatalf("set id depends on order: %q vs %q", ab, ba)
	}
	if ab[:15] != "age-set-sha256:" {
		t.Fatalf("multi id = %q, want age-set-sha256: prefix", ab)
	}
	if ab == single {
		t.Fatalf("a two-key set collides with a single-key id: %q", ab)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
