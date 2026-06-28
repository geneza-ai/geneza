package agentd

import (
	"log/slog"
	"testing"

	"github.com/miekg/dns"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// TestDNSResolverAnswer exercises the multi-Network dispatch + policy/zone
// semantics WITHOUT binding the socket (answer() is pure): a name resolves in its
// Network's zone, an unknown in-zone name is NXDOMAIN (no enumeration), an
// out-of-zone name is REFUSED (falls back to upstream), and FQDN selects the
// right Network when a node is in multiple.
func TestDNSResolverAnswer(t *testing.T) {
	d := newDNSResolver(slog.Default())
	d.zones = zonesFromSpecs([]*genezav1.NetworkSpec{
		{DnsZone: "geneza", DnsRecords: []*genezav1.DnsRecord{
			{Name: "node1", Ip: "100.64.0.2", Ttl: 15},
			{Name: "node2", Ip: "100.64.0.3", Ttl: 15},
		}},
		{DnsZone: "prod.acme.geneza", DnsRecords: []*genezav1.DnsRecord{
			{Name: "db1", Ip: "100.64.1.5", Ttl: 30},
			{Name: "node2", Ip: "100.64.1.9", Ttl: 30}, // same label, different Network
		}},
	}, []*genezav1.DnsZoneSpec{
		// A managed-domain reservation: the same overlay names also resolve under
		// the public base, VPN-only.
		{Suffix: "acme.geneza.app", Records: []*genezav1.DnsRecord{
			{Name: "node1", Ip: "100.64.0.2", Ttl: 15},
		}},
	})

	cases := []struct {
		q      string
		wantRC int
		wantA  string // expected A (if NOERROR)
	}{
		{"node2.geneza.", dns.RcodeSuccess, "100.64.0.3"},           // default network
		{"db1.prod.acme.geneza.", dns.RcodeSuccess, "100.64.1.5"},   // other network by FQDN
		{"node2.prod.acme.geneza.", dns.RcodeSuccess, "100.64.1.9"}, // FQDN selects the right Network (collision)
		{"ghost.geneza.", dns.RcodeNameError, ""},                   // unknown in-zone -> NXDOMAIN
		{"db1.geneza.", dns.RcodeNameError, ""},                     // exists in other zone only -> NXDOMAIN here
		{"node1.acme.geneza.app.", dns.RcodeSuccess, "100.64.0.2"},  // managed-domain name resolves on the VPN
		{"ghost.acme.geneza.app.", dns.RcodeNameError, ""},          // unknown in managed zone -> NXDOMAIN
		{"example.com.", dns.RcodeRefused, ""},                      // out of zone -> REFUSED
	}
	for _, c := range cases {
		m := new(dns.Msg)
		m.SetQuestion(c.q, dns.TypeA)
		query, err := m.Pack()
		if err != nil {
			t.Fatalf("pack %s: %v", c.q, err)
		}
		out := d.answer(query)
		if out == nil {
			t.Fatalf("%s: nil answer", c.q)
		}
		var resp dns.Msg
		if err := resp.Unpack(out); err != nil {
			t.Fatalf("%s: unpack: %v", c.q, err)
		}
		if resp.Rcode != c.wantRC {
			t.Errorf("%s: rcode=%d want=%d", c.q, resp.Rcode, c.wantRC)
			continue
		}
		if c.wantA != "" {
			if len(resp.Answer) != 1 {
				t.Errorf("%s: want 1 answer, got %d", c.q, len(resp.Answer))
				continue
			}
			a, ok := resp.Answer[0].(*dns.A)
			if !ok || a.A.String() != c.wantA {
				t.Errorf("%s: A=%v want %s", c.q, resp.Answer[0], c.wantA)
			}
		}
	}
}
