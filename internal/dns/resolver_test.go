package dns

import (
	"testing"

	"github.com/miekg/dns"
)

func query(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func reply(t *testing.T, wire []byte) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	if err := m.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestResolverAnswers(t *testing.T) {
	r := NewResolver("geneza")
	lookup := func(label string) (string, uint32, bool) {
		if label == "web1" {
			return "100.64.0.7", 15, true
		}
		return "", 0, false // unknown OR denied
	}

	// In-zone known name -> A record.
	out, err := r.Answer(query(t, "web1.geneza", dns.TypeA), lookup)
	if err != nil {
		t.Fatal(err)
	}
	m := reply(t, out)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Fatalf("web1: rcode=%d answers=%d", m.Rcode, len(m.Answer))
	}
	if a, ok := m.Answer[0].(*dns.A); !ok || a.A.String() != "100.64.0.7" {
		t.Fatalf("bad A record: %v", m.Answer[0])
	}

	// In-zone unknown/denied -> NXDOMAIN (no enumeration oracle).
	out, _ = r.Answer(query(t, "secret.geneza", dns.TypeA), lookup)
	if m := reply(t, out); m.Rcode != dns.RcodeNameError {
		t.Fatalf("denied name: want NXDOMAIN, got rcode=%d", m.Rcode)
	}

	// Out-of-zone -> REFUSED (split DNS leaves other names on upstream).
	out, _ = r.Answer(query(t, "example.com", dns.TypeA), lookup)
	if m := reply(t, out); m.Rcode != dns.RcodeRefused {
		t.Fatalf("out-of-zone: want REFUSED, got rcode=%d", m.Rcode)
	}

	// Multi-label under the zone is not a machine -> NXDOMAIN-ish (REFUSED here,
	// since it's not a single machine label).
	out, _ = r.Answer(query(t, "a.b.geneza", dns.TypeA), lookup)
	if m := reply(t, out); m.Rcode == dns.RcodeSuccess {
		t.Fatalf("multi-label resolved unexpectedly: rcode=%d", m.Rcode)
	}
}
