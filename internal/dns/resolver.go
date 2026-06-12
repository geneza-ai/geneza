// Package dns is Geneza's embedded, policy-aware resolver. miekg/dns (the engine
// CoreDNS itself is built on) parses/builds wire-format DNS; the authoritative,
// policy-filtered answers come from a caller-supplied lookup closure, so this
// package stays free of gateway/ca/policy imports (no cycle) and a full CoreDNS
// plugin.Handler can later replace Answer behind this same shape.
//
// The resolver runs in the gateway (where identity, policy and the node
// directory live) — never on the payload-blind relay. The `geneza vpn` client
// runs a thin local stub that relays its queries here over the authenticated
// mTLS channel.
package dns

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// LookupA resolves one bare machine label (zone stripped, lowercased) to an
// IPv4 for THIS caller. ok=false means unknown OR not-permitted — the resolver
// maps both to NXDOMAIN so a denied name is indistinguishable from a
// nonexistent one (no enumeration oracle).
type LookupA func(label string) (ip string, ttlSeconds uint32, ok bool)

// Resolver answers DNS for one tenant zone (fqdn, e.g. "geneza." or
// "acme.geneza.").
type Resolver struct {
	Zone string
}

// NewResolver normalizes the zone to a lowercase fqdn with a trailing dot.
func NewResolver(zone string) *Resolver {
	z := strings.ToLower(strings.Trim(zone, "."))
	return &Resolver{Zone: z + "."}
}

// Answer parses a wire-format query and returns a wire-format reply, using
// lookupA for in-zone A questions.
func (r *Resolver) Answer(query []byte, lookupA LookupA) ([]byte, error) {
	var req dns.Msg
	if err := req.Unpack(query); err != nil {
		return nil, fmt.Errorf("unpack dns query: %w", err)
	}
	resp := new(dns.Msg)
	resp.SetReply(&req)
	resp.Authoritative = true
	resp.RecursionAvailable = false

	if len(req.Question) != 1 {
		resp.Rcode = dns.RcodeFormatError
		return resp.Pack()
	}
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	label, inZone := r.label(name)
	if !inZone {
		// Not our zone: refuse rather than recurse (split-DNS leaves other names
		// on the system's normal upstream).
		resp.Rcode = dns.RcodeRefused
		return resp.Pack()
	}
	switch q.Qtype {
	case dns.TypeA:
		if ip, ttl, ok := lookupA(label); ok {
			rr, err := dns.NewRR(fmt.Sprintf("%s %d IN A %s", q.Name, ttl, ip))
			if err != nil {
				resp.Rcode = dns.RcodeServerFailure
				return resp.Pack()
			}
			resp.Answer = append(resp.Answer, rr)
		} else {
			resp.Rcode = dns.RcodeNameError // NXDOMAIN (unknown or denied)
		}
	case dns.TypeAAAA:
		// No IPv6 overlay yet: NOERROR/NODATA if the name exists for A, else
		// NXDOMAIN. Cheap proxy: reuse the A lookup to decide existence.
		if _, _, ok := lookupA(label); !ok {
			resp.Rcode = dns.RcodeNameError
		}
	default:
		resp.Rcode = dns.RcodeNameError
	}
	return resp.Pack()
}

// label returns the single machine label if name is directly under the zone
// (<machine>.<zone>), else ok=false. Phase 1 is single-label only.
func (r *Resolver) label(name string) (string, bool) {
	if name == r.Zone {
		return "", false
	}
	suffix := "." + r.Zone
	if !strings.HasSuffix(name, suffix) {
		return "", false
	}
	label := strings.TrimSuffix(name, suffix)
	if label == "" || strings.Contains(label, ".") {
		return "", false
	}
	return label, true
}
