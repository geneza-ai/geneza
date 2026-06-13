package agentd

// dnsserver.go is Geneza's IN-NETWORK DNS: a LOCAL resolver each agent runs at
// 100.64.0.53, answering name->overlayIP PURELY from the zone the gateway PUSHED
// in NetworkConfig — never querying the gateway or relay at lookup time (the
// Tailscale MagicDNS model; zero per-query trust/availability dependency, works
// offline). One resolver per machine holds the UNION of all the node's Networks'
// zones; each Network's dns_zone is its search-domain suffix, so a node in
// multiple Networks resolves each in isolation (FQDN selects the Network; the OS
// search list + precedence handle bare names). Policy is by construction: the
// pushed records ARE the node's policy-filtered peer set, so it can resolve
// exactly what it can route to. The 100.64.0.53 socket is bound host-local
// (SO_BINDTODEVICE=lo on Linux) so a peer cannot query another node's resolver.
// See memory geneza-roadmap-coredns-tenancy / docs/dns-coredns-design.md.

import (
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"

	genezadns "osie.cloud/geneza/internal/dns"
	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

const (
	dnsResolverIP     = "100.64.0.53" // Geneza's own resolver IP (NOT Tailscale's 100.100.100.100)
	dnsResolverListen = dnsResolverIP + ":53"
	dnsDefaultTTL     = 15
)

type dnsRec struct {
	ip  string
	ttl uint32
}

type dnsZone struct {
	suffix   string // lowercased fqdn with trailing dot, e.g. "prod.acme.geneza."
	resolver *genezadns.Resolver
	recs     map[string]dnsRec // label -> record (immutable once built)
}

// dnsResolver is the per-agent local resolver. Update() swaps the zone set on each
// NetworkConfig reconcile; the UDP server (started once) answers from it.
type dnsResolver struct {
	log *slog.Logger

	mu      sync.RWMutex
	zones   []*dnsZone // longest-suffix-first (longest match wins)
	pc      net.PacketConn
	started bool
}

func newDNSResolver(log *slog.Logger) *dnsResolver {
	return &dnsResolver{log: log.With("component", "dns")}
}

// Update rebuilds the zone set from the reconciled NetworkConfig and (lazily)
// starts the resolver. Zones with the same suffix across Networks are merged
// (union); the gateway pushes only records this node may resolve.
func (d *dnsResolver) Update(specs []*genezav1.NetworkSpec) {
	zones := zonesFromSpecs(specs)
	d.mu.Lock()
	d.zones = zones
	d.mu.Unlock()
	if len(zones) > 0 {
		if err := d.ensureStarted(); err != nil {
			d.log.Warn("in-network DNS resolver unavailable", "err", err)
		}
	}
	d.log.Debug("dns zones updated", "zones", len(zones))
}

// zonesFromSpecs merges the pushed NetworkSpecs into the per-zone record set
// (union; same suffix across Networks merges), longest-suffix-first.
func zonesFromSpecs(specs []*genezav1.NetworkSpec) []*dnsZone {
	byZone := map[string]map[string]dnsRec{}
	for _, sp := range specs {
		z := strings.ToLower(strings.Trim(sp.GetDnsZone(), "."))
		if z == "" {
			continue
		}
		m := byZone[z]
		if m == nil {
			m = map[string]dnsRec{}
			byZone[z] = m
		}
		for _, r := range sp.GetDnsRecords() {
			lbl := strings.ToLower(strings.TrimSpace(r.GetName()))
			if lbl == "" || r.GetIp() == "" {
				continue
			}
			m[lbl] = dnsRec{ip: r.GetIp(), ttl: r.GetTtl()}
		}
	}
	zones := make([]*dnsZone, 0, len(byZone))
	for z, recs := range byZone {
		zr := genezadns.NewResolver(z)
		zones = append(zones, &dnsZone{suffix: zr.Zone, resolver: zr, recs: recs})
	}
	sort.Slice(zones, func(i, j int) bool { return len(zones[i].suffix) > len(zones[j].suffix) })
	return zones
}

func (d *dnsResolver) ensureStarted() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.started {
		return nil
	}
	pc, err := bindResolverSocket() // platform-specific (Linux: .53/32 on lo + SO_BINDTODEVICE)
	if err != nil {
		return err
	}
	d.pc = pc
	d.started = true
	go d.serve(pc)
	d.log.Info("in-network DNS resolver up", "addr", dnsResolverListen)
	return nil
}

func (d *dnsResolver) serve(pc net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return // closed
		}
		if out := d.answer(buf[:n]); out != nil {
			_, _ = pc.WriteTo(out, addr)
		}
	}
}

// answer resolves a query against the longest-matching pushed zone; out-of-zone
// names get REFUSED so the OS resolver falls back to its normal upstream
// (split-DNS), and unknown/denied in-zone names get NXDOMAIN (no enumeration).
func (d *dnsResolver) answer(query []byte) []byte {
	var req dns.Msg
	if err := req.Unpack(query); err != nil || len(req.Question) != 1 {
		return nil
	}
	name := strings.ToLower(req.Question[0].Name)
	d.mu.RLock()
	zones := d.zones
	d.mu.RUnlock()
	for _, z := range zones {
		if name == z.suffix || strings.HasSuffix(name, "."+z.suffix) {
			recs := z.recs
			lk := func(label string) (string, uint32, bool) {
				r, ok := recs[strings.ToLower(label)]
				if !ok {
					return "", 0, false
				}
				ttl := r.ttl
				if ttl == 0 {
					ttl = dnsDefaultTTL
				}
				return r.ip, ttl, true
			}
			out, err := z.resolver.Answer(query, lk)
			if err != nil {
				return nil
			}
			return out
		}
	}
	resp := new(dns.Msg)
	resp.SetReply(&req)
	resp.Rcode = dns.RcodeRefused
	out, err := resp.Pack()
	if err != nil {
		return nil
	}
	return out
}

func (d *dnsResolver) Stop() {
	d.mu.Lock()
	pc := d.pc
	d.pc = nil
	d.started = false
	d.zones = nil
	d.mu.Unlock()
	if pc != nil {
		_ = pc.Close()
	}
	releaseResolverAddr()
}
