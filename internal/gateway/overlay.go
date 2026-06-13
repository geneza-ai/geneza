package gateway

import (
	"fmt"
	"net"
	"sync"
)

// Overlay address plan within the CGNAT /24 (100.64.0.0/24):
//
//	.1            gateway (reserved)
//	.2  .. .126   STABLE per-machine addresses (DNS A records)
//	.53           the in-overlay resolver (reserved; see dns design)
//	.128 .. .254  per-SESSION client addresses (overlayAllocator)
const (
	OverlayResolverIP   = "100.64.0.53"
	overlayClientFirst  = 128
	overlayClientLast   = 254
	overlayMachineFirst = 2
	overlayMachineLast  = 126
	// defaultOverlayCIDR is the per-workspace overlay space (each tenant gets its
	// own; the .1/.53/.2-126/.128-254 split applies within each /24).
	defaultOverlayCIDR = "100.64.0.0/24"
)

// overlayAllocator hands out per-SESSION client overlay IPs for VPN (subnet-route
// / exit-node) sessions from the high half of 100.64.0.0/24. In-memory and
// released on session end; one gateway, a few hundred concurrent VPN clients.
type overlayAllocator struct {
	mu   sync.Mutex
	used map[string]bool
	next int
}

func newOverlayAllocator() *overlayAllocator {
	return &overlayAllocator{used: map[string]bool{}, next: overlayClientFirst}
}

// alloc returns a free per-session client 100.64.0.X (X in 128..254).
func (a *overlayAllocator) alloc() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	span := overlayClientLast - overlayClientFirst + 1
	for i := 0; i < span; i++ {
		x := a.next
		a.next++
		if a.next > overlayClientLast {
			a.next = overlayClientFirst
		}
		ip := fmt.Sprintf("100.64.0.%d", x)
		if !a.used[ip] {
			a.used[ip] = true
			return ip, nil
		}
	}
	return "", fmt.Errorf("overlay address pool exhausted")
}

// allocMachineIP picks a free STABLE machine address (100.64.0.2..126, skipping
// the reserved resolver .53), given the set already assigned to other nodes.
func allocMachineIP(used map[string]bool) (string, error) {
	for x := overlayMachineFirst; x <= overlayMachineLast; x++ {
		ip := fmt.Sprintf("100.64.0.%d", x)
		if ip == OverlayResolverIP || used[ip] {
			continue
		}
		return ip, nil
	}
	return "", fmt.Errorf("machine overlay pool exhausted")
}

func (a *overlayAllocator) release(ip string) {
	if ip == "" {
		return
	}
	a.mu.Lock()
	delete(a.used, ip)
	a.mu.Unlock()
}

// validCIDR is a small guard for subnet-route service addrs.
func validCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// allocIPInCIDR hands out a STABLE host address from an arbitrary subnet for the
// per-Network FIB. It reserves the first usable host (.1) as the Network gateway
// and skips the network/broadcast addresses, so two Networks with the same CIDR
// allocate independently but consistently. Caller passes the already-used set.
func allocIPInCIDR(cidr string, used map[string]bool) (string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("network subnet %q: %w", cidr, err)
	}
	ip = ip.Mask(ipnet.Mask)
	ones, bits := ipnet.Mask.Size()
	// Network + the reserved .1 gateway are skipped; for a host-bit subnet (/31,
	// /32) there is nothing to hand out.
	if bits-ones < 2 {
		return "", fmt.Errorf("network subnet %q too small to allocate hosts", cidr)
	}
	cur := cloneIP(ip)
	incIP(cur) // skip network address
	gateway := cloneIP(cur)
	incIP(cur) // skip the reserved .1 gateway
	for ipnet.Contains(cur) {
		s := cur.String()
		// Skip the IPv4 broadcast (all-ones host) and the gateway.
		if !isBroadcast(cur, ipnet) && s != gateway.String() && !used[s] {
			return s, nil
		}
		incIP(cur)
	}
	return "", fmt.Errorf("network subnet %q address pool exhausted", cidr)
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// isBroadcast reports whether ip is the all-ones (broadcast) host of an IPv4
// subnet; IPv6 has no broadcast so it always returns false there.
func isBroadcast(ip net.IP, ipnet *net.IPNet) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	bcast := make(net.IP, len(v4))
	for i := range v4 {
		bcast[i] = v4[i] | ^ipnet.Mask[i]
	}
	return v4.Equal(bcast)
}
