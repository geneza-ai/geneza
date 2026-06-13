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
