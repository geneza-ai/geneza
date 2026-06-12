package gateway

import (
	"fmt"
	"net"
	"sync"
)

// overlayAllocator hands out client overlay IPs for VPN (subnet-route /
// exit-node) sessions from the CGNAT range 100.64.0.0/24. In-memory and
// released on session end; one gateway, a few hundred concurrent VPN clients.
type overlayAllocator struct {
	mu   sync.Mutex
	used map[string]bool
	next int
}

func newOverlayAllocator() *overlayAllocator {
	return &overlayAllocator{used: map[string]bool{}, next: 2}
}

// alloc returns a free 100.64.0.X (X in 2..254).
func (a *overlayAllocator) alloc() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := 0; i < 253; i++ {
		x := a.next
		a.next++
		if a.next > 254 {
			a.next = 2
		}
		ip := fmt.Sprintf("100.64.0.%d", x)
		if !a.used[ip] {
			a.used[ip] = true
			return ip, nil
		}
	}
	return "", fmt.Errorf("overlay address pool exhausted")
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
