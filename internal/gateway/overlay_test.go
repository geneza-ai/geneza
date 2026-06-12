package gateway

import "testing"

func TestOverlayAllocReleaseUnique(t *testing.T) {
	a := newOverlayAllocator()
	seen := map[string]bool{}
	var ips []string
	for i := 0; i < 50; i++ {
		ip, err := a.alloc()
		if err != nil {
			t.Fatalf("alloc %d: %v", i, err)
		}
		if seen[ip] {
			t.Fatalf("duplicate overlay ip handed out: %s", ip)
		}
		seen[ip] = true
		ips = append(ips, ip)
	}
	// Releasing makes addresses available again.
	a.release(ips[0])
	a.release(ips[1])
	got1, _ := a.alloc()
	got2, _ := a.alloc()
	if got1 == got2 {
		t.Fatalf("alloc returned the same ip twice after two releases: %s", got1)
	}
}

func TestOverlayPoolExhaustion(t *testing.T) {
	a := newOverlayAllocator()
	n := 0
	for {
		_, err := a.alloc()
		if err != nil {
			break
		}
		n++
		if n > 300 {
			t.Fatal("allocator never reported exhaustion")
		}
	}
	if n != overlayClientLast-overlayClientFirst+1 { // per-session client range (128..254)
		t.Fatalf("expected %d addresses, got %d", overlayClientLast-overlayClientFirst+1, n)
	}
}

func TestMachineIPAllocation(t *testing.T) {
	used := map[string]bool{}
	first, err := allocMachineIP(used)
	if err != nil || first != "100.64.0.2" {
		t.Fatalf("first machine ip = %q (%v), want 100.64.0.2", first, err)
	}
	// The resolver address is skipped.
	used = map[string]bool{}
	for x := 2; x < 53; x++ {
		used[fmtIP(x)] = true
	}
	ip, _ := allocMachineIP(used)
	if ip == OverlayResolverIP {
		t.Fatalf("machine allocation handed out the reserved resolver IP %s", ip)
	}
	if ip != "100.64.0.54" {
		t.Fatalf("expected .53 skipped -> .54, got %s", ip)
	}
}

func fmtIP(x int) string { return "100.64.0." + itoa(x) }
func itoa(x int) string {
	if x == 0 {
		return "0"
	}
	var b []byte
	for x > 0 {
		b = append([]byte{byte('0' + x%10)}, b...)
		x /= 10
	}
	return string(b)
}

func TestValidCIDR(t *testing.T) {
	for _, c := range []string{"192.168.99.0/24", "0.0.0.0/0", "10.0.0.0/8"} {
		if !validCIDR(c) {
			t.Errorf("expected %q to be a valid CIDR", c)
		}
	}
	for _, c := range []string{"", "192.168.99.0", "not-a-cidr", "192.168.99.0/33"} {
		if validCIDR(c) {
			t.Errorf("expected %q to be invalid", c)
		}
	}
}
