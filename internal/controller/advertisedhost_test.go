package controller

import "testing"

// advertisedHost() is handed to REMOTE parties: it is embedded in every enrollment
// code the console mints, and in the runtime endpoints the enrolled agent then dials.
// `advertise` conventionally lists localhost so on-host flows work, so taking entry
// [0] blindly emits "localhost:7401" to nodes that are not this host — enrollment then
// fails with `dial tcp [::1]:7401: connect: connection refused`, which reads like the
// controller is down rather than like it advertised the wrong name.
func TestAdvertisedHostPrefersRoutableEntry(t *testing.T) {
	for _, tc := range []struct {
		name string
		dns  []string
		ips  []string
		want string
	}{
		{"localhost first is skipped", []string{"localhost", "geneza.example.com"}, []string{"127.0.0.1", "203.0.113.9"}, "geneza.example.com"},
		{"already routable first", []string{"geneza.example.com", "localhost"}, nil, "geneza.example.com"},
		{"ip-only advertise skips loopback", nil, []string{"127.0.0.1", "203.0.113.9"}, "203.0.113.9"},
		{"ipv6 loopback is skipped", nil, []string{"::1", "203.0.113.9"}, "203.0.113.9"},
		{"dns wins over ip", []string{"localhost", "geneza.example.com"}, []string{"203.0.113.9"}, "geneza.example.com"},
		// A purely local lab advertises nothing routable. Returning "" would strip the
		// endpoints out of the enrollment code entirely, so keep the declared order.
		{"loopback-only falls back to declared order", []string{"localhost"}, []string{"127.0.0.1"}, "localhost"},
		{"loopback ip only", nil, []string{"127.0.0.1"}, "127.0.0.1"},
		{"nothing advertised", nil, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{cfg: &Config{}}
			s.cfg.Advertise.DNSNames = tc.dns
			s.cfg.Advertise.IPs = tc.ips
			if got := s.advertisedHost(); got != tc.want {
				t.Fatalf("advertisedHost() = %q, want %q (dns=%v ips=%v)", got, tc.want, tc.dns, tc.ips)
			}
		})
	}
}

// The endpoints the enrollment code carries are built from advertisedHost(), so the
// preference has to survive into them — that is the actual failure a node hits.
func TestControllerEndpointsUseRoutableHost(t *testing.T) {
	s := &Server{cfg: &Config{GRPCListen: ":7401", HTTPListen: ":7402"}}
	s.cfg.Advertise.DNSNames = []string{"localhost", "geneza.example.com"}
	s.cfg.Advertise.IPs = []string{"127.0.0.1", "203.0.113.9"}

	if got, want := s.controllerGRPCEndpoint(), "geneza.example.com:7401"; got != want {
		t.Errorf("controllerGRPCEndpoint() = %q, want %q", got, want)
	}
	if got, want := s.controllerRuntimeBase(), "https://geneza.example.com:7402"; got != want {
		t.Errorf("controllerRuntimeBase() = %q, want %q", got, want)
	}
}
