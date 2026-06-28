package controller

import "testing"

// The separate cluster-control listener must be its own address; colliding it
// with the agent/user gRPC or the HTTPS listener is a config error (it would
// fail to segment, or fail to bind). Empty is always fine (the default — the
// registrar stays on grpc_listen).
func TestClusterControlListenValidation(t *testing.T) {
	base := func() *Config {
		return &Config{
			PolicyFile: "/etc/geneza/policy.yaml",
			RelayAddrs: []string{"10.0.0.1:7403"},
			GRPCListen: ":7401",
			HTTPListen: ":7402",
		}
	}
	cases := []struct {
		name   string
		listen string
		wantOK bool
	}{
		{"empty default", "", true},
		{"own address", ":7405", true},
		{"collides with grpc", ":7401", false},
		{"collides with http", ":7402", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := base()
			cfg.ClusterControlListen = c.listen
			err := cfg.validateForServe()
			if c.wantOK && err != nil {
				t.Fatalf("cluster_control_listen=%q: unexpected error %v", c.listen, err)
			}
			if !c.wantOK && err == nil {
				t.Fatalf("cluster_control_listen=%q: expected a collision error", c.listen)
			}
		})
	}
}
