package controller

import (
	"fmt"
	"testing"
)

// BenchmarkNetworkConfigProto measures building one node's desired NetworkConfig
// as the workspace's member count N grows. This is the per-node unit that
// repushAllNetworks runs for every node, so its cost is the inner term of the
// membership-change fan-out (repush ≈ N × this). Watch how it scales in N and
// how many store scans it pays per call.
func BenchmarkNetworkConfigProto(b *testing.B) {
	// Kept within the default-network machine-overlay pool (~124 addresses): past
	// it ensureNodeOverlayIP thrashes (a distinct scale limit), which would mask the
	// fan-out cost this benchmark targets.
	for _, n := range []int{25, 50, 100} {
		srv := newDataPlaneServer(b)
		ws := defaultWorkspace
		// One open (all-members) non-default Network so every peer's overlay IP is a
		// per-Network binding resolve — the heavier path the fan-out actually walks.
		if err := srv.store.PutNetwork(&NetworkRecord{WorkspaceID: ws, ID: "net1", VNI: 100}); err != nil {
			b.Fatal(err)
		}
		if err := srv.store.PutSubnet(&SubnetRecord{WorkspaceID: ws, NetworkID: "net1", ID: "s", CIDR: "10.20.0.0/16"}); err != nil {
			b.Fatal(err)
		}
		var self *NodeRecord
		for i := 0; i < n; i++ {
			r := putWGNode(b, srv, ws, fmt.Sprintf("n-%04d", i), fmt.Sprintf("node%d", i), nil, true, byte(1+i%255))
			if i == 0 {
				self = r
			}
		}
		// Warm the bindings so steady-state measures resolves, not first-time allocs.
		_ = srv.networkConfigProto(ws, self, 0)
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for k := 0; k < b.N; k++ {
				cfg := srv.networkConfigProto(ws, self, int64(k+1))
				if len(cfg.Networks) == 0 {
					b.Fatal("no networks in config")
				}
			}
		})
	}
}
