package gateway

import (
	"testing"
)

// newDataPlaneServer spins up a server with the default workspace and returns it.
func newDataPlaneServer(t *testing.T) *Server {
	t.Helper()
	cfg := testServerConfig(t)
	if err := InitDataDir(cfg); err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}

func putWGNode(t *testing.T, srv *Server, ws, id, name string, labels map[string]string, approved bool, wgByte byte) *NodeRecord {
	t.Helper()
	wg := make([]byte, 32)
	wg[0] = wgByte
	rec := &NodeRecord{ID: id, Name: name, Labels: labels, Approved: approved, WGPub: wg}
	if err := srv.store.PutNode(ws, rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

// TestDesiredNetworksMembership: a node sees the default (open) Network always,
// and a tag-gated Network only when its labels match the Selector.
func TestDesiredNetworksMembership(t *testing.T) {
	srv := newDataPlaneServer(t)
	ws := defaultWorkspace

	// A tag-gated "prod" Network (Selector role=db).
	if err := srv.store.PutNetwork(&NetworkRecord{
		WorkspaceID: ws, ID: "prod", VNI: 100, Name: "prod", Selector: map[string]string{"role": "db"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.PutSubnet(&SubnetRecord{
		WorkspaceID: ws, NetworkID: "prod", ID: "prod-sub0", CIDR: "10.20.0.0/24",
	}); err != nil {
		t.Fatal(err)
	}

	dbNode := putWGNode(t, srv, ws, "n-db", "db1", map[string]string{"role": "db"}, true, 1)
	webNode := putWGNode(t, srv, ws, "n-web", "web1", map[string]string{"role": "web"}, true, 2)

	dbNets := vniSet(srv.desiredNetworks(ws, dbNode))
	if !dbNets[vniForWorkspace(ws)] || !dbNets[100] {
		t.Fatalf("db node should be in {default, prod}, got %v", dbNets)
	}
	webNets := vniSet(srv.desiredNetworks(ws, webNode))
	if !webNets[vniForWorkspace(ws)] || webNets[100] {
		t.Fatalf("web node should be in {default} only, got %v", webNets)
	}
}

// TestNetworkPeersFilters: peers exclude self, the unapproved, the keyless, and
// non-members of the Network.
func TestNetworkPeersFilters(t *testing.T) {
	srv := newDataPlaneServer(t)
	ws := defaultWorkspace
	prod := &NetworkRecord{WorkspaceID: ws, ID: "prod", VNI: 100, Selector: map[string]string{"role": "db"}}
	if err := srv.store.PutNetwork(prod); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.PutSubnet(&SubnetRecord{WorkspaceID: ws, NetworkID: "prod", ID: "s", CIDR: "10.20.0.0/24"}); err != nil {
		t.Fatal(err)
	}

	self := putWGNode(t, srv, ws, "n-self", "self", map[string]string{"role": "db"}, true, 1)
	putWGNode(t, srv, ws, "n-peer", "peer", map[string]string{"role": "db"}, true, 2)        // valid peer
	putWGNode(t, srv, ws, "n-pending", "pending", map[string]string{"role": "db"}, false, 3) // unapproved -> excluded
	putWGNode(t, srv, ws, "n-web", "web", map[string]string{"role": "web"}, true, 4)         // not a member -> excluded
	// keyless db node -> excluded
	if err := srv.store.PutNode(ws, &NodeRecord{ID: "n-nokey", Name: "nokey", Labels: map[string]string{"role": "db"}, Approved: true}); err != nil {
		t.Fatal(err)
	}

	peers := srv.networkPeers(ws, prod, self)
	if len(peers) != 1 {
		t.Fatalf("want exactly 1 valid peer, got %d", len(peers))
	}
	if peers[0].GetWgPubkey()[0] != 2 {
		t.Fatalf("wrong peer surfaced: key[0]=%d", peers[0].GetWgPubkey()[0])
	}
}

// TestBindingStability: a non-default Network's per-node overlay IP is stable
// across calls (persisted as a BindingRecord), and overlapping CIDRs on two
// VNIs allocate independently.
func TestBindingStability(t *testing.T) {
	srv := newDataPlaneServer(t)
	ws := defaultWorkspace
	netA := &NetworkRecord{WorkspaceID: ws, ID: "a", VNI: 100}
	netB := &NetworkRecord{WorkspaceID: ws, ID: "b", VNI: 200}
	for _, n := range []*NetworkRecord{netA, netB} {
		if err := srv.store.PutNetwork(n); err != nil {
			t.Fatal(err)
		}
		// Same CIDR for both -> overlapping, must stay independent.
		if err := srv.store.PutSubnet(&SubnetRecord{WorkspaceID: ws, NetworkID: n.ID, ID: n.ID + "-s", CIDR: "10.99.0.0/24"}); err != nil {
			t.Fatal(err)
		}
	}
	node := putWGNode(t, srv, ws, "n-x", "x", nil, true, 1)

	ipA1, err := srv.networkOverlayIP(ws, netA, node)
	if err != nil {
		t.Fatal(err)
	}
	ipA2, err := srv.networkOverlayIP(ws, netA, node)
	if err != nil {
		t.Fatal(err)
	}
	if ipA1 != ipA2 {
		t.Fatalf("binding not stable: %s != %s", ipA1, ipA2)
	}
	// A persisted binding exists.
	if b, err := srv.store.GetBinding(ws, 100, node.ID); err != nil || b.OverlayIP != ipA1 {
		t.Fatalf("binding not persisted: %+v %v", b, err)
	}
	// Independent allocator per VNI: the first host in B's identical CIDR is free
	// again, so node x gets the same first address on VNI 200 as on VNI 100.
	ipB, err := srv.networkOverlayIP(ws, netB, node)
	if err != nil {
		t.Fatal(err)
	}
	if ipB != ipA1 {
		t.Fatalf("overlapping CIDRs not independent: A=%s B=%s (expected equal first-host)", ipA1, ipB)
	}
}

func vniSet(nets []*NetworkRecord) map[uint32]bool {
	out := map[uint32]bool{}
	for _, n := range nets {
		out[n.VNI] = true
	}
	return out
}
