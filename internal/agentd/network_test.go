package agentd

import (
	"io"
	"log/slog"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
)

// fakeWG records interface lifecycle calls so reconcile logic is testable
// without root or the wireguard kernel module.
type fakeWG struct {
	mu      sync.Mutex
	live    map[string]bool   // interfaces currently created
	addr    map[string]string // last address set per interface
	peers   map[string]int    // last peer count configured per interface
	creates int
	deletes int
}

func newFakeWG() *fakeWG {
	return &fakeWG{live: map[string]bool{}, addr: map[string]string{}, peers: map[string]int{}}
}

func (f *fakeWG) Create(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.live[name] {
		f.creates++
	}
	f.live[name] = true
	return nil
}
func (f *fakeWG) SetAddr(name, cidr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addr[name] = cidr
	return nil
}
func (f *fakeWG) Configure(name string, _ wgtypes.Key, _ int, peers []*genezav1.WGPeer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peers[name] = len(peers)
	return nil
}
func (f *fakeWG) ListenPort(name string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.live[name] {
		return 0, nil
	}
	return 51820, nil // deterministic stub port
}
func (f *fakeWG) Delete(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.live[name] {
		f.deletes++
	}
	delete(f.live, name)
	delete(f.addr, name)
	delete(f.peers, name)
	return nil
}

func (f *fakeWG) isLive(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.live[name]
}

func testNetMgr() (*networkManager, *fakeWG) {
	fake := newFakeWG()
	m := &networkManager{
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		wg:      fake,
		running: map[uint32]*wgIface{},
	}
	return m, fake
}

func peer(pub byte, allowed string) *genezav1.WGPeer {
	key := make([]byte, 32)
	key[0] = pub
	return &genezav1.WGPeer{WgPubkey: key, AllowedIps: []string{allowed}}
}

func TestNetworkReconcileBringsUpAndTearsDown(t *testing.T) {
	m, fake := testNetMgr()

	// Version 1: two Networks desired.
	m.reconcile(&genezav1.NetworkConfig{Version: 1, Networks: []*genezav1.NetworkSpec{
		{Vni: 1, OverlayCidr: "100.64.0.2/24", Peers: []*genezav1.WGPeer{peer(1, "100.64.0.3/32")}},
		{Vni: 7, OverlayCidr: "10.10.0.2/24"},
	}})
	if !fake.isLive("gnzw1") || !fake.isLive("gnzw7") {
		t.Fatalf("both interfaces should be up: %+v", fake.live)
	}
	if fake.addr["gnzw1"] != "100.64.0.2/24" {
		t.Fatalf("gnzw1 addr = %q", fake.addr["gnzw1"])
	}
	if fake.peers["gnzw1"] != 1 {
		t.Fatalf("gnzw1 peers = %d, want 1", fake.peers["gnzw1"])
	}

	// Version 2: VNI 7 removed (tag lost) -> torn down; VNI 1 kept.
	m.reconcile(&genezav1.NetworkConfig{Version: 2, Networks: []*genezav1.NetworkSpec{
		{Vni: 1, OverlayCidr: "100.64.0.2/24", Peers: []*genezav1.WGPeer{peer(1, "100.64.0.3/32")}},
	}})
	if fake.isLive("gnzw7") {
		t.Fatal("gnzw7 should be torn down after tag removal")
	}
	if !fake.isLive("gnzw1") {
		t.Fatal("gnzw1 should remain up")
	}
}

func TestNetworkReconcileIgnoresStaleVersion(t *testing.T) {
	m, fake := testNetMgr()
	m.reconcile(&genezav1.NetworkConfig{Version: 5, Networks: []*genezav1.NetworkSpec{
		{Vni: 1, OverlayCidr: "100.64.0.2/24"},
	}})
	// A lower-version push (e.g. a stale sweep racing an explicit push) must not
	// regress state: it should be ignored entirely.
	m.reconcile(&genezav1.NetworkConfig{Version: 4, Networks: nil})
	if !fake.isLive("gnzw1") {
		t.Fatal("stale (lower-version) config tore down a live interface")
	}
}

func TestNetworkDownAll(t *testing.T) {
	m, fake := testNetMgr()
	m.reconcile(&genezav1.NetworkConfig{Version: 1, Networks: []*genezav1.NetworkSpec{
		{Vni: 1, OverlayCidr: "100.64.0.2/24"},
		{Vni: 2, OverlayCidr: "100.65.0.2/24"},
	}})
	m.downAll()
	if fake.isLive("gnzw1") || fake.isLive("gnzw2") {
		t.Fatalf("downAll left interfaces up: %+v", fake.live)
	}
}

func TestNetworkReportsListenPorts(t *testing.T) {
	m, _ := testNetMgr()
	var got []wgEndpoint
	m.report = func(eps []wgEndpoint) { got = eps }
	m.reconcile(&genezav1.NetworkConfig{Version: 1, Networks: []*genezav1.NetworkSpec{
		{Vni: 1, OverlayCidr: "100.64.0.2/24"},
	}})
	if len(got) != 1 || got[0].vni != 1 || got[0].port != 51820 {
		t.Fatalf("report = %+v, want vni=1 port=51820", got)
	}
}

func TestToPeerConfigsSkipsMalformed(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	specs := []*genezav1.WGPeer{
		peer(1, "100.64.0.3/32"),                                         // good
		{WgPubkey: []byte{1, 2, 3}, AllowedIps: nil},                     // bad key length -> skipped
		{WgPubkey: make([]byte, 32), AllowedIps: []string{"not-a-cidr"}}, // bad CIDR dropped, peer kept
	}
	got := toPeerConfigs(specs, log)
	if len(got) != 2 {
		t.Fatalf("want 2 peers (1 skipped for bad key), got %d", len(got))
	}
	if len(got[0].AllowedIPs) != 1 {
		t.Fatalf("good peer allowedIPs = %d, want 1", len(got[0].AllowedIPs))
	}
	if len(got[1].AllowedIPs) != 0 {
		t.Fatalf("bad-CIDR peer should have 0 allowedIPs, got %d", len(got[1].AllowedIPs))
	}
}
