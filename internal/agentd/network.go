package agentd

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
	"osie.cloud/geneza/internal/vpn"
)

// networkManager reconciles the agent's kernel-WireGuard interfaces against the
// gateway's desired NetworkConfig: one wg interface per Network (VNI), with the
// principal's overlay address and the per-Network peer set. It mirrors
// moduleManager (reconcile + monotonic version + idempotent up/down) but drives
// the data plane instead of metrics modules — nothing is pushed upward; WG data
// rides its own UDP socket end-to-end, never the control stream.
//
// Isolation is structural: a Network absent from the desired set (because the
// node's tags no longer match its Selector) is torn down; a peer dropped from a
// Network's set vanishes from the device (ReplacePeers), so kernel WG has no key
// for it and drops its packets.
type networkManager struct {
	log    *slog.Logger
	wgPriv wgtypes.Key
	wg     wgBackend // the kernel-WG backend (real on Linux; a fake in tests)

	mu      sync.Mutex
	running map[uint32]*wgIface
	version int64
}

// wgBackend abstracts the kernel-WireGuard operations so reconcile logic is
// unit-testable without root or the wireguard module.
type wgBackend interface {
	Create(name string) error
	SetAddr(name, cidr string) error
	Configure(name string, priv wgtypes.Key, listenPort int, peers []wgtypes.PeerConfig) error
	Delete(name string) error
}

// realWGBackend drives the actual kernel interface via internal/vpn.
type realWGBackend struct{}

func (realWGBackend) Create(name string) error        { return vpn.WGCreate(name) }
func (realWGBackend) SetAddr(name, cidr string) error { return vpn.WGSetAddr(name, cidr) }
func (realWGBackend) Configure(name string, priv wgtypes.Key, port int, peers []wgtypes.PeerConfig) error {
	return vpn.WGConfigure(name, priv, port, peers)
}
func (realWGBackend) Delete(name string) error { return vpn.WGDelete(name) }

// wgIface tracks one live Network interface so reconcile can detect changes.
type wgIface struct {
	name string
	vni  uint32
	addr string // overlay CIDR currently assigned (e.g. 100.64.0.2/24)
}

func newNetworkManager(log *slog.Logger, wgPriv wgtypes.Key) *networkManager {
	return &networkManager{
		log:     log.With("component", "networks"),
		wgPriv:  wgPriv,
		wg:      realWGBackend{},
		running: map[uint32]*wgIface{},
	}
}

// wgIfaceName is the per-VNI interface name. A 24-bit VNI yields at most
// "gnzw16777215" (12 chars), within the 15-char kernel limit.
func wgIfaceName(vni uint32) string { return fmt.Sprintf("gnzw%d", vni) }

// reconcile diffs the desired NetworkConfig against the running interfaces and
// brings up / syncs / tears down to match. Monotonic: a stale (lower-version)
// config is ignored so a reconnect re-push cannot regress state.
func (m *networkManager) reconcile(cfg *genezav1.NetworkConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cfg.GetVersion() < m.version {
		return
	}
	m.version = cfg.GetVersion()

	desired := map[uint32]*genezav1.NetworkSpec{}
	for _, n := range cfg.GetNetworks() {
		desired[n.GetVni()] = n
	}
	// Tear down Networks no longer desired (tag removed → instant access loss).
	for vni := range m.running {
		if _, ok := desired[vni]; !ok {
			m.downLocked(vni)
		}
	}
	// Bring up / sync the desired set.
	for vni, spec := range desired {
		m.upOrSyncLocked(vni, spec)
	}
}

func (m *networkManager) upOrSyncLocked(vni uint32, spec *genezav1.NetworkSpec) {
	name := wgIfaceName(vni)
	iface := m.running[vni]
	if iface == nil {
		if err := m.wg.Create(name); err != nil {
			m.log.Error("wg interface create failed", "vni", vni, "iface", name, "err", err)
			return
		}
		iface = &wgIface{name: name, vni: vni}
		m.running[vni] = iface
		m.log.Info("network interface up", "vni", vni, "iface", name, "overlay", spec.GetOverlayCidr())
	}
	// Address (idempotent; replaced if the overlay IP changed).
	if spec.GetOverlayCidr() != iface.addr {
		if err := m.wg.SetAddr(name, spec.GetOverlayCidr()); err != nil {
			m.log.Error("wg set address failed", "vni", vni, "iface", name, "err", err)
		} else {
			iface.addr = spec.GetOverlayCidr()
		}
	}
	// Key + peers (ReplacePeers: the pushed set is authoritative).
	peers := toPeerConfigs(spec.GetPeers(), m.log)
	if err := m.wg.Configure(name, m.wgPriv, 0, peers); err != nil {
		m.log.Error("wg configure failed", "vni", vni, "iface", name, "err", err)
		return
	}
	m.log.Debug("network reconciled", "vni", vni, "iface", name, "peers", len(peers))
}

func (m *networkManager) downLocked(vni uint32) {
	iface, ok := m.running[vni]
	if !ok {
		return
	}
	if err := m.wg.Delete(iface.name); err != nil {
		m.log.Warn("wg interface delete failed", "vni", vni, "iface", iface.name, "err", err)
	}
	delete(m.running, vni)
	m.log.Info("network interface down", "vni", vni, "iface", iface.name)
}

// downAll tears down every interface (worker shutdown).
func (m *networkManager) downAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for vni := range m.running {
		m.downLocked(vni)
	}
}

// toPeerConfigs converts wire WGPeers to wgctrl peer configs. Each peer's
// allowedIPs are cryptokey-routing scopes; an endpoint (filled by the gateway's
// endpoint-distribution phase) plus PersistentKeepalive keep the dial-out NAT
// mapping open. A malformed peer is skipped, not fatal.
func toPeerConfigs(specs []*genezav1.WGPeer, log *slog.Logger) []wgtypes.PeerConfig {
	keepalive := 25 * time.Second
	var out []wgtypes.PeerConfig
	for _, p := range specs {
		if len(p.GetWgPubkey()) != 32 {
			continue
		}
		var key wgtypes.Key
		copy(key[:], p.GetWgPubkey())
		pc := wgtypes.PeerConfig{PublicKey: key, ReplaceAllowedIPs: true}
		for _, a := range p.GetAllowedIps() {
			_, ipnet, err := net.ParseCIDR(a)
			if err != nil {
				log.Warn("skip bad allowed-ip", "cidr", a, "err", err)
				continue
			}
			pc.AllowedIPs = append(pc.AllowedIPs, *ipnet)
		}
		if ep := p.GetEndpoint(); ep != "" {
			if addr, err := net.ResolveUDPAddr("udp", ep); err == nil {
				pc.Endpoint = addr
				pc.PersistentKeepaliveInterval = &keepalive
			} else {
				log.Warn("skip bad peer endpoint", "endpoint", ep, "err", err)
			}
		}
		out = append(out, pc)
	}
	return out
}
