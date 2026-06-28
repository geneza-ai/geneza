package agentd

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	genezav1 "geneza.io/internal/pb/geneza/v1"
	"geneza.io/internal/vpn"
)

// wg_userspace.go is the userspace-WireGuard data-plane backend: a wireguard-go
// device per Network bound to a pion-ICE conn.Bind (internal/vpn.ICEBind). It
// implements the same wgBackend seam as the kernel path, so the reconcile loop
// (network.go) is unchanged — only the bottom layer (kernel wgctrl -> userspace
// device + pion ICE/TURN/STUN) swaps. See docs/dataplane-libs-plan.md.

type usDevice struct {
	dev  *device.Device
	bind *vpn.ICEBind
	tun  tun.Device
	vni  uint32
}

type userspaceWGBackend struct {
	log       *slog.Logger
	relayOnly bool // force the TURN floor (P-libs1 proof); false = full ICE (auto direct upgrade)
	mu        sync.Mutex
	ifs       map[string]*usDevice
	sink      vpn.SignalSink // ICE signaling up-channel (set by the worker)
}

func newUserspaceWGBackend(log *slog.Logger, relayOnly bool) *userspaceWGBackend {
	return &userspaceWGBackend{log: log.With("component", "wg-userspace"), relayOnly: relayOnly, ifs: map[string]*usDevice{}}
}

var (
	_ wgBackend    = (*userspaceWGBackend)(nil)
	_ discoBackend = (*userspaceWGBackend)(nil)
)

// discoBackend is the ICE-signaling control surface the worker drives: it pushes
// our candidates/creds up (via the sink) and routes the controller-relayed peer
// candidates/creds down to the right VNI's bind.
type discoBackend interface {
	SetSignalSink(sink vpn.SignalSink)
	DeliverCandidates(vni uint32, peerWGPub []byte, candidates []string)
	DeliverICECreds(vni uint32, peerWGPub []byte, ufrag, pwd string)
	DeliverPunchAt(vni uint32, peerWGPub []byte, t0UnixMs int64, attempt int)
}

func (u *userspaceWGBackend) SetSignalSink(sink vpn.SignalSink) {
	u.mu.Lock()
	u.sink = sink
	for _, d := range u.ifs {
		d.bind.SetSink(sink)
	}
	u.mu.Unlock()
}

func (u *userspaceWGBackend) bindForVNI(vni uint32) *vpn.ICEBind {
	u.mu.Lock()
	defer u.mu.Unlock()
	if d := u.ifs[wgIfaceName(vni)]; d != nil {
		return d.bind
	}
	return nil
}

func (u *userspaceWGBackend) DeliverCandidates(vni uint32, peerWGPub []byte, candidates []string) {
	if len(peerWGPub) != 32 {
		return
	}
	if b := u.bindForVNI(vni); b != nil {
		var k [32]byte
		copy(k[:], peerWGPub)
		for _, c := range candidates {
			b.AddRemoteCandidate(k, c)
		}
	}
}

func (u *userspaceWGBackend) DeliverICECreds(vni uint32, peerWGPub []byte, ufrag, pwd string) {
	if len(peerWGPub) != 32 {
		return
	}
	if b := u.bindForVNI(vni); b != nil {
		var k [32]byte
		copy(k[:], peerWGPub)
		b.OnICECreds(k, ufrag, pwd)
	}
}

func (u *userspaceWGBackend) DeliverPunchAt(vni uint32, peerWGPub []byte, t0UnixMs int64, attempt int) {
	if len(peerWGPub) != 32 {
		return
	}
	if b := u.bindForVNI(vni); b != nil {
		var k [32]byte
		copy(k[:], peerWGPub)
		b.OnPunchAt(k, t0UnixMs, attempt)
	}
}

// Create brings up a userspace WG device on a fresh TUN bound to a pion-ICE bind.
func (u *userspaceWGBackend) Create(name string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, ok := u.ifs[name]; ok {
		return nil
	}
	vni, err := vniFromIfName(name)
	if err != nil {
		return err
	}
	t, err := tun.CreateTUN(name, device.DefaultMTU)
	if err != nil {
		return fmt.Errorf("create tun %s: %w", name, err)
	}
	bind := vpn.NewICEBind(vni, u.relayOnly, u.log)
	if u.sink != nil {
		bind.SetSink(u.sink)
	}
	dlog := &device.Logger{
		Verbosef: func(f string, a ...any) { u.log.Debug("wg-go: " + fmt.Sprintf(f, a...)) },
		Errorf:   func(f string, a ...any) { u.log.Warn("wg-go: " + fmt.Sprintf(f, a...)) },
	}
	dev := device.NewDevice(t, bind, dlog)
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("device up %s: %w", name, err)
	}
	u.ifs[name] = &usDevice{dev: dev, bind: bind, tun: t, vni: vni}
	u.log.Info("userspace wg device up", "iface", name, "vni", vni, "relay_only", u.relayOnly)
	return nil
}

// SetAddr assigns the overlay address out-of-band (same `ip` path as the kernel
// backend; the link is a TUN here, not a kernel WG type).
func (u *userspaceWGBackend) SetAddr(name, cidr string) error { return vpn.WGSetAddr(name, cidr) }

// Configure renders the wireguard-go UAPI from the desired peer set and pushes it
// via IpcSet, then hands the per-peer ICE/TURN setups to the bind (which spins an
// ICE agent per peer using the controller-minted TURN creds).
func (u *userspaceWGBackend) Configure(name string, priv wgtypes.Key, _ int, peers []*genezav1.WGPeer) error {
	u.mu.Lock()
	d := u.ifs[name]
	u.mu.Unlock()
	if d == nil {
		return fmt.Errorf("configure: unknown interface %s", name)
	}
	d.bind.SetSelfPub([32]byte(priv.PublicKey()))
	if err := d.dev.IpcSet(renderUAPI(priv, peers)); err != nil {
		return fmt.Errorf("ipc set %s: %w", name, err)
	}
	d.bind.SyncPeers(peerSetups(peers))
	return nil
}

// ListenPort: the ICE bind owns no fixed WG listen port (each ice.Agent manages
// its own sockets), so report 0 — the controller's observed-IP+port direct hint is
// unused on the ICE path (pion gathers host/srflx candidates itself).
func (u *userspaceWGBackend) ListenPort(string) (int, error) { return 0, nil }

// Delete tears the device down (closes the bind + ICE agents + TUN).
func (u *userspaceWGBackend) Delete(name string) error {
	u.mu.Lock()
	d := u.ifs[name]
	delete(u.ifs, name)
	u.mu.Unlock()
	if d == nil {
		return nil
	}
	d.dev.Close()
	return nil
}

// renderUAPI builds the wireguard-go UAPI config from the desired peer set.
// endpoint=gz:<hex(pubkey)> is synthesized for EVERY peer regardless of
// WGPeer.endpoint: wireguard-go refuses to send a handshake with a nil endpoint,
// and the ICE bind resolves the gz: token to the live (relay-or-direct) path.
func renderUAPI(priv wgtypes.Key, peers []*genezav1.WGPeer) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(priv[:]))
	b.WriteString("replace_peers=true\n")
	for _, p := range peers {
		if len(p.GetWgPubkey()) != 32 {
			continue
		}
		ph := hex.EncodeToString(p.GetWgPubkey())
		fmt.Fprintf(&b, "public_key=%s\n", ph)
		fmt.Fprintf(&b, "endpoint=gz:%s\n", ph)
		b.WriteString("persistent_keepalive_interval=25\n")
		b.WriteString("replace_allowed_ips=true\n")
		for _, a := range p.GetAllowedIps() {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a)
		}
	}
	return b.String()
}

// peerSetups extracts the bind's per-peer ICE/TURN setup from the desired peers.
func peerSetups(peers []*genezav1.WGPeer) []vpn.PeerSetup {
	var out []vpn.PeerSetup
	for _, p := range peers {
		if len(p.GetWgPubkey()) != 32 || p.GetTurn() == nil {
			continue
		}
		t := p.GetTurn()
		var ps vpn.PeerSetup
		copy(ps.WGPub[:], p.GetWgPubkey())
		ps.Controlling = t.GetControlling()
		ps.TurnURL = t.GetTurnUrl()
		ps.TurnUser = t.GetUsername()
		ps.TurnPass = t.GetPassword()
		ps.TurnRealm = t.GetRealm()
		out = append(out, ps)
	}
	return out
}

func vniFromIfName(name string) (uint32, error) {
	s := strings.TrimPrefix(name, "gnzw")
	if s == name {
		return 0, fmt.Errorf("not a gnzw interface: %s", name)
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("bad vni in %s: %w", name, err)
	}
	return uint32(v), nil
}
