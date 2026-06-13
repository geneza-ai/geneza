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

	genezav1 "osie.cloud/geneza/internal/pb/geneza/v1"
	"osie.cloud/geneza/internal/vpn"
)

// wg_userspace.go is the userspace-WireGuard data-plane backend: a wireguard-go
// device per Network bound to a magicsock-lite conn.Bind (internal/vpn). It
// implements the same wgBackend seam as the kernel path, so the reconcile loop
// (network.go) is unchanged — only the bottom layer (kernel wgctrl -> userspace
// device + magicsock) swaps. See docs/magicsock-design.md §7.

type usDevice struct {
	dev  *device.Device
	bind *vpn.MagicBind
	tun  tun.Device
	vni  uint32
}

type userspaceWGBackend struct {
	log *slog.Logger
	mu  sync.Mutex
	ifs map[string]*usDevice
}

func newUserspaceWGBackend(log *slog.Logger) *userspaceWGBackend {
	return &userspaceWGBackend{log: log.With("component", "wg-userspace"), ifs: map[string]*usDevice{}}
}

var _ wgBackend = (*userspaceWGBackend)(nil)

// Create brings up a userspace WG device on a fresh TUN bound to a magicsock.
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
	bind := vpn.NewMagicBind(vni, u.log)
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
	u.log.Info("userspace wg device up", "iface", name, "vni", vni)
	return nil
}

// SetAddr assigns the overlay address out-of-band (same `ip` path as the kernel
// backend; the link is a TUN here, not a kernel WG type).
func (u *userspaceWGBackend) SetAddr(name, cidr string) error { return vpn.WGSetAddr(name, cidr) }

// Configure renders the wireguard-go UAPI from the desired peer set and pushes
// it via IpcSet, then hands the per-peer relay coordinates to the bind (which
// REGisters each mailbox so the relay floor is ready before WG sends).
func (u *userspaceWGBackend) Configure(name string, priv wgtypes.Key, _ int, peers []*genezav1.WGPeer) error {
	u.mu.Lock()
	d := u.ifs[name]
	u.mu.Unlock()
	if d == nil {
		return fmt.Errorf("configure: unknown interface %s", name)
	}
	if err := d.dev.IpcSet(renderUAPI(priv, peers)); err != nil {
		return fmt.Errorf("ipc set %s: %w", name, err)
	}
	d.bind.SyncPeers(peerRelays(peers))
	return nil
}

// ListenPort reports the bind's bound UDP port (the magicsock socket).
func (u *userspaceWGBackend) ListenPort(name string) (int, error) {
	u.mu.Lock()
	d := u.ifs[name]
	u.mu.Unlock()
	if d == nil {
		return 0, fmt.Errorf("listenport: unknown interface %s", name)
	}
	return int(d.bind.ListenPort()), nil
}

// Delete tears the device down (closes the bind + TUN).
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
//
// SEV-1 fix (docs/magicsock-design.md): `endpoint=gz:<hex(pubkey)>` is
// synthesized for EVERY peer regardless of WGPeer.endpoint. wireguard-go refuses
// to send a handshake ("no known endpoint for peer") when the endpoint is nil,
// so the relay floor would never come up without this. The bind resolves the
// gz: token to the live path internally.
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

// peerRelays extracts the bind's relay coordinates from the desired peers.
func peerRelays(peers []*genezav1.WGPeer) []vpn.PeerRelay {
	var out []vpn.PeerRelay
	for _, p := range peers {
		if len(p.GetWgPubkey()) != 32 || p.GetRelay() == nil {
			continue
		}
		r := p.GetRelay()
		var pr vpn.PeerRelay
		copy(pr.WGPub[:], p.GetWgPubkey())
		pr.RelayAddr = r.GetRelayAddr()
		pr.SelfRid = r.GetSelfRid()
		pr.PeerRid = r.GetPeerRid()
		pr.FlowSecret = r.GetFlowSecret()
		out = append(out, pr)
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
